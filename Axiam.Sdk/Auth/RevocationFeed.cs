using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Axiam.Sdk.Auth;

/// <summary>
/// The optional session-revocation feed poller (CONTRACT.md &#167;10.4, contract 1.44 —
/// AXIAM threats T-39 and T-143).
/// </summary>
/// <remarks>
/// <para><strong>What this narrows, and what it is not.</strong> An AXIAM access token is
/// self-contained and valid for up to fifteen minutes, and this SDK verifies it locally. A
/// logout, a role removal or an account disable therefore does not reach a token already in
/// a caller's hands until it expires — &#167;10.2 records that, and the documented answer
/// has been "route the decision through gRPC introspection instead", which is correct and
/// costs a round trip PER REQUEST.</para>
/// <para>A deployment may publish <c>GET /oauth2/revocations</c>: the base64url-unpadded
/// SHA-256 of every session id revoked within the last access-token lifetime. A guard that
/// polls it rejects a revoked session within ONE POLL INTERVAL instead of one token
/// lifetime, for one cacheable fetch per interval.</para>
/// <para>It is NOT a control, and every rule below follows from that:</para>
/// <list type="bullet">
///   <item><strong>Default off.</strong> Nothing polls unless a caller attaches a feed.</item>
///   <item><strong>Never on the request path.</strong> <see cref="IsRevokedAsync"/> answers
///   from the cached set and, at most, refreshes a set the NEXT caller sees.</item>
///   <item><strong>Never fail closed.</strong> An unreachable feed, a non-<c>200</c>, a body
///   that does not parse, an <c>alg</c> this build does not know — every one of them behaves
///   exactly as no feed at all. Not as an empty list: an empty list asserts that nothing has
///   been revoked, which is a guard that silently honours no revocations while appearing to
///   honour them.</item>
///   <item><strong>It only ever rejects.</strong> Every &#167;10.1 rule runs first and still
///   decides. The feed can turn an accept into a reject and never the reverse.</item>
///   <item><strong>A token with no <c>sid</c> is never matched.</strong> There is no session
///   behind a client-credentials token, an RPT or a token exchange, and hashing <c>jti</c>
///   instead would match nothing while looking like it worked.</item>
/// </list>
/// <para>Safe for concurrent use, and meant to be shared: several verifiers built from one
/// feed poll once between them rather than once each.</para>
/// </remarks>
public sealed class RevocationFeed
{
    /// <summary>The published feed's path, resolved against a deployment's base URL.</summary>
    public const string FeedPath = "/oauth2/revocations";

    /// <summary>
    /// The only digest the feed publishes, and the only one this poller accepts.
    /// </summary>
    /// <remarks>
    /// A document naming anything else is treated as unusable — exactly as an unreachable
    /// feed is — rather than as a list of entries that happen not to match. Silently
    /// matching nothing is how a guard ends up reporting that it honours revocations while
    /// honouring none.
    /// </remarks>
    private const string SupportedAlg = "SHA-256";

    /// <summary>
    /// The shortest interval a caller may configure (&#167;10.4 rule 2).
    /// </summary>
    /// <remarks>
    /// Bounded because the feed is one deployment-wide document and a fleet of guards
    /// polling it at a hundred milliseconds is a load source rather than a security
    /// improvement. The floor is applied by clamping, not by refusing: a caller who asked
    /// for something faster gets the fastest thing on offer.
    /// </remarks>
    public static readonly TimeSpan MinPollInterval = TimeSpan.FromSeconds(15);

    /// <summary>The interval &#167;10.4 recommends, and the one a feed uses unless told
    /// otherwise.</summary>
    public static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The largest number of entries kept in the cache (&#167;10.4 rule 2).
    /// </summary>
    /// <remarks>
    /// The server bounds the document by its own revocation rate over one token lifetime,
    /// so this is defence against a server that stops doing so — a cache with no ceiling is
    /// an allocation an unauthenticated endpoint controls. Overflow drops the WHOLE set
    /// rather than truncating it: a truncated set is a guard that admits some revoked
    /// sessions and reports none, which is worse than a guard that admits all of them and
    /// says the feed is unusable.
    /// </remarks>
    public const int MaxEntries = 100_000;

    /// <summary>
    /// Caps what is read off the wire before the entry count can be known, since the count
    /// is only knowable after decoding. 64 bytes of entry plus JSON framing over
    /// <see cref="MaxEntries"/>, rounded up.
    /// </summary>
    private const int MaxBodyBytes = 8 << 20;

    private readonly HttpClient _http;
    private readonly Uri _feedUri;
    private readonly TimeSpan _pollInterval;

    /// <summary>
    /// Serializes refreshers, so a burst of guards that all notice the cache is stale
    /// produces one fetch rather than one each — the same shape as
    /// <see cref="JwksVerifier"/>'s refresh lock, and for the same reason.
    /// </summary>
    private readonly SemaphoreSlim _fetchLock = new(1, 1);

    private readonly object _stateLock = new();

    /// <summary>
    /// <c>null</c> means "never successfully fetched", which is NOT the same as an empty
    /// set, and is why this is compared against <c>null</c> rather than by count.
    /// </summary>
    private HashSet<string>? _entries;

    private DateTimeOffset _lastAttempt = DateTimeOffset.MinValue;

    /// <summary>A testing seam only; <c>null</c> means <see cref="DateTimeOffset.UtcNow"/>.
    /// Internal so it can never be reached from configuration.</summary>
    internal Func<DateTimeOffset>? TimeProvider { get; set; }

    /// <summary>
    /// Polls <c>{baseUrl}/oauth2/revocations</c> through <paramref name="httpClient"/>.
    /// </summary>
    /// <param name="httpClient">Used only to fetch the feed document; ownership stays with
    /// the caller.</param>
    /// <param name="baseUrl">The AXIAM server base URL; the feed path is resolved against
    /// it. A deployment that does not publish the feed is not an error here — that is
    /// discovered on the first poll, and behaves as no feed at all from then on.</param>
    /// <param name="pollInterval">How long a fetched set is served before a refetch is
    /// attempted. Clamped up to <see cref="MinPollInterval"/> rather than refused;
    /// <c>null</c> means <see cref="DefaultPollInterval"/>.</param>
    public RevocationFeed(HttpClient httpClient, Uri baseUrl, TimeSpan? pollInterval = null)
    {
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        ArgumentNullException.ThrowIfNull(baseUrl);
        if (!baseUrl.IsAbsoluteUri)
        {
            throw new ArgumentException($"'{baseUrl}' is not an absolute base URL", nameof(baseUrl));
        }

        _feedUri = new Uri(baseUrl, FeedPath);
        TimeSpan interval = pollInterval ?? DefaultPollInterval;
        _pollInterval = interval < MinPollInterval ? MinPollInterval : interval;
    }

    /// <summary>The feed document's URL, for diagnostics.</summary>
    public Uri FeedUri => _feedUri;

    /// <summary>The interval actually in effect, after the <see cref="MinPollInterval"/>
    /// clamp.</summary>
    public TimeSpan PollInterval => _pollInterval;

    /// <summary>
    /// The feed entry for a <c>sid</c>, as the server computes it.
    /// </summary>
    /// <remarks>
    /// Base64url without padding over the claim's EXACT string — never a
    /// parsed-and-re-rendered UUID, or the answer would depend on this type's UUID parser
    /// rather than on the feed.
    /// </remarks>
    /// <param name="sid">The <c>sid</c> claim's exact string.</param>
    /// <returns>The base64url-unpadded SHA-256 of <paramref name="sid"/>.</returns>
    public static string EntryFor(string sid)
    {
        ArgumentNullException.ThrowIfNull(sid);
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(sid));
        return Convert.ToBase64String(digest)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// Reports whether this session has been revoked, as far as this poller knows.
    /// </summary>
    /// <remarks>
    /// <c>false</c> whenever the answer is not a confident yes — a feed never fetched,
    /// unreachable, malformed, or simply not listing this session. The caller admits the
    /// request in all of those cases, which is &#167;10.4 rule 3 and is the whole reason
    /// the feature is safe to turn on.
    /// </remarks>
    /// <param name="sid">The <c>sid</c> claim, or <c>null</c>/empty for a token that
    /// carries none — which is never matched (&#167;10.4 rule 6).</param>
    /// <param name="cancellationToken">Cancels an in-flight refresh.</param>
    /// <returns><c>true</c> only when this session id is listed in a successfully fetched
    /// document.</returns>
    public async Task<bool> IsRevokedAsync(string? sid, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(sid))
        {
            return false;
        }

        await RefreshIfStaleAsync(cancellationToken).ConfigureAwait(false);

        lock (_stateLock)
        {
            return _entries is not null && _entries.Contains(EntryFor(sid));
        }
    }

    /// <summary>
    /// Fetches now, whatever the interval says. For tests, and for a caller that wants the
    /// first poll to have happened before it starts serving.
    /// </summary>
    /// <param name="cancellationToken">Cancels the fetch.</param>
    /// <returns>A task that completes when the attempt has been recorded.</returns>
    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        await _fetchLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            HashSet<string>? fetched = await FetchAsync(cancellationToken).ConfigureAwait(false);
            lock (_stateLock)
            {
                _lastAttempt = Now();
                if (fetched is not null)
                {
                    _entries = fetched;
                }
                // On failure the previous set is deliberately left in place: a blip must
                // not un-revoke a session the guard already knows about.
            }
        }
        finally
        {
            _fetchLock.Release();
        }
    }

    private DateTimeOffset Now() => TimeProvider?.Invoke() ?? DateTimeOffset.UtcNow;

    /// <summary>
    /// Refetches if the poll interval has elapsed since the last ATTEMPT.
    /// </summary>
    /// <remarks>
    /// Attempt, not success: a feed that is down must not be retried on every request,
    /// which would put the request path back on the network — the cost &#167;10.4 exists
    /// to avoid.
    /// </remarks>
    private async Task RefreshIfStaleAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset last;
        lock (_stateLock)
        {
            last = _lastAttempt;
        }

        if (last != DateTimeOffset.MinValue && Now() - last < _pollInterval)
        {
            return;
        }

        await RefreshAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Performs one fetch. <c>null</c> for every kind of failure, which the caller treats
    /// identically — see the type-level remarks on why "unusable" must not collapse into
    /// "empty".
    /// </summary>
    private async Task<HashSet<string>?> FetchAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, _feedUri);
            using HttpResponseMessage response =
                await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode != HttpStatusCode.OK)
            {
                return null;
            }

            byte[] body = await response.Content.ReadAsByteArrayAsync(cancellationToken)
                .ConfigureAwait(false);
            if (body.Length > MaxBodyBytes)
            {
                return null;
            }

            using JsonDocument document = JsonDocument.Parse(body);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            if (!root.TryGetProperty("alg", out JsonElement alg) ||
                alg.ValueKind != JsonValueKind.String ||
                alg.GetString() != SupportedAlg)
            {
                return null;
            }

            if (!root.TryGetProperty("revoked", out JsonElement revoked) ||
                revoked.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            if (revoked.GetArrayLength() > MaxEntries)
            {
                // The WHOLE set, not a truncation — see MaxEntries.
                return null;
            }

            var entries = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonElement entry in revoked.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.String)
                {
                    return null;
                }

                string? value = entry.GetString();
                if (!string.IsNullOrEmpty(value))
                {
                    entries.Add(value);
                }
            }

            return entries;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Unreachable, non-200, unparseable, wrong alg — every one of them is
            // "no feed at all" (§10.4 rule 3), never an empty list.
            return null;
        }
    }
}
