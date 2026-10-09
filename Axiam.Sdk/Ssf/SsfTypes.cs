using System.Collections.Concurrent;
using System.Text.Json;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Ssf;

/// <summary>
/// Why <see cref="SsfReceiver.VerifySetAsync"/> refused a Security Event Token — the reason
/// codes of CONTRACT.md &#167;32.7, in the order its nine steps check them.
/// </summary>
public enum SetFailureReason
{
    /// <summary>Step 1: not three base64url parts, or the header or payload is not a JSON object (<c>malformed</c>).</summary>
    Malformed,

    /// <summary>Step 2: <c>typ</c> is not <c>secevent+jwt</c> / <c>application/secevent+jwt</c> (<c>invalid_type</c>).</summary>
    InvalidType,

    /// <summary>Steps 3–5: <c>alg</c> not <c>EdDSA</c>, no key for <c>kid</c>, or a bad signature (<c>invalid_key</c>).</summary>
    InvalidKey,

    /// <summary>Step 6: <c>iss</c> is not the configured issuer (<c>invalid_issuer</c>).</summary>
    InvalidIssuer,

    /// <summary>Step 7: <c>aud</c> does not name this receiver (<c>invalid_audience</c>).</summary>
    InvalidAudience,

    /// <summary>Step 8: a SET claim rule broken — <c>exp</c>/<c>sub</c> present, <c>jti</c>/<c>iat</c>/<c>sub_id</c> missing, not exactly one event (<c>invalid_request</c>).</summary>
    InvalidRequest,

    /// <summary>Step 9: the <c>jti</c> was already accepted within the replay window (<c>replayed</c>).</summary>
    Replayed,
}

/// <summary>The wire spellings of <see cref="SetFailureReason"/>.</summary>
public static class SetFailureReasons
{
    /// <summary>The &#167;32.7 reason code: <c>malformed</c>, <c>invalid_type</c>, … <c>replayed</c>.</summary>
    /// <param name="reason">The reason.</param>
    /// <returns>Its code.</returns>
    public static string Code(this SetFailureReason reason) => reason switch
    {
        SetFailureReason.Malformed => "malformed",
        SetFailureReason.InvalidType => "invalid_type",
        SetFailureReason.InvalidKey => "invalid_key",
        SetFailureReason.InvalidIssuer => "invalid_issuer",
        SetFailureReason.InvalidAudience => "invalid_audience",
        SetFailureReason.InvalidRequest => "invalid_request",
        _ => "replayed",
    };

    /// <summary>
    /// The RFC 8935 &#167;2.4 <c>err</c> a push endpoint answers with (<c>400 {"err": …}</c>):
    /// the reason itself for <c>invalid_key</c>, <c>invalid_issuer</c>,
    /// <c>invalid_audience</c> and <c>invalid_request</c>; <c>invalid_request</c> for
    /// <c>malformed</c>, <c>invalid_type</c> and <c>replayed</c>, which are not RFC 8935 codes.
    /// </summary>
    /// <param name="reason">The reason.</param>
    /// <returns>An RFC 8935 code.</returns>
    public static string PushErrorCode(this SetFailureReason reason) => reason switch
    {
        SetFailureReason.InvalidKey => "invalid_key",
        SetFailureReason.InvalidIssuer => "invalid_issuer",
        SetFailureReason.InvalidAudience => "invalid_audience",
        _ => "invalid_request",
    };
}

/// <summary>
/// A SET refusal: an <see cref="AuthError"/> (CONTRACT.md &#167;32.7) carrying the typed
/// <see cref="FailureReason"/>; <see cref="AuthError.Reason"/> holds its code.
/// </summary>
public sealed class SetVerificationError : AuthError
{
    /// <summary>Constructs the refusal.</summary>
    /// <param name="reason">Which step refused.</param>
    /// <param name="detail">What failed, naming no claim value.</param>
    public SetVerificationError(SetFailureReason reason, string detail)
        : base($"SET refused ({reason.Code()}): {detail}", reason.Code())
    {
        FailureReason = reason;
    }

    /// <summary>Which of the nine steps refused the SET.</summary>
    public SetFailureReason FailureReason { get; }
}

/// <summary>The six AXIAM event types and the two SSF ones (CONTRACT.md &#167;32.6).</summary>
public static class SsfEventTypes
{
    /// <summary>CAEP session revoked.</summary>
    public const string SessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

    /// <summary>CAEP credential change.</summary>
    public const string CredentialChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change";

    /// <summary>CAEP assurance level change.</summary>
    public const string AssuranceLevelChange = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";

    /// <summary>RISC account disabled.</summary>
    public const string AccountDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";

    /// <summary>RISC account enabled.</summary>
    public const string AccountEnabled = "https://schemas.openid.net/secevent/risc/event-type/account-enabled";

    /// <summary>RISC account purged.</summary>
    public const string AccountPurged = "https://schemas.openid.net/secevent/risc/event-type/account-purged";

    /// <summary>SSF verification.</summary>
    public const string Verification = "https://schemas.openid.net/secevent/ssf/event-type/verification";

    /// <summary>SSF stream updated.</summary>
    public const string StreamUpdated = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";
}

/// <summary>
/// Remembers the <c>jti</c>s already accepted, for &#167;32.7 step 9. Pluggable so a receiver
/// running several instances can share one store.
/// </summary>
public interface IReplayStore
{
    /// <summary>
    /// Records <paramref name="jti"/> for <paramref name="window"/> and returns <c>true</c>, or
    /// returns <c>false</c> without recording when it is already held. MUST be atomic: two
    /// concurrent calls with one <c>jti</c> must not both see <c>true</c>.
    /// </summary>
    /// <param name="jti">The SET's id.</param>
    /// <param name="window">How long to remember it.</param>
    /// <returns>Whether this is the first sighting.</returns>
    bool CheckAndRecord(string jti, TimeSpan window);
}

/// <summary>The in-memory <see cref="IReplayStore"/>: one process, lost on restart, entries expire.</summary>
public sealed class MemoryReplayStore : IReplayStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;
    private readonly object _lock = new();

    /// <summary>A store on the system clock.</summary>
    public MemoryReplayStore()
        : this(TimeProvider.System)
    {
    }

    /// <summary>A store on <paramref name="time"/>.</summary>
    /// <param name="time">The clock expiry is measured against.</param>
    public MemoryReplayStore(TimeProvider time)
    {
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    /// <inheritdoc />
    public bool CheckAndRecord(string jti, TimeSpan window)
    {
        ArgumentNullException.ThrowIfNull(jti);
        DateTimeOffset now = _time.GetUtcNow();
        lock (_lock)
        {
            foreach (KeyValuePair<string, DateTimeOffset> entry in _seen)
            {
                if (entry.Value <= now)
                {
                    _seen.TryRemove(entry.Key, out _);
                }
            }

            return _seen.TryAdd(jti, now + window);
        }
    }
}

/// <summary>Where the transmitter's signing keys come from (CONTRACT.md &#167;32.7).</summary>
public sealed record SsfKeySource
{
    private SsfKeySource(string? jwksUri, string? discoveryUrl)
    {
        JwksUri = jwksUri;
        DiscoveryUrl = discoveryUrl;
    }

    /// <summary>The JWKS URL itself, when given directly.</summary>
    public string? JwksUri { get; }

    /// <summary>The SSF configuration document URL, when the keys are discovered.</summary>
    public string? DiscoveryUrl { get; }

    /// <summary>Keys from <paramref name="uri"/> (AXIAM: <c>{issuer}/oauth2/jwks</c>).</summary>
    /// <param name="uri">The JWKS URL.</param>
    /// <returns>The key source.</returns>
    public static SsfKeySource FromJwksUri(string uri) => new(uri ?? throw new ArgumentNullException(nameof(uri)), null);

    /// <summary>
    /// Keys from the <c>jwks_uri</c> of the SSF configuration document at <paramref name="url"/>
    /// (<c>/.well-known/ssf-configuration…</c>), whose <c>issuer</c> must equal the configured issuer.
    /// </summary>
    /// <param name="url">The discovery URL.</param>
    /// <returns>The key source.</returns>
    public static SsfKeySource FromDiscoveryUrl(string url) => new(null, url ?? throw new ArgumentNullException(nameof(url)));
}

/// <summary>Configuration for an <see cref="SsfReceiver"/> (&#167;32.7: issuer, audience, keys, token provider).</summary>
public sealed class SsfReceiverOptions
{
    /// <summary>The replay window's default and floor: seven days, the transmitter's buffer retention.</summary>
    public static readonly TimeSpan MinReplayWindow = TimeSpan.FromDays(7);

    /// <summary>The transmitter's issuer — compared to <c>iss</c> exactly.</summary>
    public required string Issuer { get; init; }

    /// <summary>This receiver's audience — the stream's <c>audience</c>.</summary>
    public required string Audience { get; init; }

    /// <summary>Where the signing keys come from.</summary>
    public required SsfKeySource Keys { get; init; }

    /// <summary>
    /// The bearer <see cref="SsfReceiver.PollAsync"/> presents — a client-credentials token
    /// carrying <c>ssf.manage</c> (e.g. from <c>LoginClientCredentialsAsync</c>), called once per
    /// poll. <c>null</c> for a push-only receiver.
    /// </summary>
    public Func<CancellationToken, Task<Sensitive<string>>>? AccessTokenProvider { get; init; }

    /// <summary>How long a <c>jti</c> is remembered. At least <see cref="MinReplayWindow"/>.</summary>
    public TimeSpan ReplayWindow { get; init; } = MinReplayWindow;

    /// <summary>Where accepted <c>jti</c>s are kept; <c>null</c> uses a <see cref="MemoryReplayStore"/>.</summary>
    public IReplayStore? ReplayStore { get; init; }

    /// <summary>The clock the JWKS refetch limit is measured against; <c>null</c> is the system clock.</summary>
    public TimeProvider? TimeProvider { get; init; }
}

/// <summary>A verified Security Event Token (&#167;32.7's result).</summary>
/// <param name="Jti">The SET's unique id.</param>
/// <param name="Iat">When it was issued, seconds since the epoch.</param>
/// <param name="Iss">The issuer, equal to the configured one.</param>
/// <param name="Aud">The audience as sent: one string, or an array containing yours.</param>
/// <param name="Txn">The transaction id shared by every SET one operation produced, if any.</param>
/// <param name="EventType">The single <c>events</c> key — an event-type URI, see <see cref="SsfEventTypes"/>.</param>
/// <param name="Event">That event's object, opaque to the helper.</param>
/// <param name="SubId">The RFC 9493 subject identifier, opaque to the helper.</param>
public sealed record SecurityEvent(
    string Jti, long Iat, string Iss, JsonElement Aud, string? Txn, string EventType, JsonElement Event, JsonElement SubId);

/// <summary>One SET a poll returned and the helper refused.</summary>
/// <param name="Jti">The key the transmitter returned the SET under.</param>
/// <param name="Reason">Why. Pass <see cref="SetErr.FromReason"/> of it in the next poll's <c>SetErrs</c>.</param>
public sealed record RefusedSet(string Jti, SetFailureReason Reason);

/// <summary>An RFC 8936 <c>setErrs</c> entry.</summary>
/// <param name="Err">The RFC 8935 &#167;2.4 code.</param>
/// <param name="Description">Optional text; AXIAM never stores it.</param>
public sealed record SetErr(string Err, string? Description = null)
{
    /// <summary>The entry for a refusal: its <see cref="SetFailureReasons.PushErrorCode"/>.</summary>
    /// <param name="reason">The refusal reason.</param>
    /// <returns>The entry.</returns>
    public static SetErr FromReason(SetFailureReason reason) => new(reason.PushErrorCode());
}

/// <summary>Arguments to <see cref="SsfReceiver.PollAsync"/>; each member passed through as given, an unset one not sent.</summary>
public sealed class SsfPollOptions
{
    /// <summary><c>maxEvents</c> — the server clamps it to 100; <c>0</c> acknowledges and returns nothing.</summary>
    public int? MaxEvents { get; init; }

    /// <summary><c>returnImmediately</c> — without it the server long-polls up to 30 s.</summary>
    public bool? ReturnImmediately { get; init; }

    /// <summary><c>ack</c> — the <c>jti</c>s you <b>processed</b> since the last poll.</summary>
    public IReadOnlyList<string>? Ack { get; init; }

    /// <summary><c>setErrs</c> — the <c>jti</c>s you refuse, each with its code.</summary>
    public IReadOnlyDictionary<string, SetErr>? SetErrs { get; init; }
}

/// <summary>What <see cref="SsfReceiver.PollAsync"/> returns.</summary>
/// <param name="Events">The SETs that verified, in the transmitter's order.</param>
/// <param name="MoreAvailable">Whether the transmitter holds more.</param>
/// <param name="Refused">The SETs that did not verify.</param>
public sealed record SsfPollResult(IReadOnlyList<SecurityEvent> Events, bool MoreAvailable, IReadOnlyList<RefusedSet> Refused);
