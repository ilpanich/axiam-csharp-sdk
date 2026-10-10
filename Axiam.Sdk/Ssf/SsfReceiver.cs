using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Axiam.Sdk.Ssf;

/// <summary>
/// The Shared Signals Framework receiver helper — CONTRACT.md &#167;32.7: verifies a Security
/// Event Token (<see cref="VerifySetAsync"/>) and polls a stream's RFC 8936 endpoint
/// (<see cref="PollAsync"/>).
/// </summary>
/// <remarks>
/// <para>
/// A relying party's tool, not the &#167;27 <c>ssf</c> management namespace (which registers
/// streams). Built over an <see cref="AxiamClient"/> for its transport: the JWKS, the SSF
/// configuration document and the poll endpoint are fetched under the client's &#167;6 TLS
/// policy, on a session-free transport — no cookie, no session bearer, no redirect.
/// </para>
/// <para>
/// <b>Keys come only from the configured JWKS</b> (directly, or from a discovery document whose
/// <c>issuer</c> matches): a <c>jwk</c> or <c>x5c</c> header member is never honoured. On an
/// unknown <c>kid</c> the JWKS is fetched again once, and forced refetches happen at most once a
/// minute. A JWKS that cannot be fetched is a <see cref="NetworkError"/> — not a verdict on the SET.
/// </para>
/// <para>
/// <b>The key cache expires</b> <see cref="Options.AxiamClientOptions.JwksCacheTtl"/> after the fetch that
/// filled it, and never later than 10 minutes (CONTRACT.md &#167;34.2 P6; a longer setting is
/// clamped for this receiver and reported as a <see cref="ConfigClampedEvent"/>). A <b>failed</b>
/// fetch — a cold fill, the refresh of an expired cache, or an unknown-<c>kid</c> refetch — counts
/// toward the once-a-minute limit: a SET inside the minute after one makes no fetch and is a
/// <see cref="NetworkError"/> (no verdict). A successful fill or refresh does not count, so an
/// unknown <c>kid</c> right after one is refetched.
/// </para>
/// </remarks>
public sealed class SsfReceiver
{
    private static readonly TimeSpan ForcedRefetchInterval = TimeSpan.FromSeconds(60);

    /// <summary>The longest an SSF key cache may live (CONTRACT.md &#167;34.2 P6).</summary>
    internal static readonly TimeSpan MaxKeyCacheLifetime = TimeSpan.FromMinutes(10);

    private readonly AxiamClient _client;
    private readonly SsfReceiverOptions _options;
    private readonly IReplayStore _replay;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _jwksLock = new(1, 1);
    private Dictionary<string, byte[]>? _keys;
    private DateTimeOffset _fetchedAt;
    private readonly TimeSpan _keyCacheLifetime;

    // Every fetch that counts toward the once-a-minute limit (§34.2 P6): an unknown-kid refetch,
    // whatever its outcome, and any failed fetch. `_lastFailedFetch` alone gates a cold fill or the
    // refresh of an expired cache, which a successful fetch does not hold back.
    private DateTimeOffset? _lastCountedFetch;
    private DateTimeOffset? _lastFailedFetch;
    private string? _jwksUri;

    /// <summary>Builds a receiver over <paramref name="client"/>'s transport.</summary>
    /// <param name="client">The client whose TLS policy and base URL (the transmitter root) are used.</param>
    /// <param name="options">The receiver configuration.</param>
    /// <exception cref="ValidationError">
    /// The replay window is below seven days, or the issuer or audience is empty — refused at
    /// configuration, before any I/O.
    /// </exception>
    public SsfReceiver(AxiamClient client, SsfReceiverOptions options)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        if (options.ReplayWindow < SsfReceiverOptions.MinReplayWindow)
        {
            throw Refuse("ReplayWindow", "must be at least seven days, the transmitter's buffer retention (CONTRACT.md §32.7)");
        }

        if (string.IsNullOrEmpty(options.Issuer) || string.IsNullOrEmpty(options.Audience))
        {
            throw Refuse("Issuer", "issuer and audience are required (CONTRACT.md §32.7)");
        }

        ArgumentNullException.ThrowIfNull(options.Keys);
        _time = options.TimeProvider ?? TimeProvider.System;
        _replay = options.ReplayStore ?? new MemoryReplayStore(_time);
        _keyCacheLifetime = client.Options.JwksCacheTtl;
        if (_keyCacheLifetime > MaxKeyCacheLifetime)
        {
            _keyCacheLifetime = MaxKeyCacheLifetime;
            client.Telemetry.Emit(new ConfigClampedEvent(
                "JwksCacheTtl (SsfReceiver key cache)",
                client.Options.JwksCacheTtl.ToString(),
                MaxKeyCacheLifetime.ToString(),
                "§34.2 P6"));
        }
    }

    private static ValidationError Refuse(string field, string why) =>
        new($"SsfReceiver: {field} {why}", new[] { new FieldError(field, why) });

    /// <summary>
    /// Verifies one compact SET (CONTRACT.md &#167;32.7), refusing at the first failure with a
    /// <see cref="SetVerificationError"/> naming the step.
    /// </summary>
    /// <remarks>
    /// <para>The order: 1 three base64url parts, JSON-object header and payload
    /// [<c>malformed</c>]; 2 <c>typ</c> <c>secevent+jwt</c> or <c>application/secevent+jwt</c>,
    /// any case [<c>invalid_type</c>]; 3 <c>alg</c> exactly <c>EdDSA</c> [<c>invalid_key</c>];
    /// 4 the <c>kid</c> in the configured JWKS, one refetch on a miss, at most once a minute
    /// [<c>invalid_key</c>]; 5 the Ed25519 signature [<c>invalid_key</c>]; 6 <c>iss</c> exactly the
    /// configured issuer [<c>invalid_issuer</c>]; 7 <c>aud</c> equal to, or an array containing,
    /// the audience [<c>invalid_audience</c>]; 8 no <c>exp</c>, no <c>sub</c>, a non-empty
    /// <c>jti</c>, a numeric <c>iat</c>, an object <c>sub_id</c>, exactly one <c>events</c> member
    /// [<c>invalid_request</c>]; 9 a <c>jti</c> not seen within the replay window
    /// [<c>replayed</c>], recorded only once 1–8 passed.</para>
    /// <para><b>A SET that verifies has been recorded</b>: verifying it again is
    /// <c>replayed</c>. Acknowledge a polled SET once you have processed it.</para>
    /// </remarks>
    /// <param name="set">The compact SET.</param>
    /// <param name="cancellationToken">Cancels a JWKS fetch.</param>
    /// <returns>The verified event.</returns>
    /// <exception cref="SetVerificationError">The SET was refused.</exception>
    /// <exception cref="NetworkError">
    /// The JWKS (or discovery document) could not be fetched, or the <see cref="IReplayStore"/> could
    /// not answer (&#167;34.2 P3, P4): no verdict, no reason code, and the <c>jti</c> is not recorded.
    /// </exception>
    public Task<SecurityEvent> VerifySetAsync(string set, CancellationToken cancellationToken = default)
        => VerifyAsync(set, expectedJti: null, batch: null, cancellationToken);

    /// <summary>What one <see cref="PollAsync"/> batch has learned so far (&#167;34.2 P1).</summary>
    private sealed class Batch
    {
        /// <summary>
        /// <c>false</c> once a failure that is no verdict happened with a SET already recorded:
        /// from then on the store is asked nothing, and a SET that passes steps 1 – 8 is unjudged.
        /// </summary>
        public bool AskStore { get; set; } = true;

        /// <summary>What first left a SET unjudged: <c>replay_store</c> or <c>key_fetch</c>.</summary>
        public SsfUnjudgedCause? Cause { get; set; }
    }

    private async Task<SecurityEvent> VerifyAsync(
        string set, string? expectedJti, Batch? batch, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(set);

        // 1.
        string[] parts = set.Split('.');
        if (parts.Length != 3 || !TryB64(parts[2], out byte[] signature) ||
            !TryObject(parts[0], out JsonElement header) || !TryObject(parts[1], out JsonElement claims))
        {
            throw new SetVerificationError(SetFailureReason.Malformed, "not three base64url parts with a JSON-object header and payload");
        }

        // 2.
        string typ = Str(header, "typ") ?? string.Empty;
        if (!string.Equals(typ, "secevent+jwt", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(typ, "application/secevent+jwt", StringComparison.OrdinalIgnoreCase))
        {
            throw new SetVerificationError(SetFailureReason.InvalidType, "typ is not secevent+jwt");
        }

        // 3.
        if (Str(header, "alg") != "EdDSA")
        {
            throw new SetVerificationError(SetFailureReason.InvalidKey, "alg is not EdDSA");
        }

        // 4.
        string? kid = Str(header, "kid");
        if (kid is null)
        {
            throw new SetVerificationError(SetFailureReason.InvalidKey, "no kid");
        }

        byte[] key = await KeyForKidAsync(kid, cancellationToken).ConfigureAwait(false)
            ?? throw new SetVerificationError(SetFailureReason.InvalidKey, "no key for kid in the JWKS");

        // 5.
        if (key.Length != Ed25519PublicKeyParameters.KeySize || !VerifyEd25519(key, parts, signature))
        {
            throw new SetVerificationError(SetFailureReason.InvalidKey, "signature does not verify");
        }

        // 6.
        string iss = Str(claims, "iss") ?? string.Empty;
        if (!string.Equals(iss, _options.Issuer, StringComparison.Ordinal))
        {
            throw new SetVerificationError(SetFailureReason.InvalidIssuer, "iss is not the configured issuer");
        }

        // 7.
        JsonElement aud = claims.TryGetProperty("aud", out JsonElement audEl) ? audEl.Clone() : default;
        bool audOk = aud.ValueKind switch
        {
            JsonValueKind.String => aud.GetString() == _options.Audience,
            JsonValueKind.Array => aud.EnumerateArray().Any(a => a.ValueKind == JsonValueKind.String && a.GetString() == _options.Audience),
            _ => false,
        };
        if (!audOk)
        {
            throw new SetVerificationError(SetFailureReason.InvalidAudience, "aud does not name this receiver");
        }

        // 8.
        if (claims.TryGetProperty("exp", out _) || claims.TryGetProperty("sub", out _))
        {
            throw new SetVerificationError(SetFailureReason.InvalidRequest, "a SET carries no exp and no sub");
        }

        string jti = Str(claims, "jti") is { Length: > 0 } j
            ? j
            : throw new SetVerificationError(SetFailureReason.InvalidRequest, "no jti");
        if (!claims.TryGetProperty("iat", out JsonElement iatEl) || iatEl.ValueKind != JsonValueKind.Number ||
            !iatEl.TryGetInt64(out long iat))
        {
            throw new SetVerificationError(SetFailureReason.InvalidRequest, "no numeric iat");
        }

        if (!claims.TryGetProperty("sub_id", out JsonElement subId) || subId.ValueKind != JsonValueKind.Object)
        {
            throw new SetVerificationError(SetFailureReason.InvalidRequest, "no sub_id object");
        }

        if (!claims.TryGetProperty("events", out JsonElement events) || events.ValueKind != JsonValueKind.Object ||
            events.EnumerateObject().Count() != 1)
        {
            throw new SetVerificationError(SetFailureReason.InvalidRequest, "events must have exactly one member");
        }

        if (expectedJti is not null && !string.Equals(expectedJti, jti, StringComparison.Ordinal))
        {
            throw new SetVerificationError(SetFailureReason.InvalidRequest, "the poll key is not the SET's jti");
        }

        JsonProperty only = events.EnumerateObject().First();
        var verified = new SecurityEvent(
            jti, iat, iss, aud, Str(claims, "txn"), only.Name, only.Value.Clone(), subId.Clone());

        // §34.2 P1 (contract 1.60): after a store failure in a poll batch the store is asked
        // nothing more; the caller reads a SET returned from here as unjudged, not recorded.
        if (batch is { AskStore: false })
        {
            return verified;
        }

        // 9. A store has three answers (§34.2 P4). `false` is "already seen"; a store that cannot
        // answer throws, and that is no verdict: NetworkError with no reason code (P3), never
        // `replayed` -- P2 would acknowledge a `replayed` SET, losing an event nobody processed.
        // An SDK error of the §2 types passes through (C-1); this SDK's own refusal type is
        // wrapped too, so no store failure surfaces carrying a reason code.
        bool firstSighting;
        try
        {
            firstSighting = _replay.CheckAndRecord(jti, _options.ReplayWindow);
        }
        catch (Exception ex) when (ex is OperationCanceledException or NetworkError ||
                                   (ex is AuthError or AuthzError && ex is not SetVerificationError))
        {
            NoteStoreFailure(batch);
            throw;
        }
        catch (Exception ex)
        {
            NoteStoreFailure(batch);
            throw NetworkError.FromException(ex, "ssf: the replay store could not answer");
        }

        if (!firstSighting)
        {
            throw new SetVerificationError(SetFailureReason.Replayed, "jti already seen");
        }

        return verified;
    }

    private static void NoteStoreFailure(Batch? batch)
    {
        if (batch is not null)
        {
            batch.Cause ??= SsfUnjudgedCause.ReplayStore;
            batch.AskStore = false;
        }
    }

    /// <summary>
    /// Polls the stream's RFC 8936 endpoint, <c>{base URL}/ssf/v1/poll/{stream_id}</c>, with a
    /// bearer from <see cref="SsfReceiverOptions.AccessTokenProvider"/>, and verifies every SET.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>Ack</c> and <c>SetErrs</c> are sent exactly as given, and only the members you set.
    /// <b>Nothing is acknowledged on your behalf</b>: acknowledge, on the next call, the
    /// <c>jti</c>s you processed, and pass each refused one in <c>SetErrs</c>
    /// (<see cref="SetErr.FromReason"/>) — except a <c>replayed</c> one, which this receiver
    /// accepted earlier: acknowledge that (CONTRACT.md &#167;34.2 P2). A SET you neither acknowledge
    /// nor refuse is re-offered — and, having been recorded when it verified, then reads as
    /// <c>replayed</c>.
    /// </para>
    /// <para>
    /// Retried per &#167;16 on a transport failure, <c>5xx</c>, <c>408</c> or <c>429</c>; never on
    /// another <c>4xx</c> (<c>400</c> is a <see cref="ValidationError"/>, <c>404</c> a
    /// <see cref="NotFoundError"/>, as on the management surface).
    /// </para>
    /// <para>
    /// <b>A poll never keeps a <c>jti</c> it does not return</b> (&#167;34.2 P1). A failure that is
    /// no verdict on a SET — a JWKS or discovery fetch that fails, a replay store that throws —
    /// leaves that SET <b>unjudged</b>, and from then on the batch asks the replay store nothing:
    /// every later SET that passes steps 1 – 8 is unjudged too, and one that fails them is refused
    /// as usual. An unjudged SET is in neither <see cref="SsfPollResult.Events"/> nor
    /// <see cref="SsfPollResult.Refused"/>, is not recorded, and is listed in
    /// <see cref="SsfPollResult.Unjudged"/>. Do not acknowledge them; the transmitter offers them
    /// again. A poll that returns with SETs unjudged emits an <see cref="SsfUnjudgedEvent"/>
    /// (&#167;19.1), so an outage that raised nothing is still visible. When the failure comes
    /// before any SET of the batch was recorded, the poll raises it instead (nothing is recorded
    /// either way).
    /// </para>
    /// </remarks>
    /// <param name="streamId">The stream id (path-escaped).</param>
    /// <param name="options">What to send; <c>null</c> sends <c>{}</c>.</param>
    /// <param name="cancellationToken">Cancels the poll.</param>
    /// <returns>The verified and the refused SETs, apart.</returns>
    /// <exception cref="AuthError">No access-token provider is configured — no request is sent.</exception>
    public async Task<SsfPollResult> PollAsync(
        string streamId, SsfPollOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(streamId);
        if (_options.AccessTokenProvider is not { } provider)
        {
            throw new AuthError(
                "SsfReceiver.PollAsync needs an AccessTokenProvider (a client-credentials token with ssf.manage); no request was sent");
        }

        options ??= new SsfPollOptions();
        var body = new JsonObject();
        if (options.MaxEvents is { } max)
        {
            body["maxEvents"] = max;
        }

        if (options.ReturnImmediately is { } immediately)
        {
            body["returnImmediately"] = immediately;
        }

        if (options.Ack is { } ack)
        {
            body["ack"] = new JsonArray(ack.Select(a => (JsonNode?)a).ToArray());
        }

        if (options.SetErrs is { } errs)
        {
            var map = new JsonObject();
            foreach ((string jti, SetErr err) in errs)
            {
                var entry = new JsonObject { ["err"] = err.Err };
                if (err.Description is not null)
                {
                    entry["description"] = err.Description;
                }

                map[jti] = entry;
            }

            body["setErrs"] = map;
        }

        string payload = body.ToJsonString();
        string root = _client.BaseUrl.GetLeftPart(UriPartial.Authority) + _client.BaseUrl.AbsolutePath.TrimEnd('/');
        var url = new Uri($"{root}/ssf/v1/poll/{Uri.EscapeDataString(streamId)}");
        Sensitive<string> token = await provider(cancellationToken).ConfigureAwait(false);

        JsonElement reply = await RetryPolicy.ExecuteAsync(
            "ssf.poll",
            _client.Options,
            _client.Telemetry,
            Random.Shared.NextDouble,
            async _ =>
            {
                var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent(payload, Encoding.UTF8, "application/json"),
                };
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Reveal());
                // §34.2 P11: poll is the one SSF write §16 retries, so it may share the pool.
                Rest.ConnectionPolicy.MarkRetryEligible(request);
                HttpResponseMessage response;
                try
                {
                    response = await _client.SessionlessHttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
                }
                catch (HttpRequestException ex)
                {
                    throw NetworkError.FromException(ex, "ssf.poll: request failed");
                }
                catch (OperationCanceledException ex) when (ex.CancellationToken != cancellationToken)
                {
                    throw NetworkError.FromException(ex, "ssf.poll: request timed out");
                }

                using (response)
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        throw await ManagementTransport.ClassifyAsync("ssf.poll", response, cancellationToken).ConfigureAwait(false);
                    }

                    string text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                    try
                    {
                        using JsonDocument document = JsonDocument.Parse(text);
                        return document.RootElement.Clone();
                    }
                    catch (JsonException)
                    {
                        throw NetworkError.FromMessage("ssf.poll: could not parse the transmitter's response");
                    }
                }
            },
            cancellationToken,
            retryable: RetryPolicy.IsTransient).ConfigureAwait(false);

        bool more = reply.ValueKind == JsonValueKind.Object &&
                    reply.TryGetProperty("moreAvailable", out JsonElement moreEl) &&
                    moreEl.ValueKind == JsonValueKind.True;
        var verified = new List<SecurityEvent>();
        var refused = new List<RefusedSet>();
        var unjudged = new List<string>();
        var batch = new Batch();
        if (reply.ValueKind == JsonValueKind.Object && reply.TryGetProperty("sets", out JsonElement sets) &&
            sets.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty entry in sets.EnumerateObject())
            {
                if (entry.Value.ValueKind != JsonValueKind.String)
                {
                    refused.Add(new RefusedSet(entry.Name, SetFailureReason.Malformed));
                    continue;
                }

                bool recording = batch.AskStore;
                try
                {
                    SecurityEvent judged = await VerifyAsync(entry.Value.GetString()!, entry.Name, batch, cancellationToken)
                        .ConfigureAwait(false);
                    if (recording)
                    {
                        verified.Add(judged);
                    }
                    else
                    {
                        unjudged.Add(entry.Name);
                    }
                }
                catch (SetVerificationError e)
                {
                    refused.Add(new RefusedSet(entry.Name, e.FailureReason));
                }
                catch (Exception ex) when (ex is not OperationCanceledException && verified.Count > 0)
                {
                    // CONTRACT.md §34.2 P1/P3: a failure that is no verdict (a key fetch, the
                    // store) leaves this SET unjudged — not returned, not recorded — and the
                    // batch asks the store nothing more. The SETs already recorded MUST be
                    // returned, so the poll returns rather than raising; with none recorded
                    // yet, the failure propagates.
                    batch.Cause ??= SsfUnjudgedCause.KeyFetch;
                    batch.AskStore = false;
                    unjudged.Add(entry.Name);
                }
            }
        }

        if (unjudged.Count > 0)
        {
            _client.Telemetry.Emit(new SsfUnjudgedEvent("ssf.poll", unjudged.Count, batch.Cause ?? SsfUnjudgedCause.KeyFetch));
        }

        return new SsfPollResult(verified, more, refused) { Unjudged = unjudged };
    }

    private async Task<byte[]?> KeyForKidAsync(string kid, CancellationToken cancellationToken)
    {
        await _jwksLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            DateTimeOffset now = _time.GetUtcNow();
            if (_keys is null || now - _fetchedAt > _keyCacheLifetime)
            {
                // A cold fill or the refresh of an expired cache. Within the minute after a failed
                // fetch it makes no fetch: no verdict (§34.2 P6), so an outage is not a fetch per SET.
                if (_lastFailedFetch is { } failed && now - failed < ForcedRefetchInterval)
                {
                    throw NetworkError.FromMessage(
                        "SSF JWKS fetch failed less than a minute ago; not fetching again yet");
                }

                _keys = null;
                await FetchCountingFailureAsync(now, cancellationToken).ConfigureAwait(false);
            }

            if (_keys!.TryGetValue(kid, out byte[]? key))
            {
                return key;
            }

            // One forced refetch for an unknown kid, and forced refetches at most once a minute:
            // a stream of SETs naming made-up kids must not become a stream of JWKS fetches.
            if (_lastCountedFetch is { } last && now - last < ForcedRefetchInterval)
            {
                return null;
            }

            _lastCountedFetch = now;
            await FetchCountingFailureAsync(now, cancellationToken).ConfigureAwait(false);
            return _keys!.TryGetValue(kid, out key) ? key : null;
        }
        finally
        {
            _jwksLock.Release();
        }
    }

    private async Task FetchCountingFailureAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        try
        {
            await FetchKeysAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _lastFailedFetch = now;
            _lastCountedFetch = now;
            throw;
        }
    }

    private async Task FetchKeysAsync(CancellationToken cancellationToken)
    {
        _jwksUri ??= _options.Keys.JwksUri is { } direct
            ? RequireSecure("jwks_uri", direct)
            : await DiscoverJwksUriAsync(cancellationToken).ConfigureAwait(false);
        JsonElement document = await GetJsonAsync(_jwksUri, "SSF JWKS", cancellationToken).ConfigureAwait(false);
        var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (document.ValueKind == JsonValueKind.Object && document.TryGetProperty("keys", out JsonElement list) &&
            list.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement jwk in list.EnumerateArray())
            {
                if (jwk.ValueKind == JsonValueKind.Object && Str(jwk, "kty") == "OKP" && Str(jwk, "crv") == "Ed25519" &&
                    Str(jwk, "kid") is { } kid && Str(jwk, "x") is { } x && TryB64(x, out byte[] raw))
                {
                    keys[kid] = raw;
                }
            }
        }

        _keys = keys;
        _fetchedAt = _time.GetUtcNow();
    }

    private async Task<string> DiscoverJwksUriAsync(CancellationToken cancellationToken)
    {
        string url = RequireSecure("discovery_url", _options.Keys.DiscoveryUrl!);
        JsonElement document = await GetJsonAsync(url, "SSF configuration", cancellationToken).ConfigureAwait(false);
        if (document.ValueKind != JsonValueKind.Object || Str(document, "issuer") != _options.Issuer)
        {
            throw NetworkError.FromMessage("the SSF configuration's issuer is not the configured issuer");
        }

        return Str(document, "jwks_uri") is { } jwks
            ? RequireSecure("jwks_uri", jwks)
            : throw NetworkError.FromMessage("the SSF configuration carries no jwks_uri");
    }

    private async Task<JsonElement> GetJsonAsync(string url, string what, CancellationToken cancellationToken)
    {
        HttpResponseMessage response;
        try
        {
            response = await _client.SessionlessHttpClient.GetAsync(new Uri(url), cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw NetworkError.FromException(ex, $"{what} fetch failed");
        }
        catch (OperationCanceledException ex) when (ex.CancellationToken != cancellationToken)
        {
            throw NetworkError.FromException(ex, $"{what} fetch timed out");
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw NetworkError.FromResponse(response, $"{what} fetch failed");
            }

            string text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using JsonDocument document = JsonDocument.Parse(text);
                return document.RootElement.Clone();
            }
            catch (JsonException)
            {
                throw NetworkError.FromMessage($"{what} is not JSON");
            }
        }
    }

    private static string RequireSecure(string label, string raw)
    {
        if (!Uri.TryCreate(raw, UriKind.Absolute, out Uri? uri) ||
            !(uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && AxiamClient.IsLoopbackHost(uri))))
        {
            throw NetworkError.FromMessage($"SsfReceiver: {label} must be an absolute https URL");
        }

        return raw;
    }

    private static bool VerifyEd25519(byte[] key, string[] parts, byte[] signature)
    {
        byte[] input = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        var verifier = new Ed25519Signer();
        verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(key));
        verifier.BlockUpdate(input, 0, input.Length);
        return verifier.VerifySignature(signature);
    }

    private static string? Str(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool TryObject(string part, out JsonElement element)
    {
        element = default;
        if (!TryB64(part, out byte[] bytes))
        {
            return false;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(bytes);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            element = document.RootElement.Clone();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    internal static bool TryB64(string text, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (text.Length == 0 || text.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_')))
        {
            return false;
        }

        string padded = text.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => string.Empty };
        try
        {
            bytes = Convert.FromBase64String(padded);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
