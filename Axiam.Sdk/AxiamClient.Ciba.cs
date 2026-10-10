using System.Globalization;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;

namespace Axiam.Sdk;

/// <content>
/// CIBA — client-initiated backchannel authentication, the client's half (CONTRACT.md &#167;33,
/// contract 1.58).
/// </content>
/// <remarks>
/// <para>
/// A client that already knows whom it wants to authenticate asks AXIAM, over a
/// client-authenticated call (<see cref="CibaInitiateAsync"/>), to authenticate that user on
/// another device; AXIAM notifies the user, who approves or refuses on the console. The client
/// then collects the tokens by polling (<see cref="CibaAwaitAsync"/>, or one
/// <see cref="CibaPollAsync"/>) — in <b>ping</b> mode after <see cref="CibaHandlePing(IEnumerable{KeyValuePair{string, string}}, string, Sensitive{string})"/>
/// has checked AXIAM's notification.
/// </para>
/// <para>
/// <b>A successful <see cref="CibaInitiateAsync"/> proves nothing about the user</b> (&#167;33.3
/// rule 4): a hint naming nobody is answered exactly like a real one, and the only sign that a
/// user did not answer is <c>expired_token</c>. The SDK never approves or refuses a request, and
/// offers no push mode, <c>login_hint_token</c>, <c>user_code</c> or <c>request_uri</c>.
/// </para>
/// </remarks>
public sealed partial class AxiamClient
{
    /// <summary>The CIBA grant type (CIBA Core &#167;10.1).</summary>
    public const string CibaGrantType = "urn:openid:params:grant-type:ciba";

    /// <summary>The interval used when the initiate response carries none (or zero), seconds (&#167;33.7 rule 2).</summary>
    public const long DefaultCibaIntervalSeconds = 5;

    /// <summary>What each <c>slow_down</c> adds to the interval, permanently (&#167;33.7 rule 3).</summary>
    public const long CibaSlowDownIncrementSeconds = 5;

    /// <summary>The lifetime of a signed request this SDK mints, seconds — inside the server's 60-minute bound.</summary>
    internal const long SignedCibaRequestLifetimeSeconds = 300;

    /// <summary>
    /// <c>POST /oauth2/bc-authorize</c> (CIBA Core &#167;7, CONTRACT.md &#167;33.1) — asks AXIAM to
    /// authenticate a user on another device.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The client authenticates as it does at <c>/oauth2/token</c>: <c>client_secret_post</c>
    /// (<see cref="Options.AxiamClientOptions.OidcClientSecret"/>), or — with a &#167;6.1 client
    /// certificate and no secret — <c>tls_client_auth</c>, sending <c>client_id</c> only. The
    /// endpoint is discovery's <c>backchannel_authentication_endpoint</c>, its
    /// <c>mtls_endpoint_aliases</c> entry on an mTLS call; <c>tenant_id</c> goes in the query.
    /// </para>
    /// <para>
    /// <b>Never retried</b> — not on a transport error, a <c>5xx</c> or a <c>429</c> (&#167;33.7
    /// rule 1): every accepted call stores a request and may notify a person. On a lost answer,
    /// let the request expire and ask again deliberately.
    /// </para>
    /// </remarks>
    /// <param name="params">The request.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The <c>auth_req_id</c>, its lifetime and the polling interval.</returns>
    /// <exception cref="AuthError">The client has no credential (no request), or the server does not support CIBA.</exception>
    /// <exception cref="ValidationError">A ping-mode request without a notification token — no request.</exception>
    /// <exception cref="OAuthProtocolError">The server's refusal, e.g. <c>invalid_binding_message</c> with its description.</exception>
    public async Task<CibaInitiateResponse> CibaInitiateAsync(CibaInitiateParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);
        EnsureNotDisposed();
        (string clientId, string? clientSecret) = CibaClientAuth("CibaInitiateAsync");
        if (@params.Hint is null || string.IsNullOrEmpty(@params.Scope))
        {
            throw new ValidationError(
                "CibaInitiateAsync: scope and exactly one hint are required (CONTRACT.md §33.2); no request was sent",
                new[] { new FieldError(@params.Hint is null ? "login_hint" : "scope", "required") });
        }

        if (@params.Delivery is { IsPing: true } ping && string.IsNullOrEmpty(ping.ClientNotificationToken!.Value.Reveal()))
        {
            throw new ValidationError(
                "CibaInitiateAsync: a ping-mode request needs a client_notification_token — without one AXIAM has nothing to ping with (CONTRACT.md §33.8); no request was sent",
                new[] { new FieldError("client_notification_token", "required in ping mode") });
        }

        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        string? endpoint = PreferredEndpoint(
            configuration, a => a.BackchannelAuthenticationEndpoint, configuration.BackchannelAuthenticationEndpoint);
        if (string.IsNullOrEmpty(endpoint))
        {
            throw new AuthError(
                "the authorization server's discovery document advertises no backchannel_authentication_endpoint: " +
                "this server does not support CIBA (CONTRACT.md §33.1)");
        }

        Guid tenantId = ResolveOidcTenantId(@params.TenantId);
        var form = new Dictionary<string, string>(StringComparer.Ordinal) { ["client_id"] = clientId };
        if (clientSecret is not null)
        {
            form["client_secret"] = clientSecret;
        }

        if (@params.Signer is { } signer)
        {
            form["request"] = SignedCibaRequest(@params, signer, clientId, configuration.Issuer);
        }
        else
        {
            foreach ((string name, string value) in CibaMembers(@params))
            {
                form[name] = value;
            }
        }

        DateTimeOffset receivedAt;
        CibaInitiateWire wire;
        using (HttpResponseMessage response = await PostOAuth2FormAsync(endpoint, form, tenantId, cancellationToken).ConfigureAwait(false))
        {
            receivedAt = DateTimeOffset.UtcNow;
            if (!response.IsSuccessStatusCode)
            {
                throw await MapOAuth2ErrorAnyStatusAsync(response, "ciba initiate request failed", cancellationToken).ConfigureAwait(false);
            }

            wire = await ReadOidcJsonAsync<CibaInitiateWire>(response, cancellationToken).ConfigureAwait(false);
        }

        if (string.IsNullOrEmpty(wire.AuthReqId))
        {
            throw NetworkError.FromMessage("the ciba initiate response carries no auth_req_id");
        }

        return new CibaInitiateResponse(
            Sensitive.Of(wire.AuthReqId),
            wire.ExpiresIn,
            wire.Interval is > 0 ? wire.Interval.Value : DefaultCibaIntervalSeconds,
            receivedAt);
    }

    /// <summary>
    /// <c>POST /oauth2/token</c> with <c>grant_type=urn:openid:params:grant-type:ciba</c> (CIBA
    /// Core &#167;10.1, CONTRACT.md &#167;33.1) — <b>one</b> token request.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The answers of &#167;33.3 rule 6 surface as <see cref="OAuthProtocolError"/> and are not
    /// retried: <c>authorization_pending</c> and <c>slow_down</c> (non-terminal),
    /// <c>access_denied</c> and <c>expired_token</c> (terminal and distinct —
    /// <see cref="OAuthProtocolError.IsAccessDenied"/>, <see cref="OAuthProtocolError.IsExpiredToken"/>),
    /// <c>invalid_grant</c>. A transport failure, <c>5xx</c>, <c>408</c> or bodiless <c>429</c> is
    /// retried per &#167;16 within the call; no other <c>4xx</c> is. A <c>5xx</c> is a
    /// <see cref="NetworkError"/> whatever its body, <c>{"error":"server_error"}</c> included
    /// (&#167;34.2 P8).
    /// </para>
    /// <para>
    /// <b>Store the returned tokens before anything else</b>: a request is redeemed once, and a
    /// second <see cref="CibaPollAsync"/> for it is <c>invalid_grant</c> (&#167;33.7 rule 7). The ID
    /// token is validated as for every other grant (no nonce).
    /// </para>
    /// </remarks>
    /// <param name="params">The <c>auth_req_id</c> and its context.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The token set.</returns>
    /// <exception cref="AuthError">The client has no credential — no request is sent.</exception>
    public async Task<OidcTokenSet> CibaPollAsync(CibaPollParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);
        EnsureNotDisposed();
        (string clientId, string? clientSecret) = CibaClientAuth("CibaPollAsync");
        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        Guid tenantId = ResolveOidcTenantId(@params.TenantId);
        string endpoint = PreferredRequiredEndpoint(configuration, a => a.TokenEndpoint, configuration.TokenEndpoint);
        var form = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = CibaGrantType,
            ["auth_req_id"] = @params.AuthReqId.Reveal(),
            ["client_id"] = clientId,
        };
        if (clientSecret is not null)
        {
            form["client_secret"] = clientSecret;
        }

        string body = await RetryPolicy.ExecuteAsync(
            "ciba_poll",
            _options,
            _telemetry,
            Random.Shared.NextDouble,
            async _ =>
            {
                using HttpResponseMessage response = await PostOAuth2FormAsync(endpoint, form, tenantId, cancellationToken, retryEligible: true).ConfigureAwait(false);
                if ((int)response.StatusCode >= 500)
                {
                    // §33.7 rule 5, §34.2 P8: on ciba_poll a 5xx is transient whatever its body —
                    // AXIAM's own token endpoint answers 500 {"error":"server_error"}.
                    throw NetworkError.FromResponse(response, "ciba poll failed");
                }

                if (!response.IsSuccessStatusCode)
                {
                    // An OAuthProtocolError is an AuthError: never retried. A bodiless status is a
                    // NetworkError, retried only when RetryPolicy.IsTransient says so.
                    throw await MapOAuth2ErrorAnyStatusAsync(response, "ciba poll failed", cancellationToken).ConfigureAwait(false);
                }

                // §33.7 rule 7: consume the 200 here; parsing happens outside the retry, since the
                // server may already have redeemed the request.
                return await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            },
            cancellationToken,
            retryable: RetryPolicy.IsTransient).ConfigureAwait(false);

        TokenResponseWire wire;
        try
        {
            wire = JsonSerializer.Deserialize<TokenResponseWire>(body)
                   ?? throw NetworkError.FromMessage("the ciba poll response deserialized to null");
        }
        catch (JsonException ex)
        {
            throw NetworkError.FromException(ex, "failed to parse the ciba poll response");
        }

        var expectations = new IdTokenExpectations(configuration.Issuer, clientId, HasNonce: false, Nonce: null, _oidcClockSkewSeconds);
        return await ToTokenSetAsync(wire, configuration, expectations, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Polls for <paramref name="initiated"/>'s outcome until it is decided or expires (&#167;33.1,
    /// &#167;33.7). Surfaces nothing to the user — AXIAM notified them.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    ///   <item>The first poll waits one <c>interval</c> (the response's, or 5 s): polling earlier
    ///   only earns <c>slow_down</c> and a longer wait.</item>
    ///   <item><c>slow_down</c> adds 5 s to the interval, cumulatively and for good;
    ///   <c>authorization_pending</c> never lowers it.</item>
    ///   <item>A transport failure, <c>5xx</c> or <c>429</c> (<c>rate_limit_exceeded</c>) that
    ///   outlived &#167;16 is not terminal: it counts as one interval.</item>
    ///   <item>Polling stops at <see cref="CibaInitiateResponse.ReceivedAt"/> +
    ///   <see cref="CibaInitiateResponse.ExpiresIn"/>, even if the server has not said
    ///   <c>expired_token</c>; the same <c>expired_token</c> is then raised locally, with no request.</item>
    ///   <item><c>access_denied</c>, <c>expired_token</c>, <c>invalid_grant</c> and any other answer
    ///   end the loop.</item>
    /// </list>
    /// <para>
    /// Returns the token set without adopting it as this client's credential (the posture of
    /// <see cref="DeviceLoginAsync"/> and <see cref="LoginClientCredentialsAsync"/>). <b>Ping
    /// mode</b>: do not loop — call <see cref="CibaPollAsync"/> once from the ping handler (after
    /// answering the ping), once more after <c>interval</c> if it said <c>authorization_pending</c>
    /// or <c>slow_down</c>, and fall back to this loop only once half of <c>expires_in</c> has
    /// passed without a ping (&#167;33.7 rule 6).
    /// </para>
    /// </remarks>
    /// <param name="initiated">The initiate response.</param>
    /// <param name="params">Tenant, discovery document and clock; <c>null</c> for the defaults.</param>
    /// <param name="cancellationToken">Cancels the loop.</param>
    /// <returns>The token set.</returns>
    public async Task<OidcTokenSet> CibaAwaitAsync(
        CibaInitiateResponse initiated, CibaAwaitParams? @params = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(initiated);
        @params ??= new CibaAwaitParams();
        ICibaClock clock = @params.Clock ?? SystemCibaClock.Instance;
        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        DateTimeOffset deadline = initiated.ReceivedAt + TimeSpan.FromSeconds(initiated.ExpiresIn);
        long interval = initiated.Interval > 0 ? initiated.Interval : DefaultCibaIntervalSeconds;

        while (true)
        {
            TimeSpan wait = TimeSpan.FromSeconds(interval);
            if (clock.UtcNow + wait >= deadline)
            {
                throw new OAuthProtocolError(
                    "expired_token",
                    "the CIBA request expired before it was decided (client-side deadline from expires_in; CONTRACT.md §33.7 rule 4)");
            }

            await clock.SleepAsync(wait, cancellationToken).ConfigureAwait(false);
            try
            {
                return await CibaPollAsync(
                    new CibaPollParams(initiated.AuthReqId, @params.TenantId, configuration), cancellationToken).ConfigureAwait(false);
            }
            catch (OAuthProtocolError e) when (e.Error is "authorization_pending" or "rate_limit_exceeded")
            {
            }
            catch (OAuthProtocolError e) when (e.Error is "slow_down")
            {
                interval += CibaSlowDownIncrementSeconds;
            }
            catch (NetworkError e) when (RetryPolicy.IsTransient(e))
            {
                // §33.7 rule 5: a transport failure or 5xx that survived §16 is not terminal.
            }
        }
    }

    /// <summary>
    /// Checks a ping AXIAM delivered to your notification endpoint and returns the
    /// <c>auth_req_id</c> it names (CIBA Core &#167;10.2, CONTRACT.md &#167;33.1). <b>No I/O</b>, synchronous.
    /// </summary>
    /// <remarks>
    /// <list type="number">
    ///   <item>Exactly one <c>Authorization</c> header (name matched case-insensitively): the scheme
    ///   <c>Bearer</c> in any case, one space, and <paramref name="expectedToken"/> — compared with
    ///   <see cref="CryptographicOperations.FixedTimeEquals"/>. Anything else is an
    ///   <see cref="AuthError"/> whose message names no value.</item>
    ///   <item>A JSON object with a non-empty string <c>auth_req_id</c>; other members are ignored.
    ///   Anything else is a <see cref="ValidationError"/>.</item>
    /// </list>
    /// <para>
    /// It neither answers the HTTP request nor calls the token endpoint: answer <c>204</c> as soon
    /// as this returns, <b>then</b> call <see cref="CibaPollAsync"/> — AXIAM retries a ping that is
    /// not answered quickly. It does not check that the id is one you issued; the token endpoint
    /// answers <c>invalid_grant</c> for any other.
    /// </para>
    /// </remarks>
    /// <param name="headers">The request's headers as name/value pairs — one pair per value (flatten a multi-valued collection).</param>
    /// <param name="body">The raw request body.</param>
    /// <param name="expectedToken">The <c>client_notification_token</c> you sent with the request.</param>
    /// <returns>The <c>auth_req_id</c>, Sensitive.</returns>
    public Sensitive<string> CibaHandlePing(
        IEnumerable<KeyValuePair<string, string>> headers, string body, Sensitive<string> expectedToken)
    {
        ArgumentNullException.ThrowIfNull(headers);
        var authorization = headers
            .Where(h => string.Equals(h.Key, "Authorization", StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value)
            .Take(2)
            .ToList();
        static AuthError Refused() => new(
            "ciba ping refused: the Authorization header is not the expected bearer (CONTRACT.md §33.1)");

        if (authorization.Count != 1 || authorization[0] is not { } value)
        {
            throw Refused();
        }

        int space = value.IndexOf(' ', StringComparison.Ordinal);
        if (space <= 0 || !string.Equals(value[..space], "Bearer", StringComparison.OrdinalIgnoreCase))
        {
            throw Refused();
        }

        byte[] presented = Encoding.UTF8.GetBytes(value[(space + 1)..]);
        byte[] expected = Encoding.UTF8.GetBytes(expectedToken.Reveal() ?? string.Empty);
        if (expected.Length == 0 || presented.Length == 0 || !CryptographicOperations.FixedTimeEquals(presented, expected))
        {
            throw Refused();
        }

        static ValidationError Malformed() => new(
            "ciba ping refused: the body is not a JSON object with a non-empty auth_req_id string (CONTRACT.md §33.1)",
            new[] { new FieldError("auth_req_id", "missing or not a non-empty string") });

        try
        {
            using JsonDocument document = JsonDocument.Parse(body ?? string.Empty);
            if (document.RootElement.ValueKind == JsonValueKind.Object &&
                document.RootElement.TryGetProperty("auth_req_id", out JsonElement id) &&
                id.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(id.GetString()))
            {
                return Sensitive.Of(id.GetString()!);
            }
        }
        catch (JsonException)
        {
        }

        throw Malformed();
    }

    /// <summary><see cref="CibaHandlePing(IEnumerable{KeyValuePair{string, string}}, string, Sensitive{string})"/> over a raw UTF-8 body.</summary>
    /// <param name="headers">The request's headers as name/value pairs.</param>
    /// <param name="body">The raw request body bytes.</param>
    /// <param name="expectedToken">The <c>client_notification_token</c> you sent with the request.</param>
    /// <returns>The <c>auth_req_id</c>, Sensitive.</returns>
    public Sensitive<string> CibaHandlePing(
        IEnumerable<KeyValuePair<string, string>> headers, byte[] body, Sensitive<string> expectedToken)
    {
        string text;
        try
        {
            text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(body ?? Array.Empty<byte>());
        }
        catch (DecoderFallbackException)
        {
            text = string.Empty;
        }

        return CibaHandlePing(headers, text, expectedToken);
    }

    /// <summary>The CIBA client's credential: client_secret_post, or tls_client_auth (client_id only).</summary>
    private (string ClientId, string? ClientSecret) CibaClientAuth(string operation)
    {
        string? secret = _oidcClientSecret?.Reveal();
        if (string.IsNullOrWhiteSpace(_oidcClientId) || (secret is null && !PresentsClientCertificate))
        {
            throw new AuthError(
                $"{operation} requires client authentication: a CIBA client is never public — configure " +
                "AxiamClientOptions.OidcClientId with OidcClientSecret, or a §6.1 client certificate " +
                "(CONTRACT.md §33.1). No request was sent.");
        }

        return (_oidcClientId, secret);
    }

    /// <summary>The authentication-request members, exactly those set, as form strings.</summary>
    private static List<(string Name, string Value)> CibaMembers(CibaInitiateParams p)
    {
        var members = new List<(string, string)> { ("scope", p.Scope), (p.Hint.Member, p.Hint.Value) };
        if (p.BindingMessage is not null)
        {
            members.Add(("binding_message", p.BindingMessage));
        }

        if (p.RequestedExpiry is { } expiry)
        {
            members.Add(("requested_expiry", expiry.ToString(CultureInfo.InvariantCulture)));
        }

        if (p.AcrValues is not null)
        {
            members.Add(("acr_values", p.AcrValues));
        }

        if (p.Resource is not null)
        {
            members.Add(("resource", p.Resource));
        }

        if (p.Delivery.ClientNotificationToken is { } token)
        {
            members.Add(("client_notification_token", token.Reveal()));
        }

        return members;
    }

    /// <summary>
    /// The CIBA Core &#167;7.1.1 signed request: every member inside the JWT (<c>requested_expiry</c>
    /// as a number), plus <c>iss</c> = client id, <c>aud</c> = the issuer, <c>iat</c> = <c>nbf</c> =
    /// now, <c>exp</c> = now + 300 and a fresh 128-bit <c>jti</c>.
    /// </summary>
    private static string SignedCibaRequest(CibaInitiateParams p, CibaRequestSigner signer, string clientId, string issuer)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var claims = new JsonObject
        {
            ["iss"] = clientId,
            ["aud"] = issuer,
            ["iat"] = now,
            ["nbf"] = now,
            ["exp"] = now + SignedCibaRequestLifetimeSeconds,
            ["jti"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
        };
        foreach ((string name, string value) in CibaMembers(p))
        {
            claims[name] = name == "requested_expiry" ? JsonValue.Create(p.RequestedExpiry!.Value) : JsonValue.Create(value);
        }

        var header = new JsonObject { ["alg"] = signer.JoseAlg, ["typ"] = "JWT" };
        if (signer.Kid is not null)
        {
            header["kid"] = signer.Kid;
        }

        string signingInput = $"{B64Url(Encoding.UTF8.GetBytes(header.ToJsonString()))}.{B64Url(Encoding.UTF8.GetBytes(claims.ToJsonString()))}";
        byte[] signature = signer.Sign(Encoding.ASCII.GetBytes(signingInput));
        return $"{signingInput}.{B64Url(signature)}";
    }

    private static string B64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>The <c>200</c> body of <c>POST /oauth2/bc-authorize</c>.</summary>
    private sealed record CibaInitiateWire(
        [property: System.Text.Json.Serialization.JsonPropertyName("auth_req_id")] string? AuthReqId,
        [property: System.Text.Json.Serialization.JsonPropertyName("expires_in")] long ExpiresIn,
        [property: System.Text.Json.Serialization.JsonPropertyName("interval")] long? Interval);
}
