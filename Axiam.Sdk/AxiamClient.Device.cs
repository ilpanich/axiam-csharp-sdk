using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Rest;

namespace Axiam.Sdk;

// CONTRACT.md §6.1 rules 6-10 — authenticate_device(), the mTLS device login,
// AuthenticateDeviceAsync() under §1's C# name (contract 1.51).
public sealed partial class AxiamClient
{
    private const string DeviceAuthPath = "/api/v1/auth/device";

    /// <summary>
    /// <c>POST /api/v1/auth/device</c> (CONTRACT.md &#167;6.1 rules 6&#8211;10): the mTLS
    /// device login. Issues no request body and returns a new <see cref="AxiamClient"/>
    /// handle already carrying the returned <see cref="DeviceToken"/> as its credential —
    /// adopted exactly as a <see cref="LoginAsync"/> result is adopted — plus the raw
    /// token for a caller that wants to inspect <see cref="DeviceToken.ExpiresIn"/> or
    /// persist it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Reachable only on a client configured with a certificate</b> (&#167;6.1 rule 7).
    /// Calling this on a client built without <see cref="Options.AxiamClientOptions.ClientCertificatePem"/>/
    /// <see cref="Options.AxiamClientOptions.ClientKeyPem"/> throws <see cref="AuthError"/>
    /// client-side, with ZERO wire calls — without a certificate the server would answer
    /// <c>401</c> in any case, so going to the wire would only turn a configuration mistake
    /// into an authentication failure.
    /// </para>
    /// <para>
    /// <b>A device holds no login result.</b> The returned handle is built over a FRESH,
    /// empty cookie jar of its own — never <c>this</c> client's session — so a device
    /// token can never run as whatever principal <c>this</c> client happened to be signed
    /// in as, and an earlier session's refresh token (if any) cannot survive into a
    /// credential that has none. Every subsequent request the returned handle makes
    /// carries the device token as <c>Authorization: Bearer</c>; there is no cookie for
    /// the server's cookie-before-header read order to prefer instead. The &#167;17
    /// decision memo and the &#167;5.2 acting-tenant gate both start fresh/unknown on the
    /// returned handle, matching "a device holds no login result." The SAME withholding
    /// applies to the login POST itself: it runs over <see cref="_anonymousHttpClient"/>
    /// (&#167;24.1's anonymous transport, own permanently-empty cookie jar, never wrapped in
    /// <see cref="Rest.AxiamHttpMessageHandler"/>) rather than <c>_httpClient</c>, so it
    /// carries neither <c>this</c> client's <c>Cookie</c> header nor the
    /// <c>Authorization: Bearer</c> header <see cref="Rest.AxiamHttpMessageHandler"/> would
    /// otherwise derive from an existing session's <c>axiam_access</c> cookie — the server
    /// reads <c>axiam_access</c> before <c>Authorization</c>, so either one reaching the
    /// wire could evaluate this call against the PRIOR principal instead of the
    /// certificate presenting it.
    /// </para>
    /// <para>
    /// <b>No refresh, ever</b> (&#167;6.1 rule 6/8). There is no refresh token — the
    /// returned handle's transport never attempts one. A later <c>401</c> on the device
    /// token (an expired or revoked credential) surfaces as <see cref="AuthError"/>
    /// exactly as this call's own <c>401</c> would; the recovery path is calling
    /// <see cref="AuthenticateDeviceAsync"/> again, which costs one TLS handshake. A
    /// <c>429</c> (the route's per-client-IP rate limit) is NOT an authentication failure
    /// and is not retried (&#167;16), matching every other AXIAM login.
    /// </para>
    /// </remarks>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>
    /// A new <see cref="AxiamClient"/> handle, already authenticated with the device
    /// token, and the <see cref="DeviceToken"/> itself.
    /// </returns>
    /// <exception cref="AuthError">
    /// No client certificate is configured (client-side, zero wire calls); or the server
    /// refused the certificate — unknown, untrusted, expired, revoked, unbound, or a
    /// <c>Server</c>-type certificate all answer <c>401</c> (&#167;6.1 rule 8), surfaced
    /// verbatim.
    /// </exception>
    public async Task<(AxiamClient Client, DeviceToken Token)> AuthenticateDeviceAsync(CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();

        // §6.1 rule 7: reachable only on a client configured with a certificate. C# has
        // no typestate to make this a compile error (the same judgement call the
        // reference implementation records for its own language) — the client-side
        // AuthError is the conforming alternative the rule itself names.
        if (_options.ClientCertificatePem is null || _options.ClientKeyPem is null)
        {
            throw new AuthError(
                "AuthenticateDeviceAsync() requires a client certificate — construct this "
                + "AxiamClient with ClientCertificatePem and ClientKeyPem set (CONTRACT.md §6.1 rule 7); "
                + "without one the server would answer 401, so this call was refused locally "
                + "and never reached the network.");
        }

        // No request body at all — not even `{}` (§6.1 rule 6). Runs over the ANONYMOUS
        // transport (_anonymousHttpClient, §24.1's own permanently-empty-jar client), NOT
        // `_httpClient` — a client that already holds a cookie session must not let that
        // session's `Cookie` header or its derived `Authorization: Bearer` reach this
        // call; the mTLS handshake alone is what authenticates it (§6.1 rule 4).
        // `_anonymousHttpClient`'s primary handler is built from the SAME
        // CustomCaPem/ClientCertificatePem/ClientKeyPem/TLS policy as `_httpClient`'s (see
        // the constructor), so the certificate this call needs to present is unaffected —
        // only the session-derived headers are withheld. `_anonymousHttpClient` is never
        // wrapped in AxiamHttpMessageHandler, so — unlike that handler's derivation of
        // X-Tenant-Id (§5 rule 2, unconditional on every request) — it must be added here
        // by hand, exactly as PostAnonymousRawJsonAsync does for the §24.1 pair.
        using var request = new HttpRequestMessage(HttpMethod.Post, DeviceAuthPath);
        request.Headers.TryAddWithoutValidation("X-Tenant-Id", _tenant.TenantId);
        HttpResponseMessage response;
        try
        {
            response = await _anonymousHttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw NetworkError.FromException(ex, $"POST {DeviceAuthPath} failed");
        }

        using (response)
        {
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                // §6.1 rule 8: "the message differs by case, and the SDK surfaces it
                // verbatim" — unlike ErrorMapper.FromHttpResponse's generic 401 case
                // (which, matching every other 401 site in this SDK, uses a fixed
                // context string and does not read the body), this operation's rule is
                // explicit enough to read the server's own "message" field itself.
                // Falls back to the generic context only when the body carries none —
                // a malformed/absent body must not make this call throw a DIFFERENT
                // exception than AuthError.
                throw new AuthError(await ReadDeviceAuthMessageAsync(response, cancellationToken).ConfigureAwait(false));
            }

            if (response.StatusCode != HttpStatusCode.OK)
            {
                // A 429 (the route's rate limit) and anything else map through
                // NetworkError, never AuthError (§16: not an authentication failure, not
                // retried — this IS the login, attempted exactly once like every other).
                throw ErrorMapper.FromHttpResponse(response, "device authentication failed");
            }

            JsonElement wire = await ReadJsonAsync(response, cancellationToken).ConfigureAwait(false);
            string accessToken = ReadString(wire, "access_token");
            string tokenType = wire.TryGetProperty("token_type", out JsonElement typeEl) && typeEl.ValueKind == JsonValueKind.String
                ? typeEl.GetString() ?? "Bearer"
                : "Bearer";
            int expiresIn = wire.TryGetProperty("expires_in", out JsonElement expEl) && expEl.TryGetInt32(out int seconds)
                ? seconds
                : 900;

            var token = new DeviceToken(Sensitive.Of(accessToken), tokenType, expiresIn);
            AxiamClient deviceHandle = BuildDeviceHandle(accessToken);
            return (deviceHandle, token);
        }
    }

    /// <summary>
    /// Builds the handle <see cref="AuthenticateDeviceAsync"/> returns: a FULLY
    /// INDEPENDENT client over the same certificate identity and tenant/org
    /// configuration as <c>this</c>, but with its own empty cookie jar, its own
    /// <see cref="AxiamHttpMessageHandler"/> (configured with the device token as a
    /// static bearer credential — see that class's <c>staticBearerToken</c> parameter),
    /// its own never-invoked <see cref="RefreshGuard"/>, and its own &#167;17 memo/&#167;5.2
    /// session state. This is deliberately NOT a &#167;5.2 <c>ActingTenant</c>-style "view"
    /// over <c>this</c> client's session — a device credential shares nothing of
    /// <c>this</c> client's session, by construction, rather than by a conditional that
    /// has to remember to withhold it.
    /// </summary>
    /// <summary>
    /// The server's own <c>message</c> field from a <c>401</c> on
    /// <c>POST /api/v1/auth/device</c> (&#167;6.1 rule 8's "surfaces it verbatim"), or a
    /// generic fallback when the body carries none — never throws itself, matching
    /// <c>ReadSetupTokenAsync</c>'s established pattern of tolerating a non-JSON/absent
    /// body on an already-decided error path.
    /// </summary>
    private static async Task<string> ReadDeviceAuthMessageAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            string raw = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(raw))
            {
                using JsonDocument doc = JsonDocument.Parse(raw);
                if (doc.RootElement.TryGetProperty("message", out JsonElement messageEl)
                    && messageEl.ValueKind == JsonValueKind.String
                    && messageEl.GetString() is { Length: > 0 } message)
                {
                    return message;
                }
            }
        }
        catch (JsonException)
        {
            // Not a JSON body the server shaped this way — fall through to the generic message.
        }
        return "device authentication failed";
    }

    private AxiamClient BuildDeviceHandle(string deviceAccessToken) => new(this, deviceAccessToken);

    /// <summary>
    /// Builds the device handle — see <see cref="BuildDeviceHandle"/>. The
    /// <paramref name="deviceAccessToken"/> parameter is what distinguishes this overload
    /// from the &#167;5.2 <see cref="AxiamClient(AxiamClient, Guid?)"/> copy-constructor.
    /// </summary>
    private AxiamClient(AxiamClient source, string deviceAccessToken)
    {
        _tenant = source._tenant;
        _options = source._options;
        _baseUrl = source._baseUrl;
        _jwksVerifier = source._jwksVerifier; // org-wide JWKS; harmless and efficient to share
        _telemetry = source._telemetry;
        _session = new SharedSession(); // a device holds no login result (§5.2 rule 1)
        _actingTenant = null;
        _ownsResources = true; // a genuinely independent transport, not a view over source's
        _transportOverride = source._transportOverride;
        _staticBearerToken = deviceAccessToken;

        // The SAME fake transport `CreateForTesting` gave `source`, when there is one —
        // never a real socket-dialing handler in a unit test. In production
        // `_transportOverride` is always null, so this is `AxiamHttpClientFactory.CreatePrimaryHandler`
        // with a genuinely fresh, empty cookie jar, exactly as the public constructor
        // builds its own — never source's session (a device holds no login result).
        HttpMessageHandler primaryHandler = _transportOverride
            ?? AxiamHttpClientFactory.CreatePrimaryHandler(_options.CustomCaPem, _options.ClientCertificatePem, _options.ClientKeyPem);
        // Mirrors the public constructor: when the underlying handler IS a real
        // HttpClientHandler, its own (fresh, empty) CookieContainer is the one that
        // actually governs the wire — a SEPARATE CookieContainer object here would just
        // be dead bookkeeping AxiamHttpMessageHandler reads from but the transport never
        // writes to. Against the fake test transport (not an HttpClientHandler), an
        // empty throwaway container is correct too: nothing reads or writes it.
        _cookieContainer = (primaryHandler as HttpClientHandler)?.CookieContainer ?? new CookieContainer();

        // §6.1 rule 6/8: no refresh token exists for a device credential, so this guard's
        // delegate is never invoked — AxiamHttpMessageHandler treats every path as
        // refresh-exempt whenever staticBearerToken is set (see that class). It still
        // needs a real delegate to satisfy RefreshGuard's constructor, and one that fails
        // loudly is the right shape for something that must never run.
        _refreshGuard = new RefreshGuard(_ => throw new AuthError(
            "unreachable: a device-credentialed handle never attempts a token refresh (CONTRACT.md §6.1 rule 6)"));

        _authHandler = new AxiamHttpMessageHandler(
            _cookieContainer, _baseUrl, _tenant.TenantId, _refreshGuard, staticBearerToken: deviceAccessToken)
        {
            InnerHandler = primaryHandler,
        };

        // disposeHandler: false whenever the inner handler is the SHARED test override —
        // disposing this handle must never tear down a transport `source` (or a sibling
        // handle) is still using. In production `primaryHandler` is this handle's own,
        // so disposing it here is correct and matches the public constructor.
        _httpClient = new HttpClient(_authHandler, disposeHandler: _transportOverride is null)
        {
            BaseAddress = _baseUrl,
            Timeout = _options.RequestTimeout,
        };

        // Mirrors the public constructor's own _anonymousPrimaryHandler/_anonymousHttpClient
        // pair exactly, `_transportOverride` gate included — a device handle's §24.1
        // setup calls (if it ever makes one) must reach the same fake transport a test
        // mounted, exactly like every other transport this constructor builds.
        _anonymousPrimaryHandler = _transportOverride
            ?? AxiamHttpClientFactory.CreatePrimaryHandler(_options.CustomCaPem, _options.ClientCertificatePem, _options.ClientKeyPem);
        _anonymousHttpClient = new HttpClient(_anonymousPrimaryHandler, disposeHandler: _transportOverride is null)
        {
            BaseAddress = _baseUrl,
            Timeout = _options.RequestTimeout,
        };

        _decisionMemo = new DecisionMemo(_options.DecisionMemoTtl);
        _authz = new AuthzRestClient(_httpClient, _options, _telemetry, _decisionMemo);

        InitializeOidcState();
    }
}
