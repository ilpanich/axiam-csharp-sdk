using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;

namespace Axiam.Sdk;

// CONTRACT.md §12 — OIDC / SSO Relying-Party Helpers.
//
// The nine canonical §12 operations, under the exact §12.2 C# names (PascalCase + `Async`
// suffix per §1/SDK-Q08, EXCEPT OidcBegin — the one deliberate exception: it performs no
// network I/O, so it carries no `Async` suffix), as members of the existing AxiamClient
// (§12 T1 reference judgment call 1 — no parallel client type):
//   OidcDiscoverAsync, OidcBegin, OidcExchangeAsync, OidcRefreshAsync,
//   LoginClientCredentialsAsync, IntrospectAsync, RevokeAsync, SsoStartAsync,
//   SsoCompleteAsync, and -- as of contract 1.38 -- SsoProvidersAsync,
//   SsoStartOauth2Async, SsoCompleteOauth2Async, SsoCompleteHandoffAsync.
//
// Built on the SDK's EXISTING machinery only (§12 forbids forking any of it):
//   - the same _httpClient / AxiamHttpMessageHandler transport every other REST call uses,
//     so §3 CSRF, §4 cookie jar, §5 X-Tenant-ID, and §6 TLS all apply unconditionally;
//   - JwksVerifier.VerifyOidcIdTokenSignatureAsync (Auth/JwksVerifier.cs), extended never
//     forked, for §12.4 rules 1-2;
//   - ErrorMapper (Core/ErrorMapper.cs) as the fallback for any non-OAuth2-shaped error;
//   - Sensitive<T> (Core/Sensitive.cs) for the five §12.5 secret fields.
public sealed partial class AxiamClient
{
    private const string OidcDiscoveryPath = "/.well-known/openid-configuration";
    private const string SsoStartPath = "/api/v1/auth/federation/oidc/start";
    private const string SsoCompletePath = "/api/v1/auth/federation/oidc/callback";

    // Contract 1.38's public "Sign in with X" surface.
    private const string SsoProvidersPath = "/api/v1/auth/federation/providers";
    private const string SsoOAuth2StartPath = "/api/v1/auth/federation/oauth2/start";
    private const string SsoOAuth2CompletePath = "/api/v1/auth/federation/oauth2/callback";
    private const string SsoHandoffPath = "/api/v1/auth/federation/handoff";

    /// <summary>CONTRACT.md &#167;12.3 rule 6 FLOOR for the discovery-document cache TTL.</summary>
    private static readonly TimeSpan MinOidcDiscoveryTtl = TimeSpan.FromMinutes(5);

    /// <summary>The eight query parameters <see cref="OidcBegin"/> owns (&#167;12.1 rule 5).
    /// Caller-supplied <c>ExtraParams</c> may add to the authorization request but must
    /// never override these.</summary>
    private static readonly HashSet<string> ReservedAuthorizeParams = new(StringComparer.Ordinal)
    {
        "response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
        "code_challenge", "code_challenge_method",
    };

    private string? _oidcClientId;
    private Sensitive<string>? _oidcClientSecret;
    private TimeSpan _oidcDiscoveryTtl;
    private int _oidcClockSkewSeconds;

    // ---- Discovery cache: per-CLIENT-INSTANCE (never process-global/static), so it is
    // inherently keyed to this client's own single origin (§12.3 rule 6) — this client
    // only ever fetches discovery from its own configured base URL, so no explicit
    // per-origin map is needed the way a multi-origin SDK would require. SemaphoreSlim(1,1)
    // both serializes a concurrent burst into exactly one HTTP fetch AND doubles as the
    // cache guard — mirrors JwksVerifier's own _fetchLock idiom for consistency.
    private readonly SemaphoreSlim _discoveryLock = new(1, 1);
    private OidcConfiguration? _discoveryCache;
    private DateTimeOffset _discoveryExpiresAt = DateTimeOffset.MinValue;

    // ---- Per-jwks_uri verifier cache (§12.3 rule 6: JWKS is a single global key set, not
    // per-tenant — keyed on jwks_uri, never on tenant). A plain lock is sufficient: building
    // a JwksVerifier performs no I/O.
    private readonly object _oidcJwksLock = new();
    private readonly Dictionary<string, JwksVerifier> _oidcJwksVerifiers = new();

    // ---- oidc_refresh's OWN single-flight guard (CONTRACT.md §9's C# mechanism —
    // SemaphoreSlim(1,1) + Task<T> stored in a field — applied to this independent
    // operation). See RunOidcRefreshSingleFlightAsync's doc comment for why this is a
    // SEPARATE instance from the cookie-session RefreshGuard field above, not the literal
    // same guard.
    private readonly SemaphoreSlim _oidcRefreshGate = new(1, 1);
    private Task<OidcTokenSet>? _oidcRefreshInFlight;

    private void InitializeOidcState()
    {
        _oidcClientId = _options.OidcClientId;
        _oidcClientSecret = string.IsNullOrWhiteSpace(_options.OidcClientSecret)
            ? null
            : Sensitive.Of(_options.OidcClientSecret);
        _oidcDiscoveryTtl = _options.OidcDiscoveryTtl < MinOidcDiscoveryTtl ? MinOidcDiscoveryTtl : _options.OidcDiscoveryTtl;
        _oidcClockSkewSeconds = _options.OidcClockSkewSeconds is <= 0 or > 60 ? 60 : _options.OidcClockSkewSeconds;
    }

    private void DisposeOidcState()
    {
        _discoveryLock.Dispose();
        _oidcRefreshGate.Dispose();
    }

    // ------------------------------------------------------------------
    // 1. OidcDiscoverAsync
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>GET /.well-known/openid-configuration</c> (CONTRACT.md &#167;12.1) — fetches and
    /// caches the OIDC discovery document, with a &#8805;5-minute TTL and single-flight
    /// de-duplication of concurrent calls (&#167;12.3 rule 6).
    /// </summary>
    /// <remarks>
    /// The document's own <see cref="OidcConfiguration.Issuer"/> is authoritative for
    /// ID-token validation and may legitimately differ from this client's base URL behind
    /// a proxy, so a mismatch is never treated as an error.
    /// </remarks>
    public async Task<OidcConfiguration> OidcDiscoverAsync(CancellationToken cancellationToken = default)
    {
        await _discoveryLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_discoveryCache is { } cached && DateTimeOffset.UtcNow < _discoveryExpiresAt)
            {
                return cached;
            }

            HttpResponseMessage response;
            try
            {
                response = await _httpClient.GetAsync(OidcDiscoveryPath, cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                throw NetworkError.FromException(ex, "GET /.well-known/openid-configuration failed");
            }
            catch (OperationCanceledException ex) when (ex.CancellationToken != cancellationToken)
            {
                throw NetworkError.FromException(ex, "GET /.well-known/openid-configuration timed out");
            }

            using (response)
            {
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    throw ErrorMapper.FromHttpResponse(response, "oidc discovery failed");
                }

                OidcConfiguration document = await ReadOidcJsonAsync<OidcConfiguration>(response, cancellationToken).ConfigureAwait(false);
                _discoveryCache = document;
                _discoveryExpiresAt = DateTimeOffset.UtcNow + _oidcDiscoveryTtl;
                return document;
            }
        }
        finally
        {
            _discoveryLock.Release();
        }
    }

    // ------------------------------------------------------------------
    // 2. OidcBegin — NO Async suffix: pure local computation, no network I/O
    // (CONTRACT.md §12.2 "C# Async suffix" — the single deliberate exception).
    // ------------------------------------------------------------------

    /// <summary>
    /// Builds an authorization request (CONTRACT.md &#167;12.1) — PURE LOCAL COMPUTATION,
    /// no network I/O.
    /// </summary>
    /// <remarks>
    /// Generates a 32-byte CSPRNG <c>state</c> and <c>nonce</c> (base64url, unpadded) and a
    /// fresh PKCE verifier/challenge pair using S256 ONLY — <c>"plain"</c> is not
    /// implemented anywhere in this SDK. <see cref="AuthorizationRequest.Url"/> is built
    /// from <paramref name="configuration"/>'s <see cref="OidcConfiguration.AuthorizationEndpoint"/>
    /// with exactly the eight parameters &#167;12.1 rule 5 mandates, plus any
    /// <see cref="OidcBeginParams.ExtraParams"/> the caller adds. Nothing is stored: persist
    /// the returned <c>State</c>, <c>Nonce</c> and <c>CodeVerifier</c> yourself (&#167;12.3
    /// rule 1).
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// <paramref name="params"/>.<see cref="OidcBeginParams.ExtraParams"/> attempts to
    /// override one of the eight SDK-owned authorization parameters — a PROGRAMMING ERROR
    /// caught at call time, deliberately NOT the AuthError/AuthzError/NetworkError taxonomy
    /// (&#167;12 port addendum item 9).
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// <see cref="Options.AxiamClientOptions.OidcClientId"/> was not configured.
    /// </exception>
    public AuthorizationRequest OidcBegin(OidcConfiguration configuration, OidcBeginParams @params)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(@params);
        ArgumentException.ThrowIfNullOrWhiteSpace(@params.RedirectUri);

        string clientId = RequireOidcClientId();
        string state = OidcPkce.RandomUrlSafeToken();
        string nonce = OidcPkce.RandomUrlSafeToken();
        Sensitive<string> codeVerifier = OidcPkce.GenerateCodeVerifier();
        string codeChallenge = OidcPkce.ComputeCodeChallenge(codeVerifier.Reveal());
        string scope = NormalizeScope(@params.Scope);

        var query = new List<string>();
        if (@params.ExtraParams is not null)
        {
            foreach (KeyValuePair<string, string> extra in @params.ExtraParams)
            {
                if (ReservedAuthorizeParams.Contains(extra.Key))
                {
                    throw new ArgumentException(
                        $"OidcBegin: ExtraParams may not override the SDK-owned authorization parameter '{extra.Key}' (CONTRACT.md §12.1 rule 5).",
                        nameof(@params));
                }
                query.Add(EncodeQueryParam(extra.Key, extra.Value));
            }
        }

        query.Add(EncodeQueryParam("response_type", "code"));
        query.Add(EncodeQueryParam("client_id", clientId));
        query.Add(EncodeQueryParam("redirect_uri", @params.RedirectUri));
        query.Add(EncodeQueryParam("scope", scope));
        query.Add(EncodeQueryParam("state", state));
        query.Add(EncodeQueryParam("nonce", nonce));
        query.Add(EncodeQueryParam("code_challenge", codeChallenge));
        query.Add(EncodeQueryParam("code_challenge_method", OidcPkce.CodeChallengeMethodS256));

        char separator = configuration.AuthorizationEndpoint.Contains('?') ? '&' : '?';
        string url = $"{configuration.AuthorizationEndpoint}{separator}{string.Join("&", query)}";

        return new AuthorizationRequest(url, state, nonce, codeVerifier);
    }

    /// <summary>Percent-encodes a query key/value pair per RFC 3986, with spaces as
    /// <c>%20</c> (<see cref="Uri.EscapeDataString"/>'s behavior) rather than <c>+</c>
    /// (&#167;12.1 rule 5, &#167;12 port addendum item 10).</summary>
    private static string EncodeQueryParam(string key, string value) =>
        $"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(value)}";

    /// <summary>Returns a space-separated scope string that always contains
    /// <c>"openid"</c> first (&#167;12.1 rule 4), with duplicates collapsed.</summary>
    private static string NormalizeScope(string? scope)
    {
        var ordered = new List<string> { "openid" };
        var seen = new HashSet<string>(StringComparer.Ordinal) { "openid" };
        if (!string.IsNullOrWhiteSpace(scope))
        {
            foreach (string part in scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (seen.Add(part))
                {
                    ordered.Add(part);
                }
            }
        }
        return string.Join(' ', ordered);
    }

    // ------------------------------------------------------------------
    // 3. OidcExchangeAsync
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /oauth2/token</c> with <c>grant_type=authorization_code</c> (CONTRACT.md
    /// &#167;12.1) — exchanges an authorization code for a token set, validating the
    /// returned ID token in full before returning.
    /// </summary>
    /// <remarks>
    /// <paramref name="params"/>.<see cref="OidcExchangeParams.Nonce"/> is mandatory: this
    /// grant always requests the <c>"openid"</c> scope, so &#167;12.4 rule 6 always applies.
    /// If ANY &#167;12.4 rule fails, the whole token set is discarded and
    /// <see cref="AuthError"/> is raised with the matching <see cref="AuthError.Reason"/>
    /// code — the access and refresh tokens from the same response are never returned
    /// (&#167;12.4 rule 7).
    /// </remarks>
    public async Task<OidcTokenSet> OidcExchangeAsync(OidcExchangeParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);
        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        Guid tenantId = ResolveOidcTenantId(@params.TenantId);
        string clientId = RequireOidcClientId();

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = @params.Code,
            ["code_verifier"] = @params.CodeVerifier.Reveal(),
            ["redirect_uri"] = @params.RedirectUri,
            ["client_id"] = clientId,
        };
        AppendOidcClientSecretIfConfigured(form);

        TokenResponseWire wire = await PostTokenAsync(configuration, form, tenantId, cancellationToken).ConfigureAwait(false);
        var expectations = new IdTokenExpectations(configuration.Issuer, clientId, HasNonce: true, @params.Nonce, _oidcClockSkewSeconds);
        return await ToTokenSetAsync(wire, configuration, expectations, cancellationToken).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------
    // 4. OidcRefreshAsync
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /oauth2/token</c> with <c>grant_type=refresh_token</c> (CONTRACT.md
    /// &#167;12.1) under a single-flight refresh guard (&#167;9): concurrent callers
    /// collapse into ONE HTTP request and all receive the same <see cref="OidcTokenSet"/>
    /// (or the same failure), with no retry loop on failure (&#167;9.3).
    /// </summary>
    /// <remarks>
    /// This is a DISTINCT operation from the &#167;1 <c>RefreshAsync</c>, which drives the
    /// cookie/opaque-token session path at <c>POST /api/v1/auth/refresh</c> (&#167;5.1). The
    /// two MUST NOT be merged, aliased, or made to fall back to one another
    /// (CONTRACT.md &#167;12.1 "<c>oidc_refresh</c> vs <c>refresh</c>"). An <c>id_token</c>
    /// in the response is validated against &#167;12.4 rules 1-5 and 7; rule 6 (nonce) is
    /// skipped, since OIDC Core &#167;12.2 does not require a nonce in a refresh-issued ID
    /// token.
    /// </remarks>
    public Task<OidcTokenSet> OidcRefreshAsync(OidcRefreshParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);
        return RunOidcRefreshSingleFlightAsync(() => DoOidcRefreshAsync(@params, cancellationToken), cancellationToken);
    }

    private async Task<OidcTokenSet> DoOidcRefreshAsync(OidcRefreshParams @params, CancellationToken cancellationToken)
    {
        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        Guid tenantId = ResolveOidcTenantId(@params.TenantId);
        string clientId = RequireOidcClientId();

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = @params.RefreshToken.Reveal(),
            ["client_id"] = clientId,
        };
        AppendOidcClientSecretIfConfigured(form);
        if (!string.IsNullOrEmpty(@params.Scope))
        {
            form["scope"] = @params.Scope;
        }

        TokenResponseWire wire = await PostTokenAsync(configuration, form, tenantId, cancellationToken).ConfigureAwait(false);
        var expectations = new IdTokenExpectations(configuration.Issuer, clientId, HasNonce: false, Nonce: null, _oidcClockSkewSeconds);
        return await ToTokenSetAsync(wire, configuration, expectations, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// A &#167;9-mechanism single-flight guard DEDICATED to <c>oidc_refresh</c> (CONTRACT.md
    /// &#167;12.1: "<c>oidc_refresh</c> MUST run under the &#167;9 single-flight refresh
    /// guard").
    /// </summary>
    /// <remarks>
    /// Deliberately a SEPARATE <see cref="SemaphoreSlim"/>(1,1)+<see cref="Task{T}"/>
    /// instance (<see cref="_oidcRefreshGate"/>/<see cref="_oidcRefreshInFlight"/>) — built
    /// from the exact mechanism &#167;9 prescribes for C# — from the cookie-session
    /// <see cref="RefreshGuard"/> field this same class owns, rather than the literal same
    /// guard object: <see cref="RefreshGuard"/>'s freshness-reuse check compares a
    /// <see cref="TokenPair"/>'s <c>ExpiresAt</c> against the shared <c>axiam_access</c>
    /// cookie session, which has no meaning for an OAuth2 <c>refresh_token</c> grant
    /// operating on a wholly separate, cookie-independent token namespace — reusing that
    /// instance would corrupt its cookie-session comparison state with an unrelated token
    /// stream. This mirrors the Go sibling port's identical, documented deviation from the
    /// TypeScript reference (whose guard has no such comparison state to corrupt in the
    /// first place). Concurrent callers that arrive while a refresh is in flight share the
    /// SAME <see cref="Task{T}"/> (and thus the same outcome, success or failure) instead of
    /// each starting their own wire call; the in-flight slot is cleared once its own call
    /// completes so the NEXT call always starts a fresh attempt — no retry loop (&#167;9.3).
    /// </remarks>
    private async Task<OidcTokenSet> RunOidcRefreshSingleFlightAsync(Func<Task<OidcTokenSet>> action, CancellationToken cancellationToken)
    {
        await _oidcRefreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        Task<OidcTokenSet> task;
        bool owner;
        if (_oidcRefreshInFlight is { IsCompleted: false } pending)
        {
            task = pending;
            owner = false;
        }
        else
        {
            task = action();
            _oidcRefreshInFlight = task;
            owner = true;
        }
        _oidcRefreshGate.Release();

        try
        {
            return await task.ConfigureAwait(false);
        }
        finally
        {
            if (owner)
            {
                await _oidcRefreshGate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
                try
                {
                    if (ReferenceEquals(_oidcRefreshInFlight, task))
                    {
                        _oidcRefreshInFlight = null;
                    }
                }
                finally
                {
                    _oidcRefreshGate.Release();
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 5. LoginClientCredentialsAsync
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /oauth2/token</c> with <c>grant_type=client_credentials</c> (CONTRACT.md
    /// &#167;12.1) — service-account machine-to-machine login. Requests no <c>"openid"</c>
    /// scope, so the response carries no <c>id_token</c>.
    /// </summary>
    /// <exception cref="AuthError">
    /// The client was not constructed with <see cref="Options.AxiamClientOptions.OidcClientSecret"/>
    /// — this grant cannot be performed by a public client (&#167;12.1 note 4).
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// <paramref name="params"/>.<see cref="LoginClientCredentialsParams.AdoptAsCredential"/>
    /// was <c>true</c> — NOT IMPLEMENTED by this port (&#167;12 port addendum item 13
    /// explicitly permits skipping the &#167;12.1 "adopt as credential" MAY; see the
    /// CHANGELOG).
    /// </exception>
    public async Task<OidcTokenSet> LoginClientCredentialsAsync(LoginClientCredentialsParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);
        if (@params.AdoptAsCredential)
        {
            throw new NotSupportedException(
                "LoginClientCredentialsAsync's AdoptAsCredential is not implemented in this SDK port (CONTRACT.md §12.1 is a MAY; see CHANGELOG.md).");
        }

        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        string clientId = RequireOidcClientId();
        string clientSecret = RequireOidcClientSecret(nameof(LoginClientCredentialsAsync));
        Guid tenantId = ResolveOidcTenantId(@params.TenantId);

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
        };
        if (!string.IsNullOrEmpty(@params.Scope))
        {
            form["scope"] = @params.Scope;
        }

        TokenResponseWire wire = await PostTokenAsync(configuration, form, tenantId, cancellationToken).ConfigureAwait(false);
        var expectations = new IdTokenExpectations(configuration.Issuer, clientId, HasNonce: false, Nonce: null, _oidcClockSkewSeconds);
        return await ToTokenSetAsync(wire, configuration, expectations, cancellationToken).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------
    // 6. IntrospectAsync
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /oauth2/introspect</c> (RFC 7662, CONTRACT.md &#167;12.1) — asks the server
    /// whether a token is active and, if so, for its metadata.
    /// </summary>
    /// <remarks>
    /// Requires confidential-client credentials (&#167;12.1 note 4). A <c>401</c> here is a
    /// CLIENT-CREDENTIAL failure surfaced as <see cref="OAuthProtocolError"/>; it never
    /// enters the &#167;9 single-flight refresh guard, because refreshing the session
    /// cannot fix a bad <c>client_secret</c> (&#167;12.3 rule 3, enforced transport-wide by
    /// <c>AxiamHttpMessageHandler</c>'s exempt-path list).
    /// </remarks>
    public async Task<IntrospectionResult> IntrospectAsync(IntrospectParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);
        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        string clientSecret = RequireOidcClientSecret(nameof(IntrospectAsync));
        Guid tenantId = ResolveOidcTenantId(@params.TenantId);

        var form = new Dictionary<string, string>
        {
            ["token"] = @params.Token.Reveal(),
            ["client_id"] = RequireOidcClientId(),
            ["client_secret"] = clientSecret,
        };
        if (@params.TokenTypeHint is not null)
        {
            form["token_type_hint"] = @params.TokenTypeHint;
        }

        using HttpResponseMessage response = await PostOAuth2FormAsync(configuration.IntrospectionEndpoint, form, tenantId, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await MapOAuth2ErrorAsync(response, "introspect failed", cancellationToken).ConfigureAwait(false);
        }

        IntrospectionResponseWire wire = await ReadOidcJsonAsync<IntrospectionResponseWire>(response, cancellationToken).ConfigureAwait(false);
        return new IntrospectionResult(wire.Active, wire.Sub, wire.ClientId, wire.Scope, wire.TokenType, wire.Exp, wire.Iat);
    }

    // ------------------------------------------------------------------
    // 7. RevokeAsync
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /oauth2/revoke</c> (RFC 7009, CONTRACT.md &#167;12.1) — revokes an access or
    /// refresh token.
    /// </summary>
    /// <remarks>
    /// Per RFC 7009 the server answers <c>200</c> for an unknown, expired, or
    /// already-revoked token alike, so revocation is IDEMPOTENT: any 2xx is success and no
    /// error is raised for a token the server has never seen. Only a <c>401</c> (client
    /// authentication failed) is an error, surfaced as <see cref="OAuthProtocolError"/>
    /// (&#167;12.1 note 5, &#167;12.3 rule 3); a 5xx is still a <see cref="NetworkError"/> —
    /// revoke returning void does not make a server error "success" (&#167;12 T1 reference
    /// judgment call 20).
    /// </remarks>
    public async Task RevokeAsync(RevokeParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);
        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        string clientSecret = RequireOidcClientSecret(nameof(RevokeAsync));
        Guid tenantId = ResolveOidcTenantId(@params.TenantId);

        var form = new Dictionary<string, string>
        {
            ["token"] = @params.Token.Reveal(),
            ["client_id"] = RequireOidcClientId(),
            ["client_secret"] = clientSecret,
        };
        if (@params.TokenTypeHint is not null)
        {
            form["token_type_hint"] = @params.TokenTypeHint;
        }

        using HttpResponseMessage response = await PostOAuth2FormAsync(configuration.RevocationEndpoint, form, tenantId, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await MapOAuth2ErrorAsync(response, "revoke failed", cancellationToken).ConfigureAwait(false);
        }
        // Any 2xx (including for a token the server has never seen) is success — nothing
        // further to do.
    }

    // ------------------------------------------------------------------
    // 8. SsoStartAsync
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /api/v1/auth/federation/oidc/start</c> (CONTRACT.md &#167;12.1) — step 1 of
    /// first-time SSO against an UPSTREAM IdP. No JWT required.
    /// </summary>
    /// <remarks>
    /// One tenant form (<see cref="SsoStartParams.TenantId"/> or
    /// <see cref="SsoStartParams.TenantSlug"/>) and one org form
    /// (<see cref="SsoStartParams.OrgId"/> or <see cref="SsoStartParams.OrgSlug"/>) must be
    /// resolvable, from the arguments or from this client's own construction options
    /// (&#167;5.1). Redirect the browser to the returned
    /// <see cref="SsoStartResult.AuthorizeUrl"/> and round-trip
    /// <see cref="SsoStartResult.State"/> back into <see cref="SsoCompleteAsync"/>
    /// unmodified — the server keeps the nonce to itself (&#167;12.1 note 7).
    /// </remarks>
    /// <exception cref="AuthError">Tenant or organization context cannot be resolved —
    /// raised client-side with no wire call.</exception>
    public async Task<SsoStartResult> SsoStartAsync(SsoStartParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);

        string? tenantIdStr = @params.TenantId?.ToString();
        string? tenantSlug = @params.TenantSlug;
        if (tenantIdStr is null && tenantSlug is null)
        {
            if (Guid.TryParse(_tenant.TenantId, out Guid selfTenantGuid))
            {
                tenantIdStr = selfTenantGuid.ToString();
            }
            else
            {
                tenantSlug = _tenant.TenantId;
            }
        }
        if (tenantIdStr is null && tenantSlug is null)
        {
            throw new AuthError("SsoStartAsync requires tenant context: pass TenantId or TenantSlug, or construct the client with one (CONTRACT.md §5.1).");
        }

        string? orgIdStr = @params.OrgId?.ToString();
        string? orgSlug = @params.OrgSlug;
        if (orgIdStr is null && orgSlug is null)
        {
            if (_tenant.OrgId is Guid selfOrgId)
            {
                orgIdStr = selfOrgId.ToString();
            }
            else if (_tenant.OrgSlug is string selfOrgSlug)
            {
                orgSlug = selfOrgSlug;
            }
        }
        if (orgIdStr is null && orgSlug is null)
        {
            throw new AuthError("SsoStartAsync requires organization context: pass OrgId or OrgSlug, or construct the client with OrgId/OrgSlug (CONTRACT.md §5.1).");
        }

        var body = new Dictionary<string, object?>
        {
            ["federation_config_id"] = @params.FederationConfigId,
            ["redirect_uri"] = @params.RedirectUri,
        };
        if (tenantIdStr is not null)
        {
            body["tenant_id"] = tenantIdStr;
        }
        else
        {
            body["tenant_slug"] = tenantSlug;
        }
        if (orgIdStr is not null)
        {
            body["org_id"] = orgIdStr;
        }
        else
        {
            body["org_slug"] = orgSlug;
        }

        using HttpResponseMessage response = await PostJsonAsync(SsoStartPath, body, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            // §12 port addendum item 12: the federation error body shape is undocumented —
            // fall through to the generic §2 status mapping, never attempt to parse an
            // OAuth2ErrorResponse here.
            throw ErrorMapper.FromHttpResponse(response, "sso_start failed");
        }

        OidcStartResponseWire wire = await ReadOidcJsonAsync<OidcStartResponseWire>(response, cancellationToken).ConfigureAwait(false);
        return new SsoStartResult(wire.AuthorizeUrl, wire.State, wire.ExpiresInSecs);
    }

    // ------------------------------------------------------------------
    // 9. SsoCompleteAsync
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /api/v1/auth/federation/oidc/callback</c> (CONTRACT.md &#167;12.1) — step 2
    /// of upstream SSO: consumes the single-use state, provisions or links the user, and
    /// establishes the session.
    /// </summary>
    /// <remarks>
    /// The session arrives as <c>Set-Cookie</c>, NOT in the response body (&#167;12.1
    /// note 6), so this call goes through the SAME &#167;4 cookie-jar path every other
    /// request already uses — the shared <c>CookieContainer</c> captures it automatically,
    /// no separate wiring needed. &#167;12.4 does not apply here — no ID token ever reaches
    /// the SDK on the federation path.
    /// </remarks>
    public async Task<SsoCompleteResult> SsoCompleteAsync(SsoCompleteParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);

        var body = new Dictionary<string, object?> { ["state"] = @params.State, ["code"] = @params.Code };
        using HttpResponseMessage response = await PostJsonAsync(SsoCompletePath, body, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(response, "sso_complete failed");
        }

        SsoLoginSuccessResponseWire wire = await ReadOidcJsonAsync<SsoLoginSuccessResponseWire>(response, cancellationToken).ConfigureAwait(false);
        return new SsoCompleteResult(wire.UserId, wire.SessionId, wire.ExpiresIn, wire.RedirectUri);
    }

    // ------------------------------------------------------------------
    // 10. SsoProvidersAsync  (contract 1.38)
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>GET /api/v1/auth/federation/providers</c> (CONTRACT.md &#167;12.1) — which
    /// "Sign in with X" buttons to render for a workspace.
    /// </summary>
    /// <remarks>
    /// <para>The identifiers travel as <b>query</b> parameters; this is a <c>GET</c> and
    /// sends no body. The neighbouring start operations take the same four in a JSON body,
    /// and the two are one copy-paste apart.</para>
    /// <para><b>An empty list is a success.</b> An unknown organization, a known one with
    /// nothing configured, and a request naming no workspace at all all answer <c>200</c>
    /// with an empty <c>providers</c> array (&#167;12.1 note 9). Every one of them comes back
    /// as an ordinary result and nothing here synthesises a not-found: the endpoint is
    /// deliberately shaped so it cannot be used to enumerate organization or tenant slugs,
    /// and an SDK that reintroduced the distinction would reintroduce the oracle. A caller
    /// learns it named the workspace wrongly at the start operations, where every failure is
    /// a uniform <c>401</c>.</para>
    /// <para>For the same reason this is the one federation operation that does <b>not</b>
    /// throw client-side when no workspace resolves.</para>
    /// </remarks>
    /// <param name="params">The workspace to list providers for; every field optional.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The providers to offer, possibly empty.</returns>
    public async Task<FederationProviderList> SsoProvidersAsync(SsoProvidersParams? @params = null, CancellationToken cancellationToken = default)
    {
        @params ??= new SsoProvidersParams();

        string? tenantIdStr = @params.TenantId?.ToString();
        string? tenantSlug = @params.TenantSlug;
        if (tenantIdStr is null && tenantSlug is null)
        {
            if (Guid.TryParse(_tenant.TenantId, out Guid selfTenantGuid))
            {
                tenantIdStr = selfTenantGuid.ToString();
            }
            else
            {
                tenantSlug = _tenant.TenantId;
            }
        }

        string? orgIdStr = @params.OrgId?.ToString();
        string? orgSlug = @params.OrgSlug;
        if (orgIdStr is null && orgSlug is null)
        {
            if (_tenant.OrgId is Guid selfOrgId)
            {
                orgIdStr = selfOrgId.ToString();
            }
            else if (_tenant.OrgSlug is string selfOrgSlug)
            {
                orgSlug = selfOrgSlug;
            }
        }

        // Deliberately NO client-side refusal when nothing resolves: see the remarks above.
        var query = new List<string>(4);
        if (orgIdStr is not null)
        {
            query.Add($"org_id={Uri.EscapeDataString(orgIdStr)}");
        }
        else if (orgSlug is not null)
        {
            query.Add($"org_slug={Uri.EscapeDataString(orgSlug)}");
        }
        if (tenantIdStr is not null)
        {
            query.Add($"tenant_id={Uri.EscapeDataString(tenantIdStr)}");
        }
        else if (tenantSlug is not null)
        {
            query.Add($"tenant_slug={Uri.EscapeDataString(tenantSlug)}");
        }

        string url = query.Count == 0 ? SsoProvidersPath : $"{SsoProvidersPath}?{string.Join("&", query)}";
        using HttpResponseMessage response = await GetOidcAsync(url, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(response, "sso_providers failed");
        }

        PublicFederationProvidersResponseWire wire =
            await ReadOidcJsonAsync<PublicFederationProvidersResponseWire>(response, cancellationToken).ConfigureAwait(false);
        var providers = (wire.Providers ?? Array.Empty<PublicFederationProviderWire>())
            .Select(p => new FederationProvider(
                p.Id, p.ProviderKind, p.DisplayName, p.Protocol, p.HasBundledMark, p.Inherited, p.ButtonIcon))
            .ToList();
        return new FederationProviderList(providers);
    }

    // ------------------------------------------------------------------
    // 11. SsoStartOauth2Async  (contract 1.38)
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /api/v1/auth/federation/oauth2/start</c> (CONTRACT.md &#167;12.1) — step 1
    /// of a login through a <b>plain-OAuth2</b> upstream (GitHub, Facebook,
    /// <c>generic_oauth2</c>).
    /// </summary>
    /// <remarks>
    /// <para>Call this, rather than <see cref="SsoStartAsync"/>, exactly when the provider's
    /// <c>protocol</c> is <see cref="FederationProtocols.OAuth2"/> (&#167;12.1 note 10). The
    /// server refuses a mismatch with <c>400</c> rather than accepting it silently, so a
    /// client that assumes OIDC fails on every GitHub button.</para>
    /// <para>PKCE is mandatory on this path and is generated and stored <b>server-side</b>;
    /// nothing about it appears in the request or the response (&#167;12.1 note 11).</para>
    /// <para>A <c>400</c> here can mean the <c>RedirectUri</c> is not on an origin the
    /// deployment accepts (&#167;12.1 rule 12a). &#167;2's <c>400</c> row makes that a
    /// <see cref="NetworkError"/> — this taxonomy's configuration/programming-error member,
    /// as distinct from the <see cref="AuthError"/> a <c>401</c> gets. It is not retried.</para>
    /// </remarks>
    /// <param name="params">The federation config, redirect URI and workspace context.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The authorize URL and single-use state to round-trip.</returns>
    public async Task<SsoStartResult> SsoStartOauth2Async(SsoStartOauth2Params @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);

        string? tenantIdStr = @params.TenantId?.ToString();
        string? tenantSlug = @params.TenantSlug;
        if (tenantIdStr is null && tenantSlug is null)
        {
            if (Guid.TryParse(_tenant.TenantId, out Guid selfTenantGuid))
            {
                tenantIdStr = selfTenantGuid.ToString();
            }
            else
            {
                tenantSlug = _tenant.TenantId;
            }
        }
        if (tenantIdStr is null && tenantSlug is null)
        {
            throw new AuthError("SsoStartOauth2Async requires tenant context: pass TenantId or TenantSlug, or construct the client with one (CONTRACT.md §5.1).");
        }

        string? orgIdStr = @params.OrgId?.ToString();
        string? orgSlug = @params.OrgSlug;
        if (orgIdStr is null && orgSlug is null)
        {
            if (_tenant.OrgId is Guid selfOrgId)
            {
                orgIdStr = selfOrgId.ToString();
            }
            else if (_tenant.OrgSlug is string selfOrgSlug)
            {
                orgSlug = selfOrgSlug;
            }
        }
        if (orgIdStr is null && orgSlug is null)
        {
            throw new AuthError("SsoStartOauth2Async requires organization context: pass OrgId or OrgSlug, or construct the client with OrgId/OrgSlug (CONTRACT.md §5.1).");
        }

        var body = new Dictionary<string, object?>
        {
            ["federation_config_id"] = @params.FederationConfigId,
            ["redirect_uri"] = @params.RedirectUri,
        };
        if (tenantIdStr is not null)
        {
            body["tenant_id"] = tenantIdStr;
        }
        else
        {
            body["tenant_slug"] = tenantSlug;
        }
        if (orgIdStr is not null)
        {
            body["org_id"] = orgIdStr;
        }
        else
        {
            body["org_slug"] = orgSlug;
        }
        // No PKCE anywhere in this body, and there must not be (§12.1 note 11).

        using HttpResponseMessage response = await PostJsonAsync(SsoOAuth2StartPath, body, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            // The federation endpoints document no error schema — the generic §2 status
            // mapping, never an OAuth2ErrorResponse parse (§12.3 rule 3 scopes that to
            // /oauth2/*).
            throw ErrorMapper.FromHttpResponse(response, "sso_start_oauth2 failed");
        }

        OAuth2StartResponseWire wire = await ReadOidcJsonAsync<OAuth2StartResponseWire>(response, cancellationToken).ConfigureAwait(false);
        return new SsoStartResult(wire.AuthorizeUrl, wire.State, wire.ExpiresInSecs);
    }

    // ------------------------------------------------------------------
    // 12. SsoCompleteOauth2Async  (contract 1.38)
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /api/v1/auth/federation/oauth2/callback</c> (CONTRACT.md &#167;12.1) — step
    /// 2 of a plain-OAuth2 login.
    /// </summary>
    /// <remarks>
    /// The session arrives as <c>Set-Cookie</c> (&#167;12.1 note 6) through the same
    /// &#167;4 cookie-jar path <see cref="SsoCompleteAsync"/> uses. &#167;12.4 does not
    /// apply: an <c>OAuth2</c> provider issues no ID token, so there is nothing to validate
    /// — the server authenticated the user by calling a configured userinfo endpoint with
    /// the access token it had just received (&#167;12.1 note 11).
    /// </remarks>
    /// <param name="params">The state and code the provider redirected back with.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The established session's identifiers and post-login destination.</returns>
    public async Task<SsoCompleteResult> SsoCompleteOauth2Async(SsoCompleteOauth2Params @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);

        var body = new Dictionary<string, object?> { ["state"] = @params.State, ["code"] = @params.Code };
        return await CompleteFederationSessionAsync(SsoOAuth2CompletePath, body, "sso_complete_oauth2", cancellationToken).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------
    // 13. SsoCompleteHandoffAsync  (contract 1.38)
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /api/v1/auth/federation/handoff</c> (CONTRACT.md &#167;12.1) — redeem the
    /// single-use code the SAML and Apple flows deliver.
    /// </summary>
    /// <remarks>
    /// <para>Those two protocols return <b>cross-site</b>, so the server cannot set
    /// <c>SameSite=Strict</c> session cookies on that response. It instead redirects the
    /// browser to the SPA's callback URL with a <see cref="FederationHandoff.QueryParam"/>
    /// query parameter; this call posts that code back same-origin, and <i>this</i> response
    /// is the one that carries the cookies (&#167;12.1 note 12).</para>
    /// <para><b>The code is gone either way.</b> It is valid for
    /// <see cref="FederationHandoff.CodeTtlSeconds"/> seconds and redeemable <b>once</b>.
    /// Redeem it from the same origin, immediately, and never retry a failed redemption: a
    /// <c>401</c> is terminal, and this method makes exactly one wire call so that it cannot
    /// become a retry by accident. Unknown, expired and already-redeemed all answer the same
    /// <c>401</c>, deliberately.</para>
    /// </remarks>
    /// <param name="params">The single-use handoff code.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The established session's identifiers and post-login destination.</returns>
    public async Task<SsoCompleteResult> SsoCompleteHandoffAsync(SsoCompleteHandoffParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);

        var body = new Dictionary<string, object?> { ["code"] = @params.Code };
        return await CompleteFederationSessionAsync(SsoHandoffPath, body, "sso_complete_handoff", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The shared body of the two session-establishing federation POSTs: one wire call, the
    /// &#167;2 status mapping on anything but <c>200</c>, and the &#167;4 cookie container
    /// absorbing the session because the request went through the shared
    /// <c>HttpClient</c>.
    /// </summary>
    private async Task<SsoCompleteResult> CompleteFederationSessionAsync(
        string path,
        Dictionary<string, object?> body,
        string operation,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await PostJsonAsync(path, body, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(response, $"{operation} failed");
        }

        SsoLoginSuccessResponseWire wire =
            await ReadOidcJsonAsync<SsoLoginSuccessResponseWire>(response, cancellationToken).ConfigureAwait(false);
        return new SsoCompleteResult(wire.UserId, wire.SessionId, wire.ExpiresIn, wire.RedirectUri);
    }

    /// <summary>GET a &#167;12 path on the shared transport, mapping a transport failure to
    /// <see cref="NetworkError"/> exactly as <c>PostJsonAsync</c> does.</summary>
    private async Task<HttpResponseMessage> GetOidcAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            return await _httpClient.GetAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw NetworkError.FromException(ex, $"GET {path} failed");
        }
        catch (OperationCanceledException ex) when (ex.CancellationToken != cancellationToken)
        {
            throw NetworkError.FromException(ex, $"GET {path} timed out");
        }
    }

    // ------------------------------------------------------------------
    // Shared §12 wire mechanics
    // ------------------------------------------------------------------

    private async Task<OidcConfiguration> ResolveOidcConfigurationAsync(OidcConfiguration? provided, CancellationToken cancellationToken) =>
        provided ?? await OidcDiscoverAsync(cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Resolves the tenant UUID for the mandatory <c>?tenant_id=</c> query parameter
    /// (CONTRACT.md &#167;12.3 rule 4): the explicit per-call argument when given, else this
    /// client's own tenant when it was constructed in UUID form, else the tenant UUID
    /// resolved from the current session's access-token claim (mirrors
    /// <c>DoHttpRefreshAsync</c>'s identical fallback for &#167;1 <c>RefreshAsync</c>).
    /// Neither source available is a CLIENT-SIDE <see cref="AuthError"/>, no wire call
    /// (same discipline as &#167;1.1 rule 3).
    /// </summary>
    private Guid ResolveOidcTenantId(Guid? explicitTenantId)
    {
        if (explicitTenantId is { } explicitGuid)
        {
            return explicitGuid;
        }
        if (Guid.TryParse(_tenant.TenantId, out Guid ownGuid))
        {
            return ownGuid;
        }

        string? access = ReadCookie(AccessCookieName);
        if (access is not null)
        {
            JsonElement? claims = DecodeUnverifiedClaims(access);
            if (claims is { } c && c.TryGetProperty("tenant_id", out JsonElement tEl) &&
                Guid.TryParse(tEl.GetString(), out Guid fromClaim))
            {
                return fromClaim;
            }
        }

        throw new AuthError(
            "this OIDC operation requires a tenant_id UUID for the /oauth2 query parameter: pass tenantId explicitly, construct the client with a tenant UUID, or call LoginAsync() first (CONTRACT.md §12.3 rule 4).");
    }

    private string RequireOidcClientId()
    {
        if (string.IsNullOrWhiteSpace(_oidcClientId))
        {
            throw new InvalidOperationException(
                "this OIDC operation requires AxiamClientOptions.OidcClientId to be configured (CONTRACT.md §12.1).");
        }
        return _oidcClientId;
    }

    private string RequireOidcClientSecret(string operationName)
    {
        if (_oidcClientSecret is not { } secret)
        {
            throw new AuthError(
                $"{operationName} requires confidential-client credentials: construct the client with AxiamClientOptions.OidcClientSecret (CONTRACT.md §12.1 note 4).");
        }
        return secret.Reveal();
    }

    /// <summary>Adds <c>client_secret</c> for a confidential client, and omits it entirely
    /// for a public client — &#167;12.1 forbids sending an empty/null value for an absent
    /// optional field.</summary>
    private void AppendOidcClientSecretIfConfigured(IDictionary<string, string> form)
    {
        if (_oidcClientSecret is { } secret)
        {
            form["client_secret"] = secret.Reveal();
        }
    }

    private static string AppendTenantIdQuery(string endpointUrl, Guid tenantId)
    {
        char separator = endpointUrl.Contains('?') ? '&' : '?';
        return $"{endpointUrl}{separator}tenant_id={tenantId}";
    }

    /// <summary>
    /// POSTs an <c>application/x-www-form-urlencoded</c> body (&#167;12.1 note 1) to
    /// <paramref name="endpointUrl"/> (an ABSOLUTE URL taken from the discovery document,
    /// never hardcoded relative to this client's own base URL — &#167;12.3 rule 6) through
    /// the SAME <c>_httpClient</c>/<c>AxiamHttpMessageHandler</c> choke point every other
    /// REST call in this SDK uses, so &#167;5's X-Tenant-ID header, &#167;3's CSRF echo, and
    /// the &#167;4 cookie jar / &#167;6 TLS transport all apply unconditionally, exactly as
    /// CONTRACT.md &#167;12.1 note 2 requires.
    /// </summary>
    private async Task<HttpResponseMessage> PostOAuth2FormAsync(string endpointUrl, IDictionary<string, string> form, Guid tenantId, CancellationToken cancellationToken)
    {
        string url = AppendTenantIdQuery(endpointUrl, tenantId);
        // NOT wrapped in `using` — HttpClient.SendAsync disposes neither the request nor
        // its content on its own, and callers/tests may still need to inspect the sent
        // request's content after this call returns (e.g. asserting the exact form fields
        // POSTed). The request/content are short-lived, GC-collectible objects; nothing
        // here needs deterministic disposal.
        var content = new FormUrlEncodedContent(form);
        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        try
        {
            return await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw NetworkError.FromException(ex, $"POST {endpointUrl} failed");
        }
        catch (OperationCanceledException ex) when (ex.CancellationToken != cancellationToken)
        {
            throw NetworkError.FromException(ex, $"POST {endpointUrl} timed out");
        }
    }

    private async Task<TokenResponseWire> PostTokenAsync(OidcConfiguration configuration, IDictionary<string, string> form, Guid tenantId, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await PostOAuth2FormAsync(configuration.TokenEndpoint, form, tenantId, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await MapOAuth2ErrorAsync(response, "oidc token request failed", cancellationToken).ConfigureAwait(false);
        }
        return await ReadOidcJsonAsync<TokenResponseWire>(response, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Maps a non-2xx response from an <c>/oauth2/*</c> endpoint (CONTRACT.md &#167;2,
    /// &#167;12.1, &#167;12.3 rule 3): a <c>400</c> (token endpoint) or <c>401</c>
    /// (introspect/revoke) carrying a well-formed <c>OAuth2ErrorResponse</c> body maps to
    /// <see cref="OAuthProtocolError"/>; anything else — including a 400/401 WITHOUT that
    /// body shape, and every other status — falls through to the existing &#167;2
    /// <see cref="ErrorMapper"/>, which does NOT special-case 400 as an
    /// <see cref="OAuthProtocolError"/> (the endpoint-qualified row only wins when the body
    /// actually matches).
    /// </summary>
    private static async Task<Exception> MapOAuth2ErrorAsync(HttpResponseMessage response, string context, CancellationToken cancellationToken)
    {
        if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized)
        {
            string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(body))
            {
                try
                {
                    OAuth2ErrorResponseWire? wire = JsonSerializer.Deserialize<OAuth2ErrorResponseWire>(body);
                    if (wire is { Error.Length: > 0 })
                    {
                        return new OAuthProtocolError(wire.Error, wire.ErrorDescription ?? string.Empty);
                    }
                }
                catch (JsonException)
                {
                    // Not a well-formed OAuth2ErrorResponse body — fall through to the
                    // generic §2 mapping below.
                }
            }
        }
        return ErrorMapper.FromHttpResponse(response, context);
    }

    private static async Task<T> ReadOidcJsonAsync<T>(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            T? value = await response.Content.ReadFromJsonAsync<T>(cancellationToken: cancellationToken).ConfigureAwait(false);
            if (value is null)
            {
                throw NetworkError.FromException(new InvalidOperationException("response body deserialized to null"), "failed to parse oidc response body");
            }
            return value;
        }
        catch (JsonException ex)
        {
            throw NetworkError.FromException(ex, "failed to parse oidc response body");
        }
    }

    /// <summary>
    /// Converts a <see cref="TokenResponseWire"/> into an <see cref="OidcTokenSet"/>,
    /// validating any <c>id_token</c> FIRST (&#167;12.4). Validation precedes construction,
    /// so a failure discards the whole set — the caller never sees the access or refresh
    /// token from a response whose ID token was rejected (&#167;12.4 rule 7).
    /// </summary>
    private async Task<OidcTokenSet> ToTokenSetAsync(TokenResponseWire wire, OidcConfiguration configuration, IdTokenExpectations expectations, CancellationToken cancellationToken)
    {
        IdTokenClaims? idClaims = null;
        if (!string.IsNullOrEmpty(wire.IdToken))
        {
            idClaims = await VerifyIdTokenAsync(wire.IdToken, configuration, expectations, cancellationToken).ConfigureAwait(false);
        }

        return new OidcTokenSet(
            Sensitive.Of(wire.AccessToken),
            wire.TokenType,
            wire.ExpiresIn,
            wire.Scope,
            wire.RefreshToken is not null ? Sensitive.Of(wire.RefreshToken) : null,
            wire.IdToken is not null ? Sensitive.Of(wire.IdToken) : null,
            idClaims);
    }

    /// <summary>Performs the full &#167;12.4 checklist: signature (via the shared
    /// <see cref="JwksVerifier"/>, reused not forked) then issuer/audience/time/nonce
    /// (rules 3-6), raising <see cref="AuthError"/> with the matching
    /// <see cref="AuthError.Reason"/> code on ANY failure — never a partial result
    /// (rule 7).</summary>
    private async Task<IdTokenClaims> VerifyIdTokenAsync(string idToken, OidcConfiguration configuration, IdTokenExpectations expectations, CancellationToken cancellationToken)
    {
        JwksVerifier verifier = GetOidcJwksVerifier(configuration.JwksUri);
        (JsonElement? payload, OidcSignatureFailure? failure) =
            await verifier.VerifyOidcIdTokenSignatureAsync(idToken, cancellationToken).ConfigureAwait(false);

        if (failure is { } f)
        {
            throw IdTokenValidator.SignatureFailureToAuthError(f);
        }

        return IdTokenValidator.Validate(payload!.Value, expectations, DateTimeOffset.UtcNow);
    }

    private JwksVerifier GetOidcJwksVerifier(string jwksUri)
    {
        lock (_oidcJwksLock)
        {
            if (_oidcJwksVerifiers.TryGetValue(jwksUri, out JwksVerifier? existing))
            {
                return existing;
            }
            var verifier = JwksVerifier.ForJwksUri(_httpClient, new Uri(jwksUri), _options.JwksCacheTtl);
            _oidcJwksVerifiers[jwksUri] = verifier;
            return verifier;
        }
    }
}
