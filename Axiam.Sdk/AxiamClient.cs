using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Rest;
using Axiam.Sdk.Srp;

namespace Axiam.Sdk;

/// <summary>
/// The AXIAM C# SDK's public REST entry point (CONTRACT.md &#167;1&#8211;&#167;6, &#167;9). The
/// public constructor is the ONLY construction path — <c>tenantId</c> is a required,
/// positional argument with no default and no overload that omits it (SC#1).
/// </summary>
/// <remarks>
/// Owns exactly ONE <see cref="RefreshGuard"/> and ONE <see cref="JwksVerifier"/> per
/// client — shared by the REST auth flow here and, by a later plan, the gRPC transport
/// (D-10's "one guard across REST + gRPC on one client" requirement). Internal
/// accessors (<see cref="RefreshGuard"/>, <see cref="JwksVerifier"/>,
/// <see cref="CurrentAccessToken"/>, <see cref="BaseUrl"/>, <see cref="CustomCaPem"/>,
/// <see cref="TransportHttpClient"/>) expose this seam without requiring the gRPC plan
/// (21-05) or the ASP.NET Core plan (21-06) to edit this file.
/// </remarks>
public sealed partial class AxiamClient : IDisposable
{
    private const string LoginPath = "/api/v1/auth/login";
    private const string MfaVerifyPath = "/api/v1/auth/mfa/verify";
    private const string SrpChallengePath = "/api/v1/auth/srp/challenge";
    private const string SrpVerifyPath = "/api/v1/auth/srp/verify";
    private const string RefreshPath = "/api/v1/auth/refresh";
    private const string LogoutPath = "/api/v1/auth/logout";

    private const string AccessCookieName = "axiam_access";
    private const string RefreshCookieName = "axiam_refresh";

    private readonly TenantContext _tenant;
    private readonly AxiamClientOptions _options;
    private readonly Uri _baseUrl;
    private readonly CookieContainer _cookieContainer;
    private readonly HttpClient _httpClient;
    private readonly AxiamHttpMessageHandler _authHandler;
    private readonly RefreshGuard _refreshGuard;
    private readonly JwksVerifier _jwksVerifier;
    private readonly AuthzRestClient _authz;
    private readonly TelemetryDispatcher _telemetry;
    private readonly DecisionMemo _decisionMemo;

    /// <summary>§18 shutdown flag, read on every operation.</summary>
    private int _disposed;

    /// <summary>
    /// The ONLY construction path (SC#1) — <paramref name="tenantId"/> is required and
    /// positional; there is no overload reachable from this class that permits omitting
    /// it (CONTRACT.md &#167;5: AXIAM is multi-tenant, there is no default tenant). A
    /// blank <paramref name="tenantId"/> is a runtime guard (via <see cref="TenantContext"/>)
    /// backing this compile-time guarantee.
    /// </summary>
    /// <param name="baseUrl">The AXIAM server's base URL.</param>
    /// <param name="tenantId">The tenant slug or tenant UUID (as a string) — required, no default.</param>
    /// <param name="options">
    /// Optional tuning (custom CA, org id/slug, timeouts, JWKS cache TTL). When
    /// omitted, sane defaults are used and <see cref="AxiamClientOptions.BaseUrl"/>/
    /// <see cref="AxiamClientOptions.TenantId"/> are populated from
    /// <paramref name="baseUrl"/>/<paramref name="tenantId"/>.
    /// </param>
    public AxiamClient(Uri baseUrl, string tenantId, AxiamClientOptions? options = null)
        : this(baseUrl, tenantId, options, transportOverride: null)
    {
    }

    /// <summary>
    /// Test-only seam (internal): builds an <see cref="AxiamClient"/> whose transport
    /// bottoms out at <paramref name="transportHandler"/> instead of a real
    /// <see cref="HttpClientHandler"/> — lets unit tests fully exercise the auth-flow
    /// methods and this class's <see cref="AxiamHttpMessageHandler"/> wiring against a
    /// fake server, without a real socket. Never used by any production code path; kept
    /// `internal` (not part of the public constructor surface counted by SC#1's
    /// reflection test).
    /// </summary>
    internal static AxiamClient CreateForTesting(Uri baseUrl, string tenantId, AxiamClientOptions? options, HttpMessageHandler transportHandler) =>
        new(baseUrl, tenantId, options, transportHandler);

    private AxiamClient(Uri baseUrl, string tenantId, AxiamClientOptions? options, HttpMessageHandler? transportOverride)
    {
        ArgumentNullException.ThrowIfNull(baseUrl);
        _tenant = new TenantContext(tenantId, options?.OrgId, options?.OrgSlug); // throws ArgumentException on blank tenantId (SC#1)

        _baseUrl = baseUrl;
        AxiamClientOptions baseOptions = options ?? new AxiamClientOptions { BaseUrl = baseUrl, TenantId = _tenant.TenantId };
        // ctor params are always the source of truth for BaseUrl/TenantId (SC#1),
        // regardless of what an optional options object happened to carry.
        _options = baseOptions with { BaseUrl = baseUrl, TenantId = _tenant.TenantId };

        // §6.1: the mTLS client identity (if configured) flows into BOTH transports — the
        // REST handler built here and the gRPC channel built later from the CustomCaPem/
        // ClientCertificatePem/ClientKeyPem seam below. A cert/key mismatch throws here,
        // at client construction, before any network activity.
        HttpMessageHandler primaryHandler = transportOverride
            ?? AxiamHttpClientFactory.CreatePrimaryHandler(_options.CustomCaPem, _options.ClientCertificatePem, _options.ClientKeyPem);
        _cookieContainer = (primaryHandler as HttpClientHandler)?.CookieContainer ?? new CookieContainer();

        _refreshGuard = new RefreshGuard(DoHttpRefreshAsync);

        _authHandler = new AxiamHttpMessageHandler(_cookieContainer, _baseUrl, _tenant.TenantId, _refreshGuard)
        {
            InnerHandler = primaryHandler,
        };

        _httpClient = new HttpClient(_authHandler)
        {
            BaseAddress = _baseUrl,
            Timeout = _options.RequestTimeout,
        };

        _jwksVerifier = new JwksVerifier(
            _httpClient,
            _baseUrl,
            _options.JwksCacheTtl,
            _options.ExpectedIssuer,
            _options.ExpectedAudience);
        // §17.1 rule 1: off unless the caller asked for it. §19: inert unless a
        // hook was installed.
        _telemetry = new TelemetryDispatcher(_options.TelemetryHook);
        _decisionMemo = new DecisionMemo(_options.DecisionMemoTtl);
        _authz = new AuthzRestClient(_httpClient, _options, _telemetry, _decisionMemo);

        // §19.2 rule 6: a clamped setting is reported, not swallowed. Emitted once,
        // here, because construction is the only moment an operator can act on it.
        RetryPolicy.ReportClamps(_options, _telemetry);
        _decisionMemo.ReportClamp(_options.DecisionMemoTtl, _telemetry);

        // CONTRACT.md §12 — initializes the OidcClientId/OidcClientSecret/discovery-TTL/
        // clock-skew fields declared in AxiamClient.Oidc.cs from this same _options
        // instance. Kept as a separate initializer (rather than inline field
        // initializers, which cannot see _options) so this constructor stays readable.
        InitializeOidcState();
    }

    /// <summary>REST authorization checks (CONTRACT.md &#167;1, FND-04): <c>CheckAccessAsync</c>/<c>CanAsync</c>/<c>BatchCheckAsync</c>.</summary>
    public AuthzRestClient Authz => _authz;

    // ------------------------------------------------------------------
    // Internal seam (gRPC plan 21-05 / ASP.NET Core plan 21-06) — not part
    // of the public API contract. These accessors let both later plans compose
    // against the SAME RefreshGuard/session this client's REST transport uses,
    // without either plan needing to modify this file.
    // ------------------------------------------------------------------

    internal RefreshGuard RefreshGuard => _refreshGuard;

    internal JwksVerifier JwksVerifier => _jwksVerifier;

    internal Uri BaseUrl => _baseUrl;

    internal byte[]? CustomCaPem => _options.CustomCaPem;

    internal byte[]? ClientCertificatePem => _options.ClientCertificatePem;

    internal byte[]? ClientKeyPem => _options.ClientKeyPem;

    internal HttpClient TransportHttpClient => _httpClient;

    internal string TenantId => _tenant.TenantId;

    /// <summary>Non-blocking read of the current access token from the shared cookie jar; <c>null</c> if never logged in.</summary>
    internal string? CurrentAccessToken => ReadCookie(AccessCookieName);

    /// <summary>
    /// Disposes the owned <see cref="HttpClient"/> (and its handler chain) and the
    /// <see cref="RefreshGuard"/>. Does not perform a server-side logout — call
    /// <see cref="LogoutAsync"/> first if an active session should be terminated
    /// server-side.
    /// </summary>
    public void Dispose()
    {
        // Idempotent (CONTRACT.md §18.1 rule 2): cleanup runs from error paths, and
        // an error path that itself throws hides the original failure. Interlocked
        // also means a concurrent double-dispose does the work once.
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _decisionMemo.Clear();
        _httpClient.Dispose();
        _refreshGuard.Dispose();
        DisposeOidcState();
    }

    /// <summary>
    /// Throws if <see cref="Dispose"/> has been called (CONTRACT.md §18.1 rule 4).
    /// </summary>
    /// <remarks>
    /// Use-after-dispose is an error, not a silent reconnect: a client that quietly
    /// rebuilt its transport would make <see cref="Dispose"/> meaningless and hide the
    /// lifecycle bug that caused the call. <see cref="ObjectDisposedException"/> is the
    /// .NET-idiomatic answer here, and unlike the other SDKs' NetworkError it is what a
    /// .NET caller's existing handlers already expect.
    /// </remarks>
    private void EnsureNotDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

    /// <summary>
    /// Drops memoized decisions (CONTRACT.md §17.1 rule 9).
    /// </summary>
    /// <remarks>
    /// Entries are keyed by subject rather than session, so a re-authentication as a
    /// <em>different</em> principal would otherwise inherit the previous one's decisions.
    /// </remarks>
    private void OnCredentialChange() => _decisionMemo.Clear();

    // ------------------------------------------------------------------
    // Auth methods (CONTRACT.md §1): LoginAsync / VerifyMfaAsync / RefreshAsync / LogoutAsync
    // All async-only + CancellationToken + ConfigureAwait(false) throughout (D-10).
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /api/v1/auth/login</c>. Returns a typed <see cref="LoginResult"/> — an
    /// MFA challenge (HTTP 202) is an expected outcome, not an exception: check
    /// <see cref="LoginResult.MfaRequired"/> before assuming a session was established.
    /// </summary>
    public async Task<LoginResult> LoginAsync(string email, string password, CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        OnCredentialChange();
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        var body = new Dictionary<string, object?>
        {
            ["username_or_email"] = email,
            ["password"] = password,
        };
        ApplyTenantAndOrgFields(body);

        using HttpResponseMessage response = await PostJsonAsync(LoginPath, body, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            return new LoginResult(false);
        }

        if (response.StatusCode == HttpStatusCode.Accepted)
        {
            JsonElement wire = await ReadJsonAsync(response, cancellationToken).ConfigureAwait(false);
            string challengeToken = wire.TryGetProperty("challenge_token", out JsonElement tokenEl)
                ? tokenEl.GetString() ?? string.Empty
                : string.Empty;
            return new LoginResult(true, Sensitive.Of(challengeToken));
        }

        throw ErrorMapper.FromHttpResponse(response, "login failed");
    }

    /// <summary>
    /// <c>POST /api/v1/auth/mfa/verify</c> (CONTRACT.md &#167;1), completing the
    /// two-phase flow started by <see cref="LoginAsync"/> when
    /// <see cref="LoginResult.MfaRequired"/> was <c>true</c>.
    /// </summary>
    public async Task<LoginResult> VerifyMfaAsync(Sensitive<string> challengeToken, string totpCode, CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        OnCredentialChange();
        ArgumentException.ThrowIfNullOrWhiteSpace(totpCode);

        var body = new Dictionary<string, object?>
        {
            ["challenge_token"] = challengeToken.Reveal(),
            ["totp_code"] = totpCode,
        };

        using HttpResponseMessage response = await PostJsonAsync(MfaVerifyPath, body, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(response, "MFA verification failed");
        }

        return new LoginResult(false);
    }

    /// <summary>
    /// <c>POST /api/v1/auth/refresh</c> (CONTRACT.md &#167;1), routed through the single-
    /// flight <see cref="RefreshGuard"/> (&#167;9). A 401 on the refresh call itself
    /// surfaces as <see cref="AuthError"/> with no retry (&#167;9.3).
    /// </summary>
    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        OnCredentialChange();
        if (ReadCookie(AccessCookieName) is null)
        {
            throw new AuthError("no access token to refresh — call LoginAsync() first");
        }

        await _refreshGuard.RefreshIfNeededAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /api/v1/auth/logout</c> (CONTRACT.md &#167;1) and clears in-memory
    /// session state. The session id comes from the current access token's <c>jti</c>
    /// claim (unverified decode — an operational hint only, never an authorization
    /// decision).
    /// </summary>
    public async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        OnCredentialChange();
        string? access = ReadCookie(AccessCookieName);
        if (access is null)
        {
            throw new AuthError("no active session to log out");
        }

        JsonElement? claims = DecodeUnverifiedClaims(access);
        string? jti = claims is { } c && c.TryGetProperty("jti", out JsonElement jtiEl) ? jtiEl.GetString() : null;
        if (jti is null)
        {
            throw new AuthError("access token has no session id (jti) to log out");
        }

        var body = new Dictionary<string, object?> { ["session_id"] = jti };
        using HttpResponseMessage response = await PostJsonAsync(LogoutPath, body, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw ErrorMapper.FromHttpResponse(response, "logout failed");
        }

        _authHandler.ResetCsrfToken();
    }

    // ------------------------------------------------------------------
    // RefreshGuard delegate — performs the actual POST /api/v1/auth/refresh call.
    // Runs through the SAME HttpClient/AxiamHttpMessageHandler chain as every other
    // request; the refresh path is exempted there from triggering a NESTED refresh
    // (AxiamHttpMessageHandler.RefreshPath), so this call can never recursively
    // re-enter RefreshIfNeededAsync on itself.
    // ------------------------------------------------------------------

    private async Task<TokenPair> DoHttpRefreshAsync(CancellationToken cancellationToken)
    {
        string? access = ReadCookie(AccessCookieName);
        if (access is null)
        {
            throw new AuthError("no access token to refresh — call LoginAsync() first");
        }

        JsonElement? claims = DecodeUnverifiedClaims(access);
        string? tenantIdClaim = claims is { } tc && tc.TryGetProperty("tenant_id", out JsonElement tEl) ? tEl.GetString() : null;
        if (tenantIdClaim is null || !Guid.TryParse(tenantIdClaim, out Guid tenantGuid))
        {
            throw new AuthError("tenant_id could not be resolved from the current access token; LoginAsync() must succeed before RefreshAsync()");
        }

        Guid? orgGuid = _tenant.OrgId;
        if (orgGuid is null && claims is { } oc && oc.TryGetProperty("org_id", out JsonElement oEl) &&
            Guid.TryParse(oEl.GetString(), out Guid parsedOrg))
        {
            orgGuid = parsedOrg;
        }

        if (orgGuid is null)
        {
            throw new AuthError("org_id could not be resolved; supply OrgId/OrgSlug via AxiamClientOptions or call LoginAsync() first");
        }

        var body = new Dictionary<string, object?>
        {
            ["tenant_id"] = tenantGuid.ToString(),
            ["org_id"] = orgGuid.Value.ToString(),
        };

        using HttpResponseMessage response = await PostJsonAsync(RefreshPath, body, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            // §9.3: no retry here — RefreshGuard propagates this exception as-is to
            // every waiter.
            throw ErrorMapper.FromHttpResponse(response, "token refresh failed");
        }

        string? newAccess = ReadCookie(AccessCookieName);
        if (newAccess is null)
        {
            throw new AuthError("refresh response did not set the axiam_access cookie");
        }
        string? newRefresh = ReadCookie(RefreshCookieName);

        JsonElement? newClaims = DecodeUnverifiedClaims(newAccess);
        DateTimeOffset expiresAt = newClaims is { } nc && nc.TryGetProperty("exp", out JsonElement expEl) && expEl.TryGetInt64(out long expSeconds)
            ? DateTimeOffset.FromUnixTimeSeconds(expSeconds)
            : DateTimeOffset.UtcNow;

        return new TokenPair(Sensitive.Of(newAccess), Sensitive.Of(newRefresh ?? string.Empty), expiresAt);
    }

    // ------------------------------------------------------------------
    // Shared HTTP mechanics
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Secure Remote Password (CONTRACT.md §23)
    // ------------------------------------------------------------------

    /// <summary>
    /// The group an SRP exchange opens in before the server has named one.
    /// </summary>
    /// <remarks>
    /// The challenge response names the group, but <c>A</c> has to be computed <i>before</i>
    /// that response exists — so the first attempt guesses, and the exchange restarts if the
    /// server names another. The guess is AXIAM's own default, so the restart is the
    /// exceptional path rather than the normal one.
    /// </remarks>
    private static readonly SrpGroup SrpOpeningGroup = SrpGroup.FromWire(SrpGroup.DefaultWireName);

    /// <summary>
    /// <c>POST /api/v1/auth/srp/challenge</c> followed by <c>/verify</c> — SRP-6a login
    /// (CONTRACT.md &#167;23).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A sibling of <see cref="LoginAsync"/>, not a replacement. It takes the same arguments
    /// and returns the same <see cref="LoginResult"/>, MFA branch included, so an application
    /// can switch a tenant to SRP without touching its own code (&#167;23.1).
    /// </para>
    /// <para>
    /// <b>What this does that <see cref="LoginAsync"/> does not.</b> The password never
    /// leaves this process. What crosses the wire is <c>A</c> and a proof, neither of which is
    /// useful without the account's verifier — so a TLS-terminating proxy, an accidentally
    /// verbose request log, or a heap dump on the server cannot capture a plaintext password,
    /// because the server never has one. It does <b>not</b> protect against a compromised
    /// AXIAM server.
    /// </para>
    /// <para>
    /// <b>Cost.</b> Runs the tenant's KDF: Argon2id at 19 MiB and t=2 by default, which is
    /// tens to hundreds of milliseconds of CPU plus that memory, per attempt. That cost is the
    /// point — it is what makes a leaked verifier no cheaper to attack than a leaked Argon2id
    /// hash. The KDF runs on the thread pool rather than the caller's thread.
    /// </para>
    /// </remarks>
    /// <param name="usernameOrEmail">The username or email to authenticate with.</param>
    /// <param name="password">
    /// The account password, as a <c>char[]</c> so the caller can clear it. This SDK clears
    /// every copy it makes but cannot clear the caller's array.
    /// </param>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <returns>The login outcome, exactly as <see cref="LoginAsync"/> returns it.</returns>
    /// <exception cref="NetworkError">
    /// The tenant has SRP disabled (the endpoint answers <c>404</c> — a property of the
    /// tenant, not of any user), or this SDK cannot perform the group or KDF the server named.
    /// Deliberately not <see cref="AuthError"/>: reporting a client capability gap as a
    /// credential failure would send a user off to reset a password that works.
    /// </exception>
    /// <exception cref="AuthError">
    /// A wrong password, or a server whose <c>M2</c> does not verify — in the latter case no
    /// session is returned and the response's cookies are discarded, because an endpoint that
    /// cannot prove it holds the verifier is not the server it claims to be.
    /// </exception>
    public async Task<LoginResult> LoginSrpAsync(
        string usernameOrEmail,
        char[] password,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        OnCredentialChange();
        ArgumentException.ThrowIfNullOrWhiteSpace(usernameOrEmail);
        ArgumentNullException.ThrowIfNull(password);

        SrpClientSession session = SrpClientSession.Begin(SrpOpeningGroup);
        JsonElement challenge = await SrpChallengeAsync(usernameOrEmail, session, cancellationToken)
            .ConfigureAwait(false);

        // The server named a group other than the one A was computed in, so the exchange has
        // to restart. Rare — the opening guess is AXIAM's own default — but a tenant on a
        // narrower group must work rather than fail.
        SrpGroup named = SrpGroup.FromWire(ReadString(challenge, "group"));
        if (named.WireName != session.Group.WireName)
        {
            session = SrpClientSession.Begin(named);
            challenge = await SrpChallengeAsync(usernameOrEmail, session, cancellationToken)
                .ConfigureAwait(false);
        }

        // challenge.identity, never usernameOrEmail (§23.3 rule 2).
        string identity = ReadString(challenge, "identity");
        string saltHex = ReadString(challenge, "salt");
        string serverPublicHex = ReadString(challenge, "b_pub");
        SrpKdfParams kdf = SrpKdfParams.FromChallenge(challenge);
        SrpClientSession pinned = session;

        // The KDF is deliberately CPU- and memory-bound; keeping it off the caller's thread is
        // the difference between a slow login and a stalled UI or request pipeline.
        SrpProofs proofs = await Task.Run(
            () =>
            {
                byte[] x = SrpMath.DeriveX(identity, password, SrpMath.FromHex(saltHex, "salt"), kdf);
                try
                {
                    return pinned.Finish(identity, saltHex, serverPublicHex, x);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(x);
                }
            },
            cancellationToken).ConfigureAwait(false);

        var body = new Dictionary<string, object?>
        {
            ["srp_session"] = ReadString(challenge, "srp_session"),
            ["client_proof"] = proofs.ClientProof,
        };

        using HttpResponseMessage response = await PostJsonAsync(SrpVerifyPath, body, cancellationToken)
            .ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.OK && response.StatusCode != HttpStatusCode.Accepted)
        {
            throw ErrorMapper.FromHttpResponse(response, "SRP login failed");
        }

        JsonElement wire = await ReadJsonAsync(response, cancellationToken).ConfigureAwait(false);
        string? serverProof = wire.TryGetProperty("server_proof", out JsonElement proofEl)
            ? proofEl.GetString()
            : null;

        // Mutual authentication (§23.3 rule 6), checked BEFORE anything from the response is
        // reported. A rogue server that cannot prove itself must not get the chance to collect
        // an MFA code either — and the cookies it set are discarded rather than left in the
        // container, since there is no trustworthy Set-Cookie to expire them.
        if (!SrpMath.VerifyServerProof(proofs.ExpectedServerProof, serverProof))
        {
            DiscardSessionCookies();
            throw new AuthError("SRP: the server failed to prove it holds this account's verifier");
        }

        if (response.StatusCode == HttpStatusCode.Accepted)
        {
            string challengeToken = wire.TryGetProperty("challenge_token", out JsonElement tokenEl)
                ? tokenEl.GetString() ?? string.Empty
                : string.Empty;
            return new LoginResult(true, Sensitive.Of(challengeToken));
        }

        return new LoginResult(false);
    }

    /// <summary>
    /// Opens an SRP exchange and returns the challenge that answers it.
    /// </summary>
    /// <remarks>
    /// Reuses <see cref="ApplyTenantAndOrgFields"/> so tenant/org resolution cannot drift
    /// between the two login paths, and sends no <c>password</c> field — it has no business on
    /// this request.
    /// </remarks>
    private async Task<JsonElement> SrpChallengeAsync(
        string usernameOrEmail,
        SrpClientSession session,
        CancellationToken cancellationToken)
    {
        var body = new Dictionary<string, object?>
        {
            ["username_or_email"] = usernameOrEmail,
            ["client_public"] = session.ClientPublic,
        };
        ApplyTenantAndOrgFields(body);

        using HttpResponseMessage response = await PostJsonAsync(SrpChallengePath, body, cancellationToken)
            .ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            // 404 is a property of the tenant ("SRP is off here"), not of the user, and not a
            // credential failure — so a caller can fall back to LoginAsync without mistaking
            // it for a bad password.
            throw NetworkError.FromMessage(
                "SRP: this tenant does not offer Secure Remote Password (srp_mode is disabled); " +
                "use LoginAsync instead");
        }

        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(response, "SRP challenge failed");
        }

        return await ReadJsonAsync(response, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes a verifier for <paramref name="password"/>, to send with any request that
    /// sets one: <c>POST /api/v1/users</c>, <c>/auth/password/change</c>,
    /// <c>/auth/reset/confirm</c> and <c>/admin/bootstrap</c> (&#167;23.3 rule 11).
    /// </summary>
    /// <remarks>
    /// The server cannot compute this — it never sees the plaintext — so it has to arrive with
    /// the request or not at all. The salt is 32 fresh bytes from the platform CSPRNG on every
    /// call. This performs no I/O; it is a method on the client only so it sits beside
    /// <see cref="LoginSrpAsync"/> in the API.
    /// </remarks>
    /// <param name="identity">
    /// The account's <b>username</b> — the canonical identity the challenge endpoint hands
    /// back. An email here produces a verifier no login can ever satisfy.
    /// </param>
    /// <param name="password">The plaintext being enrolled.</param>
    /// <param name="group">
    /// The tenant's group, from <c>GET /api/v1/auth/me</c> or the reset context;
    /// <c>null</c> means AXIAM's default.
    /// </param>
    /// <param name="parameters">
    /// The tenant's KDF and costs; any zero cost is filled in with AXIAM's default for that
    /// KDF. <c>null</c> means Argon2id at AXIAM's costs.
    /// </param>
    /// <returns>The <c>srp</c> object to attach to the request.</returns>
    /// <exception cref="NetworkError">The named KDF is not one this SDK implements.</exception>
    // The return type is fully qualified because §23.1 locks the METHOD name to
    // `SrpEnrollment`, which then shadows the same-named type for simple-name lookup inside
    // this class. Renaming either one to dodge that would break the contract's vocabulary or
    // the record's own meaning; qualifying costs one line and nothing else.
    public Axiam.Sdk.Srp.SrpEnrollment SrpEnrollment(
        string identity,
        char[] password,
        SrpGroup? group = null,
        SrpKdfParams? parameters = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identity);
        ArgumentNullException.ThrowIfNull(password);

        SrpGroup resolvedGroup = group ?? SrpOpeningGroup;
        SrpKdfParams resolved = (parameters ?? new SrpKdfParams(SrpKdfParams.Argon2id, 0)).WithDefaults();
        byte[] salt = SrpMath.GenerateSalt();
        byte[] x = SrpMath.DeriveX(identity, password, salt, resolved);
        try
        {
            return new Axiam.Sdk.Srp.SrpEnrollment(
                resolvedGroup.WireName,
                resolved.Kdf,
                resolved.MemoryKib,
                resolved.Iterations,
                resolved.Parallelism,
                SrpMath.ToHex(salt),
                SrpMath.ComputeVerifier(resolvedGroup, x));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(x);
        }
    }

    /// <summary>Whether this SDK build can perform SRP (&#167;23.1).</summary>
    /// <remarks>
    /// Always <c>true</c> on .NET: <see cref="System.Numerics.BigInteger"/> is in the base
    /// class library, PBKDF2-HMAC-SHA256 comes from <c>Rfc2898DeriveBytes</c>, and Argon2id
    /// from the BouncyCastle package this SDK already depends on. It exists because
    /// &#167;23.1 puts it in the locked method vocabulary for every SDK, and in PHP — which
    /// needs <c>ext-gmp</c> or <c>ext-bcmath</c> and is guaranteed neither — it genuinely
    /// answers <c>false</c>.
    /// </remarks>
    /// <returns><c>true</c>.</returns>
    public bool SrpAvailable() => true;

    /// <summary>
    /// Evicts the session cookies from the shared container.
    /// </summary>
    /// <remarks>
    /// The ordinary way a cookie leaves the container is the server expiring it, which is
    /// exactly what is unavailable to the one caller here: the <c>M2</c> mismatch in
    /// <see cref="LoginSrpAsync"/>, where the response came from an endpoint that has just
    /// failed to prove it holds the account's verifier. &#167;23.3 rule 6 requires the session
    /// discarded "including any cookies the response set", so the client evicts them itself
    /// rather than trusting the other side to.
    /// </remarks>
    private void DiscardSessionCookies()
    {
        foreach (Cookie cookie in _cookieContainer.GetCookies(_baseUrl))
        {
            cookie.Expired = true;
        }
    }

    private static string ReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) ? value.GetString() ?? string.Empty : string.Empty;

    private void ApplyTenantAndOrgFields(IDictionary<string, object?> body)
    {
        if (Guid.TryParse(_tenant.TenantId, out Guid tenantGuid))
        {
            body["tenant_id"] = tenantGuid.ToString();
        }
        else
        {
            body["tenant_slug"] = _tenant.TenantId;
        }

        if (_tenant.OrgId is Guid orgId)
        {
            body["org_id"] = orgId.ToString();
        }
        else if (_tenant.OrgSlug is string orgSlug)
        {
            body["org_slug"] = orgSlug;
        }
    }

    private async Task<HttpResponseMessage> PostJsonAsync(string path, object body, CancellationToken cancellationToken)
    {
        try
        {
            return await _httpClient.PostAsJsonAsync(path, body, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw NetworkError.FromException(ex, $"POST {path} failed");
        }
        catch (OperationCanceledException ex) when (ex.CancellationToken != cancellationToken)
        {
            // An OperationCanceledException/TaskCanceledException whose token is NOT the
            // caller's token comes from HttpClient.Timeout expiring (RequestTimeout) — a
            // transport-level timeout, which CONTRACT.md §2 maps to NetworkError. A genuine
            // caller-supplied cancellation (ex.CancellationToken == cancellationToken) is
            // deliberately NOT caught here and propagates as-is.
            throw NetworkError.FromException(ex, $"POST {path} timed out");
        }
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            using JsonDocument doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            return doc.RootElement.Clone();
        }
    }

    private string? ReadCookie(string name)
    {
        CookieCollection cookies = _cookieContainer.GetCookies(_baseUrl);
        foreach (Cookie cookie in cookies)
        {
            if (cookie.Name == name)
            {
                return cookie.Value;
            }
        }
        return null;
    }

    private static JsonElement? DecodeUnverifiedClaims(string jwt)
    {
        string[] parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            return null;
        }

        try
        {
            byte[] payloadBytes = Base64UrlDecode(parts[1]);
            using JsonDocument doc = JsonDocument.Parse(payloadBytes);
            return doc.RootElement.Clone();
        }
        catch
        {
            return null;
        }
    }

    private static byte[] Base64UrlDecode(string s)
    {
        string padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}
