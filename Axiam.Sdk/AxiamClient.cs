using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Rest;
using Axiam.Sdk.Opaque;

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
    private const string OpaqueRegisterStartPath = "/api/v1/auth/opaque/register/start";
    private const string OpaqueLoginStartPath = "/api/v1/auth/opaque/login/start";
    private const string OpaqueLoginFinishPath = "/api/v1/auth/opaque/login/finish";
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

        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            // CONTRACT.md §25.2 rule 1: a 403 carrying mfa_setup_required is an OUTCOME,
            // not a refusal. The tenant requires MFA, this account has none, and the
            // server handed back the token to finish with.
            //
            // Matched on the body's own discriminant rather than the status alone: a
            // genuine authorization refusal is also a 403, and only one of the two
            // carries a setup_token. A non-matching 403 falls through to ErrorMapper,
            // which re-reads the buffered content for its own action/resource_id peek.
            Sensitive<string>? setupToken = await ReadSetupTokenAsync(response, cancellationToken).ConfigureAwait(false);
            if (setupToken is not null)
            {
                return new LoginResult(false, null, true, setupToken);
            }
        }

        throw ErrorMapper.FromHttpResponse(response, "login failed");
    }

    /// <summary>
    /// The <c>setup_token</c> from a &#167;25.2 rule 1 <c>403</c>, or <c>null</c> when this
    /// 403 is an ordinary authorization refusal. Never throws: a non-JSON body is simply
    /// not this outcome.
    /// </summary>
    private static async Task<Sensitive<string>?> ReadSetupTokenAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            string raw = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(raw))
            {
                return null;
            }

            using JsonDocument doc = JsonDocument.Parse(raw);
            bool flagged = doc.RootElement.TryGetProperty("mfa_setup_required", out JsonElement flag) &&
                           flag.ValueKind == JsonValueKind.True;
            if (flagged &&
                doc.RootElement.TryGetProperty("setup_token", out JsonElement tokenEl) &&
                tokenEl.GetString() is { Length: > 0 } token)
            {
                return Sensitive.Of(token);
            }
        }
        catch (JsonException)
        {
            // Not this outcome.
        }
        return null;
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
    // OPAQUE, RFC 9807 (CONTRACT.md §23)
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /api/v1/auth/opaque/login/start</c> followed by <c>/finish</c> — OPAQUE login,
    /// RFC 9807 (CONTRACT.md &#167;23).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A sibling of <see cref="LoginAsync"/>, not a replacement. It takes the same arguments
    /// and returns the same <see cref="LoginResult"/>, MFA branch included, so an application
    /// can switch a tenant to OPAQUE without touching its own code.
    /// </para>
    /// <para>
    /// <b>What this does that <see cref="LoginAsync"/> does not.</b> The password never leaves
    /// this process. What crosses the wire is a blinded group element and a MAC, neither useful
    /// without the account's registration record <i>and</i> the tenant's OPRF seed — so a
    /// TLS-terminating proxy, an accidentally verbose request log, or a heap dump on the server
    /// cannot capture a plaintext password, because the server never has one. It also means a
    /// stolen record database is not offline-crackable on its own, which is the pre-computation
    /// resistance SRP could not offer. It does <b>not</b> protect against a compromised AXIAM
    /// server.
    /// </para>
    /// <para>
    /// <b>One round trip, and no server-proof step.</b> SRP had to guess a group before the
    /// server named one and restart the exchange if it guessed wrong; <c>KE1</c> does not
    /// depend on the key-stretching function. And where the old &#167;23.3 rule 6 had to
    /// mandate an <c>M2</c> check in capitals — because skipping it kept only half the protocol
    /// — RFC 9807's AKE authenticates the server during the handshake, so opening <c>KE2</c>
    /// <i>is</i> the proof that it holds the record. There is nothing left to skip.
    /// </para>
    /// <para>
    /// <b>Cost.</b> Runs the tenant's key-stretching function: Argon2id at 19 MiB and t=2 by
    /// default, which is tens to hundreds of milliseconds of CPU plus that memory, per attempt.
    /// That cost is the point — it is what makes a stolen record expensive to attack even by
    /// someone holding the OPRF seed. It runs on the thread pool rather than the caller's
    /// thread.
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
    /// The tenant has OPAQUE disabled (the endpoint answers <c>404</c> — a property of the
    /// tenant, not of any user), <c>libaxiam_opaque_ffi</c> is not installed, or the server
    /// names a key-stretching function this SDK cannot ask for. Deliberately not
    /// <see cref="AuthError"/>: reporting a configuration gap as a credential failure would
    /// send a user off to reset a password that works, and would stop a caller falling back to
    /// <see cref="LoginAsync"/>.
    /// </exception>
    /// <exception cref="AuthError">
    /// A wrong password, an account that does not exist, or a server that does not hold the
    /// record — indistinguishable by design. <b>Nothing is sent to <c>login/finish</c> in that
    /// case</b> (&#167;23.4 rule 7), and a caller must not retry over
    /// <see cref="LoginAsync"/>: that hands the plaintext to an endpoint that just failed to
    /// prove itself.
    /// </exception>
    public async Task<LoginResult> LoginOpaqueAsync(
        string usernameOrEmail,
        char[] password,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        OnCredentialChange();
        ArgumentException.ThrowIfNullOrWhiteSpace(usernameOrEmail);
        ArgumentNullException.ThrowIfNull(password);

        using LoginExchange exchange = OpaqueProtocol.StartLogin(password);

        var startBody = new Dictionary<string, object?>
        {
            ["username_or_email"] = usernameOrEmail,
            ["ke1"] = exchange.Ke1,
        };
        ApplyTenantAndOrgFields(startBody);

        JsonElement started = await OpaqueStartAsync(
            OpaqueLoginStartPath, startBody, "login/start", cancellationToken).ConfigureAwait(false);

        if (!started.TryGetProperty("ke2", out JsonElement ke2El) ||
            ke2El.ValueKind != JsonValueKind.String)
        {
            throw NetworkError.FromMessage("OPAQUE: login/start returned no `ke2`");
        }

        string ke2 = ke2El.GetString() ?? string.Empty;
        KsfParams ksf = KsfParams.FromWire(started);

        // The key-stretching function is deliberately CPU- and memory-bound; keeping it off the
        // caller's thread is the difference between a slow login and a stalled UI or request
        // pipeline.
        string ke3 = await Task.Run(
            () => exchange.Finish(password, ke2, ksf), cancellationToken).ConfigureAwait(false);

        var finishBody = new Dictionary<string, object?>
        {
            ["opaque_session"] = ReadString(started, "opaque_session"),
            ["ke3"] = ke3,
        };

        using HttpResponseMessage response =
            await PostJsonAsync(OpaqueLoginFinishPath, finishBody, cancellationToken)
                .ConfigureAwait(false);

        if (response.StatusCode != HttpStatusCode.OK && response.StatusCode != HttpStatusCode.Accepted)
        {
            throw ErrorMapper.FromHttpResponse(response, "OPAQUE login/finish failed");
        }

        if (response.StatusCode == HttpStatusCode.Accepted)
        {
            JsonElement wire = await ReadJsonAsync(response, cancellationToken).ConfigureAwait(false);
            return new LoginResult(true, Sensitive.Of(ReadString(wire, "challenge_token")));
        }

        return new LoginResult(false);
    }

    /// <summary>
    /// Builds a registration record for <paramref name="password"/>, to send with any request
    /// that sets one: <c>POST /api/v1/users</c>, <c>/auth/password/change</c>,
    /// <c>/auth/reset/confirm</c> and <c>/admin/bootstrap</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The server cannot build this — it never sees the plaintext — so it has to arrive with
    /// the request or not at all.
    /// </para>
    /// <para>
    /// Unlike the <c>SrpEnrollment</c> it replaces this performs network I/O: one
    /// <c>register/start</c> round trip. OPAQUE's envelope is sealed under the server's
    /// oblivious PRF, so there is no offline computation that produces a valid record.
    /// </para>
    /// <para>
    /// Note the parameters that are gone. There is no <c>identity</c>: the SRP version required
    /// the account's canonical <b>username</b>, and an email there produced a verifier no login
    /// could ever satisfy, whereas a record binds to a credential identifier the server
    /// chooses. And there is no group or KDF, because those come from the
    /// <c>register/start</c> response — a caller cannot pick a cost the server will not honour.
    /// </para>
    /// </remarks>
    /// <param name="password">The plaintext being enrolled.</param>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <returns>The <c>opaque</c> object to attach to the request.</returns>
    /// <exception cref="NetworkError">
    /// The tenant has OPAQUE disabled, <c>libaxiam_opaque_ffi</c> is not installed, or the
    /// server names a key-stretching function this SDK cannot ask for.
    /// </exception>
    public async Task<OpaqueEnrollment> OpaqueEnrollmentAsync(
        char[] password,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        ArgumentNullException.ThrowIfNull(password);

        using RegistrationExchange exchange = OpaqueProtocol.StartRegistration(password);

        var body = new Dictionary<string, object?>
        {
            ["registration_request"] = exchange.Request,
        };
        ApplyTenantAndOrgFields(body);

        JsonElement started = await OpaqueStartAsync(
            OpaqueRegisterStartPath, body, "register/start", cancellationToken).ConfigureAwait(false);

        string registrationResponse = ReadString(started, "registration_response");
        KsfParams ksf = KsfParams.FromWire(started);
        string record = await Task.Run(
            () => exchange.Finish(password, registrationResponse, ksf), cancellationToken)
            .ConfigureAwait(false);

        return new OpaqueEnrollment(ReadString(started, "opaque_session"), record);
    }

    /// <summary>Whether this installation can perform OPAQUE (&#167;23.2).</summary>
    /// <remarks>
    /// Genuinely able to answer <c>false</c>, unlike the <c>SrpAvailable</c> it replaces —
    /// which was hard-coded <c>true</c> on .NET because <c>BigInteger</c> and BouncyCastle are
    /// always there. The protocol now comes from <c>libaxiam_opaque_ffi</c>, a per-platform
    /// release asset rather than a NuGet package. Ask before a login rather than discovering
    /// the gap mid-exchange.
    /// </remarks>
    /// <returns><c>true</c> when the library is present and says it can.</returns>
    public bool OpaqueAvailable() => OpaqueProtocol.Available();

    /// <summary>
    /// Sends one <c>/start</c> request and returns the parsed response.
    /// </summary>
    /// <remarks>
    /// Shared by both OPAQUE paths so the meaning of a failure cannot drift between them, and
    /// reusing <see cref="ApplyTenantAndOrgFields"/> keeps tenant/org resolution identical to
    /// the password login. A <c>404</c> is a property of the tenant ("OPAQUE is off here"), not
    /// of the user and not of the credentials — so it is a <see cref="NetworkError"/> a caller
    /// can fall back on, never an <see cref="AuthError"/> that would be shown as "invalid
    /// password".
    /// </remarks>
    private async Task<JsonElement> OpaqueStartAsync(
        string path,
        Dictionary<string, object?> body,
        string what,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await PostJsonAsync(path, body, cancellationToken)
            .ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            throw NetworkError.FromMessage(
                "OPAQUE: this tenant does not offer OPAQUE (opaque_mode is disabled); " +
                "use LoginAsync instead");
        }

        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(response, $"OPAQUE {what} failed");
        }

        return await ReadJsonAsync(response, cancellationToken).ConfigureAwait(false);
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
