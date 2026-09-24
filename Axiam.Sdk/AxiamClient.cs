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

    /// <summary>
    /// CONTRACT.md &#167;5.2 rule 1: the acting-tenant header, distinct from the
    /// unconditional <c>X-Tenant-Id</c> (&#167;5 rule 2) — "not the acting-tenant header",
    /// as the contract's own callout puts it. REST-only, and sent only when a handle has
    /// an acting tenant set.
    /// </summary>
    internal const string ActingTenantHeaderName = "X-Axiam-Tenant";

    private readonly TenantContext _tenant;
    private readonly AxiamClientOptions _options;
    private readonly Uri _baseUrl;
    private readonly CookieContainer _cookieContainer;
    private readonly HttpClient _httpClient;
    private readonly AxiamHttpMessageHandler _authHandler;
    private readonly RefreshGuard _refreshGuard;
    private readonly JwksVerifier _jwksVerifier;

    /// <summary>
    /// The transport backing <c>_anonymousHttpClient</c> — the SAME <c>primaryHandler</c>
    /// this client would otherwise wrap in <see cref="AxiamHttpMessageHandler"/> in
    /// production, or the test double <c>CreateForTesting</c> was given. Kept as its own
    /// field (rather than only living inside <c>_anonymousHttpClient</c>) so
    /// <c>AdoptAnonymousCookies</c> can pattern-match it back to a real
    /// <see cref="HttpClientHandler"/> and read the cookies it captured.
    /// </summary>
    private readonly HttpMessageHandler _anonymousPrimaryHandler;

    /// <summary>
    /// CONTRACT.md &#167;24.1 (contract 1.45): the transport for
    /// <c>WebauthnSetupRegisterStartAsync</c>/<c>WebauthnSetupRegisterFinishAsync</c> —
    /// the two calls that take a setup token as their sole credential and MUST NOT carry
    /// this client's own session credential. Points at the same underlying handler as
    /// <see cref="_httpClient"/> (so it shares &#167;6/&#167;6.1's TLS policy and, in tests,
    /// the same fake transport) but is never wrapped in <see cref="AxiamHttpMessageHandler"/>
    /// and — critically, in production — owns its OWN, permanently empty
    /// <see cref="CookieContainer"/> rather than <see cref="_cookieContainer"/>: there is
    /// nothing in it for a real transport to send, by construction, rather than by a
    /// conditional someone could get wrong later.
    /// </summary>
    private readonly HttpClient _anonymousHttpClient;

    /// <summary>
    /// CONTRACT.md &#167;5.2.2 — the tenant the signed-in principal's record <i>lives</i> in,
    /// as reported by the login response.
    /// </summary>
    /// <remarks>
    /// Distinct from the tenant being acted on, which is <see cref="_tenant"/>'s: the two
    /// diverge for an organization-level principal that has selected another one. Read by
    /// <see cref="OpaqueEnrollmentForSelfAsync"/>, which must seal a &#167;23 record against the
    /// account's own tenant rather than whichever one this client is currently pointed at.
    /// Held as a string because a client is shared and this must be visible across threads:
    /// <c>volatile</c> cannot be applied to <c>Guid?</c>, which is a struct wider than a
    /// reference, and a torn read of one would be worse than the round trip through text.
    /// <c>null</c> until a login completes.
    /// </remarks>
    private volatile string? _principalTenantId;
    private readonly AuthzRestClient _authz;
    private readonly TelemetryDispatcher _telemetry;
    private readonly DecisionMemo _decisionMemo;

    /// <summary>
    /// CONTRACT.md &#167;5.2 — what this client knows about the signed-in principal's
    /// reach, shared across every <see cref="ActingTenant"/> handle over one session so a
    /// tenant switch made on one handle is gated on the SAME login result the others
    /// observed, and so a credential change on any of them clears it for all of them.
    /// </summary>
    /// <remarks>
    /// A separate reference-type holder (rather than fields directly on
    /// <see cref="AxiamClient"/>) is what makes that sharing possible: a handle built by
    /// <see cref="ActingTenant"/> copies every other field of the client it was built
    /// from, but needs this ONE piece of state to keep being written to and read from the
    /// same place the original handle uses, not a snapshot frozen at the moment the new
    /// handle was created.
    /// </remarks>
    private sealed class SharedSession
    {
        /// <summary>
        /// <c>LoginUserInfo.organization_level</c> from the last completed login this
        /// session observed, or <c>null</c> when no login result is held (a service
        /// account from client credentials or the device login; an injected token; or a
        /// session-completing path that reports no user object at all — WebAuthn, SSO).
        /// &#167;5.2 rule 1: <c>null</c> means nothing to gate on, so
        /// <see cref="AxiamClient.ActingTenant"/> sends the header and lets the server's
        /// <c>403</c> answer.
        /// </summary>
        internal volatile object? OrganizationLevelBox; // boxed bool?, for atomic volatile read/write

        /// <summary>
        /// <c>LoginUserInfo.reachable_tenant_ids</c> from the last completed login, or
        /// <c>null</c> for "unrestricted" (&#167;5.2.3 rule 4) — including "no login result
        /// held", which is the same absence of a restriction to check.
        /// </summary>
        internal volatile IReadOnlyList<Guid>? ReachableTenantIds;

        internal bool? OrganizationLevel
        {
            get => (bool?)OrganizationLevelBox;
            set => OrganizationLevelBox = value;
        }

        internal void Reset()
        {
            OrganizationLevelBox = null;
            ReachableTenantIds = null;
        }
    }

    private readonly SharedSession _session;

    /// <summary>
    /// CONTRACT.md &#167;5.2 rule 1 — the tenant THIS handle acts on, distinct from the
    /// tenant it signed in as. <c>null</c> for a handle with no acting tenant (the
    /// ordinary case, and every client before contract 1.51).
    /// </summary>
    private readonly Guid? _actingTenant;

    /// <summary>
    /// <c>true</c> for the handle the public constructor built — the one that owns the
    /// transport, the cookie jar, the refresh guard and the JWKS verifier, and tears them
    /// down on <see cref="Dispose"/>. <c>false</c> for a handle <see cref="ActingTenant"/>
    /// or <see cref="ClearActingTenant"/> built over an existing one: it owns only its own
    /// per-handle <see cref="HttpClient"/> wrapper (built with <c>disposeHandler: false</c>,
    /// so disposing it never tears down the shared transport) and its own OIDC discovery
    /// state, both of which its own <see cref="Dispose"/> always cleans up regardless of
    /// this flag.
    /// </summary>
    private readonly bool _ownsResources;

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

        // CONTRACT.md §24.1 (contract 1.45): the setup/register/* pair MUST NOT carry this
        // client's own session credential. In production that means an entirely separate
        // HttpClientHandler with its own, permanently empty CookieContainer — reusing
        // `primaryHandler` here would reuse `_cookieContainer` too, since a real
        // HttpClientHandler's cookie jar IS the CookieContainer object, not something the
        // outer AxiamHttpMessageHandler can suppress per request. Against
        // `CreateForTesting`'s fake transport (not an HttpClientHandler, so it manages no
        // cookies of its own either way) the same override handler is reused directly so
        // the WebAuthn setup tests share the suite's mounted routes.
        _anonymousPrimaryHandler = transportOverride
            ?? AxiamHttpClientFactory.CreatePrimaryHandler(_options.CustomCaPem, _options.ClientCertificatePem, _options.ClientKeyPem);
        _anonymousHttpClient = new HttpClient(_anonymousPrimaryHandler, disposeHandler: transportOverride is null)
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

        // §5.2 rule 1, construction-time form. Precedes any login, so it cannot be
        // gated against organization_level/reachable_tenant_ids the way the on-client
        // ActingTenant()/ClearActingTenant() forms below are — a non-organization-level
        // principal meets the server's own 403 on its first request instead.
        _session = new SharedSession();
        _actingTenant = _options.ActingTenant;
        _ownsResources = true;
        if (_actingTenant is { } configuredActingTenant)
        {
            _httpClient.DefaultRequestHeaders.TryAddWithoutValidation(
                ActingTenantHeaderName, configuredActingTenant.ToString());
        }

        // §17 addendum ("For C-12" item 2): ONE memo for the whole session, SHARED by
        // every ActingTenant()/ClearActingTenant() handle built over this one — the key
        // itself carries the acting tenant (DecisionMemo.Key's fifth component), which is
        // what lets sharing be safe rather than merely convenient: login/logout/refresh
        // on ANY handle clears it for ALL of them (§17.1 rule 9), and a memoized answer
        // for one tenant is still never returned for another.
        _decisionMemo = new DecisionMemo(_options.DecisionMemoTtl);
        _authz = new AuthzRestClient(_httpClient, _options, _telemetry, _decisionMemo, actingTenant: _actingTenant);

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

    /// <summary>
    /// A new handle over the SAME session that acts on <paramref name="tenantId"/>
    /// instead of whatever this handle acts on (CONTRACT.md &#167;5.2 rule 1, the
    /// on-client form). Every <c>/api/v1</c> REST request the returned handle makes
    /// carries <c>X-Axiam-Tenant: {tenantId}</c>, in addition to — never instead of —
    /// the unconditional <c>X-Tenant-Id</c> (&#167;5 rule 2). gRPC is unaffected: this is
    /// REST-only, and a gRPC call always acts on whatever tenant the bearer token names.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Returns a NEW <see cref="AxiamClient"/> rather than mutating this one. The two
    /// share the same cookie jar, refresh guard and JWKS verifier — a refresh performed
    /// through either handle updates the session both read from — but each has its own
    /// <see cref="HttpClient"/> wrapper (so its own default headers) and its own &#167;17
    /// decision memo, so a tenant switch decided on one handle can never race a request
    /// already in flight on another, and a memoized answer for one tenant can never be
    /// returned for another (&#167;17 addendum). Dispose the returned handle, or not — it
    /// owns nothing the original handle's own <see cref="Dispose"/> does not already tear
    /// down; disposing it early only releases its own lightweight wrapper early.
    /// </para>
    /// <para>
    /// <b>Gating (&#167;5.2 rule 1's "gate it on what the SDK knows").</b> Once a
    /// password/MFA/OPAQUE login has reported the principal's reach, this method refuses
    /// client-side with <see cref="AuthzError"/> — zero wire calls — unless
    /// <c>organization_level</c> was <c>true</c>, and refuses a tenant outside
    /// <c>reachable_tenant_ids</c> when that field was present (&#167;5.2.3 rule 4). A
    /// handle that holds no login result (a service account from client credentials or
    /// the device login; an injected token) or whose last session-completing call
    /// reported no user object at all (WebAuthn, SSO) has nothing to gate on: it sends
    /// the header as asked and lets the server's <c>403</c> answer.
    /// </para>
    /// </remarks>
    /// <param name="tenantId">The tenant to act on.</param>
    /// <returns>A new handle over this client's session, acting on <paramref name="tenantId"/>.</returns>
    /// <exception cref="AuthzError">
    /// A login result is held and reports <c>organization_level: false</c>, or reports
    /// <c>reachable_tenant_ids</c> that does not contain <paramref name="tenantId"/>.
    /// Raised client-side, before any wire call.
    /// </exception>
    public AxiamClient ActingTenant(Guid tenantId)
    {
        EnsureNotDisposed();
        GateActingTenant(tenantId);
        return new AxiamClient(this, tenantId);
    }

    /// <summary>
    /// A new handle over the SAME session that acts on no particular tenant — the
    /// converse of <see cref="ActingTenant"/> (CONTRACT.md &#167;5.2 rule 1's "a way to
    /// clear it"). The returned handle sends no <c>X-Axiam-Tenant</c> header at all, byte
    /// for byte what a handle built with none ever sent.
    /// </summary>
    /// <returns>A new handle over this client's session, acting on no particular tenant.</returns>
    public AxiamClient ClearActingTenant()
    {
        EnsureNotDisposed();
        return new AxiamClient(this, actingTenant: null);
    }

    /// <summary>Client-side half of &#167;5.2 rule 1's gating — see <see cref="ActingTenant"/>.</summary>
    private void GateActingTenant(Guid tenantId)
    {
        bool? organizationLevel = _session.OrganizationLevel;
        if (organizationLevel is false)
        {
            throw new AuthzError(
                "acting_tenant is meaningful only for an organization-level principal "
                + "(CONTRACT.md §5.2 rule 1); the last login result reported organization_level: false");
        }

        if (_session.ReachableTenantIds is { } reachable && !reachable.Contains(tenantId))
        {
            throw new AuthzError(
                $"tenant {tenantId} is outside this principal's reachable_tenant_ids (CONTRACT.md §5.2.3 rule 4)");
        }
        // organizationLevel is null (no login result held / a session-completing path
        // that reported no user object) or true: nothing more to gate on client-side —
        // send the header and let the server's 403 answer (§5.2 rule 1).
    }

    /// <summary>
    /// Builds a handle sharing <paramref name="source"/>'s session (CONTRACT.md &#167;5.2
    /// rule 1's on-client form) but acting on <paramref name="actingTenant"/> instead.
    /// </summary>
    private AxiamClient(AxiamClient source, Guid? actingTenant)
    {
        _tenant = source._tenant;
        _options = source._options;
        _baseUrl = source._baseUrl;
        _cookieContainer = source._cookieContainer;
        _authHandler = source._authHandler;
        _anonymousPrimaryHandler = source._anonymousPrimaryHandler;
        _anonymousHttpClient = source._anonymousHttpClient;
        _refreshGuard = source._refreshGuard;
        _jwksVerifier = source._jwksVerifier;
        _telemetry = source._telemetry;
        _session = source._session; // shared: one login result, one gate, for every handle
        _actingTenant = actingTenant;
        _ownsResources = false;

        // A NEW HttpClient wrapper over the SAME shared _authHandler
        // (disposeHandler: false, so disposing this handle's wrapper never tears down
        // the shared transport/cookie jar) — the standard .NET pattern for giving
        // several logical clients their own default headers over one physical
        // connection pool. This is what makes the acting-tenant header per-HANDLE
        // rather than per-transport: every request this specific AxiamClient object
        // sends — through PostJsonAsync below, through AuthzRestClient, through
        // ManagementApi/ManagementTransport, through the Account/Webauthn partials —
        // goes through THIS HttpClient instance and picks up its DefaultRequestHeaders
        // automatically, with no per-call-site change anywhere else in this class or
        // its partials.
        _httpClient = new HttpClient(_authHandler, disposeHandler: false)
        {
            BaseAddress = _baseUrl,
            Timeout = _options.RequestTimeout,
        };
        if (actingTenant is { } tenantId)
        {
            _httpClient.DefaultRequestHeaders.TryAddWithoutValidation(
                ActingTenantHeaderName, tenantId.ToString());
        }

        // §17 addendum: the SAME memo instance as source — see the constructor comment
        // above for why sharing it is safe (the key carries the acting tenant) and
        // required (login/logout/refresh on any handle must clear it for every handle).
        _decisionMemo = source._decisionMemo;
        _authz = new AuthzRestClient(_httpClient, _options, _telemetry, _decisionMemo, actingTenant: actingTenant);

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
    /// Disposes this handle's own <see cref="HttpClient"/> wrapper and OIDC discovery
    /// state, and — for the handle the public constructor built — the shared transport's
    /// handler chain, the <see cref="RefreshGuard"/> and the &#167;17 memo. Does not perform
    /// a server-side logout — call <see cref="LogoutAsync"/> first if an active session
    /// should be terminated server-side.
    /// </summary>
    /// <remarks>
    /// A handle built by <see cref="ActingTenant"/>/<see cref="ClearActingTenant"/> owns
    /// only its own lightweight wrapper: disposing it never tears down the session other
    /// handles over the same client are still using, and never clears the &#167;17 memo
    /// those handles' decisions are cached in. Disposing the ORIGINAL handle does both —
    /// it ends the whole session, so every handle built over it becomes unusable anyway
    /// (their shared <see cref="HttpClient"/> chain, cookie jar and refresh guard are
    /// gone), and clearing the memo at that point is correct rather than premature.
    /// </remarks>
    public void Dispose()
    {
        // Idempotent (CONTRACT.md §18.1 rule 2): cleanup runs from error paths, and
        // an error path that itself throws hides the original failure. Interlocked
        // also means a concurrent double-dispose does the work once. Per-INSTANCE (not
        // shared): each handle tracks its own disposed state, so disposing one handle
        // never marks a sibling handle disposed.
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        // Own per-handle state, always: this handle's HttpClient wrapper (built with
        // disposeHandler: true for the owning handle, false for a derived one — see the
        // constructors) and its own OIDC discovery semaphores/cache.
        _httpClient.Dispose();
        DisposeOidcState();

        if (_ownsResources)
        {
            _decisionMemo.Clear();
            _anonymousHttpClient.Dispose();
            _refreshGuard.Dispose();
        }
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
    /// Drops memoized decisions (CONTRACT.md §17.1 rule 9) and resets the &#167;5.2
    /// acting-tenant gate to "unknown".
    /// </summary>
    /// <remarks>
    /// Entries are keyed by subject rather than session, so a re-authentication as a
    /// <em>different</em> principal would otherwise inherit the previous one's decisions.
    /// The &#167;5.2 reset is the same reasoning applied to <see cref="ActingTenant"/>'s
    /// gate: a session-completing call that reports no user object at all (WebAuthn, SSO)
    /// must not leave a STALE <c>organization_level</c>/<c>reachable_tenant_ids</c> from
    /// whatever the previous credential reported (&#167;5.2 rule 1's "For C-12" item 5) —
    /// this is called at the start of every credential-changing method in this class and
    /// its partials (login, MFA verify, OPAQUE login, refresh, logout, password change,
    /// WebAuthn authentication), so "no user object reported" and "no call happened yet"
    /// converge on the same "unknown" state rather than on a leftover value.
    /// </remarks>
    private void OnCredentialChange()
    {
        _decisionMemo.Clear();
        _session.Reset();
    }

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
            (bool organizationLevel, PrincipalScope? scope) =
                await ReadLoginScopeAsync(response, cancellationToken).ConfigureAwait(false);
            return new LoginResult(false, OrganizationLevel: organizationLevel, Scope: scope);
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

        (bool organizationLevel, PrincipalScope? scope) =
            await ReadLoginScopeAsync(response, cancellationToken).ConfigureAwait(false);
        return new LoginResult(false, OrganizationLevel: organizationLevel, Scope: scope);
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
    /// <para>
    /// <b>When the credential check fails</b> (&#167;23.4 rule 7). Nothing is sent to
    /// <c>login/finish</c> — a <c>KE2</c> that does not open <i>is</i> the authentication
    /// result — and what happens next depends only on the <c>mode</c> the <c>login/start</c>
    /// response carried, the tenant's <c>opaque_mode</c>:
    /// </para>
    /// <para>
    /// Under <c>optional</c> this method retries over <see cref="LoginAsync"/> with the same
    /// credentials before reporting anything, and returns that call's outcome. That is not
    /// belt-and-braces: <c>optional</c> is the mid-migration state, every account starts with no
    /// registration record and acquires one only when its password is next set, so treating the
    /// failed exchange as final would lock out every user of the tenant.
    /// </para>
    /// <para>
    /// Under <c>required</c> — and under an absent <c>mode</c>, which is a server older than the
    /// field, and any value this SDK does not recognise — the failure is an
    /// <see cref="AuthError"/>, the exchange is over, and nothing is retried.
    /// </para>
    /// <para>
    /// <c>mode</c> is <b>not</b> downgrade protection and this SDK does not present it as such:
    /// a hostile server that wanted the plaintext could answer <c>404</c> and get a fallback
    /// whatever it puts there. What closes that is the server refusing <c>/auth/login</c> under
    /// <c>required</c>, before it examines any credential.
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
    /// case</b> (&#167;23.4 rule 7), and under a <c>required</c> tenant the exchange is over:
    /// a caller must not retry over <see cref="LoginAsync"/>, which would hand the plaintext to
    /// an endpoint that just failed to prove itself and answers <c>403 opaque_required</c>
    /// anyway. Under an <c>optional</c> tenant this method has already retried for you — see
    /// the remarks — so an <see cref="AuthError"/> from here is the <i>password</i> login's
    /// verdict.
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

        // The tenant's opaque_mode, read BEFORE the credential check because it is the only
        // thing that decides what a failed check means (§23.4 rule 7). Absent = a server older
        // than contract 1.29, which fails closed.
        string? mode = OpaqueMode.FromWire(started);

        string ke3;
        try
        {
            // The key-stretching function is deliberately CPU- and memory-bound; keeping it off
            // the caller's thread is the difference between a slow login and a stalled UI or
            // request pipeline.
            ke3 = await Task.Run(
                () => exchange.Finish(password, ke2, ksf), cancellationToken).ConfigureAwait(false);
        }
        catch (AuthError) when (OpaqueMode.AllowsPasswordFallback(mode) && !IsBlank(password))
        {
            // §23.4 rule 7, the `optional` clause. Under `optional` an account with no
            // registration record is the ordinary case rather than an error — every account has
            // none the moment an operator enables OPAQUE, and acquires one only as it next sets
            // a password — and a wrong password, an unknown identity and a missing record are
            // indistinguishable here by design. Reporting this as final would lock out every
            // user of a tenant mid-migration, which is the state `optional` exists to serve.
            //
            // Nothing has been sent to login/finish and nothing will be: this abandons the
            // exchange (its `using` releases the native state) and re-runs the ordinary password
            // login, whose outcome — success or failure — is the one the caller gets.
            //
            // Only AuthError falls through here. A NetworkError from Finish() is a configuration
            // fault (an unknown KSF, an out-of-range cost), not a credential check, and must not
            // put a plaintext password on the wire.
            return await LoginAsync(usernameOrEmail, new string(password), cancellationToken)
                .ConfigureAwait(false);
        }

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

        (bool organizationLevel, PrincipalScope? scope) =
            await ReadLoginScopeAsync(response, cancellationToken).ConfigureAwait(false);
        return new LoginResult(false, OrganizationLevel: organizationLevel, Scope: scope);
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
    public Task<OpaqueEnrollment> OpaqueEnrollmentAsync(
        char[] password,
        CancellationToken cancellationToken = default) =>
        EnrollAsync(password, null, cancellationToken);

    /// <summary>
    /// Builds a registration record for the <b>caller's own</b> new password, sealed against
    /// the tenant the caller's account lives in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// CONTRACT.md &#167;5.2.2 rule 2. <c>POST /auth/password/change</c> and the record that
    /// accompanies it are about the account, not about whatever tenant the client is currently
    /// pointed at, and a record sealed against the acting tenant is refused with <i>"the OPAQUE
    /// session was issued for a different tenant"</i>.
    /// </para>
    /// <para>
    /// The distinction only bites for an organization-level principal that has selected another
    /// tenant to act on; for everyone else the two tenants are the same value and this behaves
    /// identically to <see cref="OpaqueEnrollmentAsync"/>. It is still the method to call for a
    /// self-service password change, because which principal is signed in is not something the
    /// call site usually knows.
    /// </para>
    /// </remarks>
    /// <param name="password">The new password.</param>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <returns>The <c>opaque</c> object to attach to the request.</returns>
    /// <exception cref="NetworkError">
    /// No login has completed on this client yet — the principal tenant is reported by the login
    /// response, so there is nothing to seal against before then — or on the same terms as
    /// <see cref="OpaqueEnrollmentAsync"/> otherwise.
    /// </exception>
    public Task<OpaqueEnrollment> OpaqueEnrollmentForSelfAsync(
        char[] password,
        CancellationToken cancellationToken = default)
    {
        if (_principalTenantId is not { } stored || !Guid.TryParse(stored, out Guid principalTenantId))
        {
            // FromMessage, not `new`: the constructor is protected so that FromResponse
            // stays the only path from a live response into this type (see NetworkError's
            // class remarks).
            throw NetworkError.FromMessage(
                "OPAQUE: no principal tenant is known yet — sign in before building a "
                + "registration record for your own password");
        }

        return EnrollAsync(password, principalTenantId, cancellationToken);
    }

    /// <summary>
    /// The shared body of the two enrolment methods; they differ only in the tenant the record
    /// is sealed against.
    /// </summary>
    private async Task<OpaqueEnrollment> EnrollAsync(
        char[] password,
        Guid? principalTenantId,
        CancellationToken cancellationToken)
    {
        EnsureNotDisposed();
        ArgumentNullException.ThrowIfNull(password);

        using RegistrationExchange exchange = OpaqueProtocol.StartRegistration(password);

        var body = new Dictionary<string, object?>
        {
            ["registration_request"] = exchange.Request,
        };
        ApplyTenantAndOrgFields(body);
        if (principalTenantId is not null)
        {
            // CONTRACT.md §5.2.2 rule 2. Name the principal tenant by id and drop the slug: a
            // slug naming the acting tenant would out-vote the id server-side, which is the
            // exact confusion this override exists to avoid.
            body.Remove("tenant_slug");
            body["tenant_id"] = principalTenantId.Value.ToString();
        }

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

    /// <summary>
    /// Reads the &#167;5.2 flag and the &#167;5.2.2/&#167;5.2.3 scope off a completed login
    /// response in one pass, and caches the principal tenant for
    /// <see cref="OpaqueEnrollmentForSelfAsync"/>.
    /// </summary>
    /// <remarks>
    /// One method rather than two because <see cref="ReadJsonAsync"/> disposes the content
    /// stream: a second <c>...OfAsync(response)</c> pass would find nothing to read.
    /// The scope is <c>null</c> when the server reports none of it, which is what a server older
    /// than contract 1.34 does — <see cref="PrincipalScope"/> itself applies the "absent means
    /// equal" fallback for the fields it does get.
    /// </remarks>
    private async Task<(bool OrganizationLevel, PrincipalScope? Scope)> ReadLoginScopeAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        JsonElement wire;
        try
        {
            wire = await ReadJsonAsync(response, cancellationToken).ConfigureAwait(false);
        }
        catch (JsonException)
        {
            // The login already succeeded; the scope is not worth failing it over.
            return (false, null);
        }

        if (wire.ValueKind != JsonValueKind.Object
            || !wire.TryGetProperty("user", out JsonElement user)
            || user.ValueKind != JsonValueKind.Object)
        {
            // No user object at all: this response tells the §5.2 gate nothing, so it
            // stays "unknown" (null) rather than being read as "false" — §5.2 rule 1's
            // "For C-12" item 5 (OPAQUE shares this method with the password login: the
            // wire shape, not which endpoint produced it, decides whether the scope is
            // known — see AxiamClient.cs's remarks on ActingTenant()).
            _session.OrganizationLevel = null;
            _session.ReachableTenantIds = null;
            return (false, null);
        }

        bool organizationLevel =
            user.TryGetProperty("organization_level", out JsonElement flag)
            && flag.ValueKind == JsonValueKind.True;

        Guid? acting = ReadGuid(user, "tenant_id");
        Guid? principal = ReadGuid(user, "principal_tenant_id");
        Guid? orgId = ReadGuid(user, "org_id");
        string? principalSlug =
            user.TryGetProperty("principal_tenant_slug", out JsonElement slug)
            && slug.ValueKind == JsonValueKind.String
                ? slug.GetString()
                : null;

        List<Guid>? reachable = null;
        if (user.TryGetProperty("reachable_tenant_ids", out JsonElement list)
            && list.ValueKind == JsonValueKind.Array)
        {
            reachable = new List<Guid>();
            foreach (JsonElement entry in list.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.String
                    && Guid.TryParse(entry.GetString(), out Guid parsed))
                {
                    reachable.Add(parsed);
                }
            }
        }

        // A `user` object was present, so §5.2 rule 1's gate is now known — true, false,
        // or (an absent field, the server-older-than-1.31 case) the field's own
        // documented safe default, false. Every one of those is "known" for gating
        // purposes: only the complete absence of a `user` object, handled above, is
        // "unknown".
        _session.OrganizationLevel = organizationLevel;
        _session.ReachableTenantIds = reachable;

        if (acting is null && principal is null && orgId is null
            && principalSlug is null && reachable is null)
        {
            return (organizationLevel, null);
        }

        var scope = new PrincipalScope(acting, principal, principalSlug, orgId, reachable);
        if (scope.PrincipalTenantId is Guid resolved)
        {
            _principalTenantId = resolved.ToString();
        }

        return (organizationLevel, scope);
    }

    /// <summary>A <see cref="Guid"/> from a JSON property, or <c>null</c> when absent or unparseable.</summary>
    private static Guid? ReadGuid(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value)
        && value.ValueKind == JsonValueKind.String
        && Guid.TryParse(value.GetString(), out Guid parsed)
            ? parsed
            : null;

    private static string ReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) ? value.GetString() ?? string.Empty : string.Empty;

    /// <summary>
    /// A password <see cref="LoginAsync"/> would reject outright, so there is nothing to fall
    /// back with: &#167;23.4 rule 7's `optional` retry keeps reporting the OPAQUE
    /// <see cref="AuthError"/> rather than swapping it for an <see cref="ArgumentException"/>
    /// about an empty argument.
    /// </summary>
    private static bool IsBlank(char[] password) =>
        password.Length == 0 || Array.TrueForAll(password, char.IsWhiteSpace);

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
