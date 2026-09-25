using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using Axiam.Sdk;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Grpc;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Axiam.V1;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Moq;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// D-10/&#167;9 gRPC transport regression suite: proves <see cref="AxiamGrpcAuthzClient"/>
/// resolves a granted/denied <c>CheckAccess</c>/<c>BatchCheckAccess</c> call, maps a
/// <c>PERMISSION_DENIED</c> status to <see cref="AuthzError"/> via the shared
/// <see cref="ErrorMapper"/>, drives EXACTLY ONE shared-guard refresh + one retry on
/// <c>UNAUTHENTICATED</c> (never a loop), and sources the wire <c>tenant_id</c>/
/// <c>subject_id</c> from the access token's claims — never from the raw configured
/// tenant string.
/// </summary>
/// <remarks>
/// The SDK's C# gRPC codegen is client-only (<c>GrpcServices="Client"</c>, [LOCKED] —
/// the SDK never hosts a gRPC server), so there is no generated
/// <c>AuthorizationServiceBase</c> to host a real in-process server against. Instead,
/// this suite drives <see cref="AxiamGrpcAuthzClient"/>'s internal test seam (which
/// accepts a raw <see cref="CallInvoker"/>) with a Moq-mocked <see cref="CallInvoker"/>
/// that stands in for the wire — scripting canned <see cref="AsyncUnaryCall{TResponse}"/>
/// responses/faults per test, exactly like the previous in-process Kestrel server did,
/// without needing a real gRPC transport. The mocked invoker is wrapped with the SAME
/// production <see cref="AuthInterceptor"/> the real client uses (via
/// <c>CallInvoker.Intercept</c>), so metadata-injection and single-flight-retry
/// behavior are still exercised end-to-end against the interceptor's real code.
/// </remarks>
[Trait("Category", "Fast")]
public class GrpcAuthzClientTests
{
    [Fact]
    public async Task CheckAccessAsync_Allowed_ReturnsTrue()
    {
        var invoker = new FakeCallInvoker(handleCheck: (_, _) => new CheckAccessResponse { Allowed = true });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt(subject: "user-1", tenantId: "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => jwt);

        bool allowed = await client.CheckAccessAsync("documents:read", "doc-42");

        Assert.True(allowed);
        Assert.Equal(0, refresh.Count);
    }

    [Fact]
    public async Task CheckAccessAsync_Denied_ReturnsFalse()
    {
        var invoker = new FakeCallInvoker(handleCheck: (_, _) => new CheckAccessResponse { Allowed = false, DenyReason = "no matching role" });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => jwt);

        bool allowed = await client.CheckAccessAsync("documents:delete", "doc-42");

        Assert.False(allowed);
    }

    // ------------------------------------------------------------------
    // Decision reason precedence (SDK-Q10, CONTRACT.md §11.2 rule 9, contract 1.19)
    //
    // `CheckAccessResponse` carries the reason under two names: the canonical
    // `reason` (proto field 4, explicit presence) and the deprecated `deny_reason`
    // (field 2, `[deprecated = true]`, removed at AXIAM 2.0). The rule: read
    // `reason`; fall back to `deny_reason` ONLY when `reason` is absent on a
    // refusal; expose exactly one reason accessor (`AccessDecision.Reason`).
    // ------------------------------------------------------------------

    [Fact]
    public async Task CheckAccessDecisionAsync_ReadsReason_InPreferenceToDenyReason()
    {
        // A current server populates both fields with the identical string; `reason` is
        // read and `deny_reason` is never consulted, even though it disagrees here.
        var invoker = new FakeCallInvoker(handleCheck: (_, _) => new CheckAccessResponse
        {
            Allowed = false,
            DenyReason = "stale duplicate",
            ReasonCode = AxiamReasonCode.DeniedByRule,
            Reason = "denied by rule",
        });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");
        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => jwt);

        AccessDecision decision = await client.CheckAccessDecisionAsync("documents:delete", "doc-42");

        Assert.False(decision.Allowed);
        Assert.Equal("denied by rule", decision.Reason);
        Assert.Equal(AxiamReasonCode.DeniedByRule, decision.ReasonCode);
    }

    [Fact]
    public async Task CheckAccessDecisionAsync_OnARefusal_FallsBackToDenyReason_WhenReasonIsAbsent()
    {
        // A pre-SDK-Q10 server never sets field 4. Because `reason` has explicit
        // presence, its absence is distinguishable from an empty value, so the
        // deprecated field is still read rather than the refusal losing its reason.
        var invoker = new FakeCallInvoker(handleCheck: (_, _) => new CheckAccessResponse
        {
            Allowed = false,
            DenyReason = "caller lacks permission",
            ReasonCode = AxiamReasonCode.NoGrant,
            // `Reason` deliberately left unset (HasReason == false).
        });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");
        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => jwt);

        AccessDecision decision = await client.CheckAccessDecisionAsync("documents:delete", "doc-42");

        Assert.False(decision.Allowed);
        Assert.Equal("caller lacks permission", decision.Reason);
    }

    [Fact]
    public async Task CheckAccessDecisionAsync_OnAnAllow_ReasonIsAbsent_AndNeverFallsBackToDenyReason()
    {
        // Fallback is refusal-only: an allow must never surface `deny_reason`, even if a
        // (malformed) server response sets it — REST omits `reason` on an allow and gRPC
        // must behave identically. There is nothing to say.
        var invoker = new FakeCallInvoker(handleCheck: (_, _) => new CheckAccessResponse
        {
            Allowed = true,
            DenyReason = "should never surface",
            // `Reason` deliberately left unset (HasReason == false) — exactly what a
            // current server sends on an allow.
        });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");
        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => jwt);

        AccessDecision decision = await client.CheckAccessDecisionAsync("documents:read", "doc-42");

        Assert.True(decision.Allowed);
        Assert.Null(decision.Reason);
    }

    [Fact]
    public async Task CheckAccessDecisionAsync_OnARefusal_AnExplicitlyEmptyReason_DoesNotFallBackToDenyReason()
    {
        // The case that motivates guarding on presence (HasReason) rather than
        // truthiness: an explicitly-set-but-empty `reason` on a REFUSAL is not absent —
        // it must not be misread as "no reason sent" and must not fall back to
        // `deny_reason`, even though `deny_reason` is populated.
        var invoker = new FakeCallInvoker(handleCheck: (_, _) => new CheckAccessResponse
        {
            Allowed = false,
            Reason = string.Empty,
            DenyReason = "caller lacks permission",
            ReasonCode = AxiamReasonCode.NoGrant,
        });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");
        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => jwt);

        AccessDecision decision = await client.CheckAccessDecisionAsync("documents:delete", "doc-42");

        Assert.False(decision.Allowed);
        Assert.Null(decision.Reason);
    }

    [Fact]
    public async Task BatchCheckDecisionsAsync_AppliesReasonPrecedence_PerResult()
    {
        var invoker = new FakeCallInvoker(handleBatch: req =>
        {
            var response = new BatchCheckAccessResponse();
            response.Results.Add(new CheckAccessResponse { Allowed = true }); // no reason either way
            response.Results.Add(new CheckAccessResponse { Allowed = false, Reason = "denied by rule", DenyReason = "stale duplicate" }); // reason wins
            response.Results.Add(new CheckAccessResponse { Allowed = false, DenyReason = "no matching role" }); // falls back
            response.Results.Add(new CheckAccessResponse { Allowed = false, Reason = string.Empty, DenyReason = "should not surface" }); // explicit empty, no fallback
            return response;
        });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");
        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => jwt);

        IReadOnlyList<AccessDecision> decisions = await client.BatchCheckDecisionsAsync(new[]
        {
            new AxiamGrpcAuthzClient.AccessCheck("documents:read", "doc-1"),
            new AxiamGrpcAuthzClient.AccessCheck("documents:delete", "doc-2"),
            new AxiamGrpcAuthzClient.AccessCheck("documents:delete", "doc-3"),
            new AxiamGrpcAuthzClient.AccessCheck("documents:delete", "doc-4"),
        });

        Assert.Equal(4, decisions.Count);
        Assert.Null(decisions[0].Reason);
        Assert.Equal("denied by rule", decisions[1].Reason);
        Assert.Equal("no matching role", decisions[2].Reason);
        Assert.Null(decisions[3].Reason);
    }

    [Fact]
    public async Task CheckAccessAsync_PermissionDenied_MapsToAuthzError()
    {
        var invoker = new FakeCallInvoker(
            handleCheck: (_, _) => throw new RpcException(new Status(StatusCode.PermissionDenied, "caller lacks documents:delete")));
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => jwt);

        await Assert.ThrowsAsync<AuthzError>(() => client.CheckAccessAsync("documents:delete", "doc-42"));
    }

    [Fact]
    public async Task CheckAccessAsync_Unauthenticated_TriggersExactlyOneRefreshThenRetries()
    {
        int callCount = 0;
        var invoker = new FakeCallInvoker(handleCheck: (_, _) =>
        {
            int n = Interlocked.Increment(ref callCount);
            if (n == 1)
            {
                // First attempt: simulate an expired/invalid token — the shared
                // AuthInterceptor MUST drive exactly one RefreshGuard refresh and retry
                // exactly once (§9.3, no loop).
                throw new RpcException(new Status(StatusCode.Unauthenticated, "token expired"));
            }
            return new CheckAccessResponse { Allowed = true };
        });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => jwt);

        bool allowed = await client.CheckAccessAsync("documents:read", "doc-42");

        Assert.True(allowed);
        Assert.Equal(2, callCount); // original attempt + exactly one retry
        Assert.Equal(1, refresh.Count); // exactly one shared-guard refresh — non-vacuous single-flight
    }

    // ---- N4.5 (CONTRACT 1.52, C-12): never refreshed on a device credential, on either
    // transport — "It surfaces the server's message, never the refresh guard's." The REST
    // transport (AxiamHttpMessageHandler) checks `_staticBearerToken is not null` and
    // skips the reactive-refresh branch ENTIRELY for a device-credentialed handle, so the
    // server's own 401 body surfaces untouched. AuthInterceptor.HandleResponseAsync has no
    // such check: it unconditionally calls `_refreshGuard.RefreshIfNeededAsync` on ANY
    // UNAUTHENTICATED. For a device handle, that guard's delegate is built to always throw
    // (AxiamClient.Device.cs: "unreachable: a device-credentialed handle never attempts a
    // token refresh") — so a gRPC UNAUTHENTICATED on the device credential replaced the
    // server's own status/message with the refresh guard's internal one instead.

    [Fact]
    public async Task CheckAccessAsync_Unauthenticated_OnADeviceCredential_SurfacesTheServersMessage_NoRefreshAttempt()
    {
        int callCount = 0;
        var invoker = new FakeCallInvoker(handleCheck: (_, _) =>
        {
            Interlocked.Increment(ref callCount);
            throw new RpcException(new Status(StatusCode.Unauthenticated, "device token expired"));
        });
        // Mirrors AxiamClient.Device.cs's own RefreshGuard construction for a device
        // handle EXACTLY: no refresh token exists, so the delegate always throws rather
        // than ever attempting an HTTP call.
        using var deviceGuard = new RefreshGuard(_ => throw new AuthError(
            "unreachable: a device-credentialed handle never attempts a token refresh (CONTRACT.md §6.1 rule 6)"));
        string deviceJwt = MintUnverifiedJwt("device-subject", "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(invoker, deviceGuard, "tenant-1", () => deviceJwt, refreshExempt: true);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.CheckAccessAsync("documents:read", "doc-42"));

        Assert.Contains("device token expired", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("unreachable", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, callCount); // no retry — never refreshed
    }

    // ---- N4.5 follow-up: refreshExempt is evaluated PER CALL, not captured once at
    // construction. AxiamGrpcAuthzClient's production constructor used to pass
    // `refreshExempt: client.HasStaticBearerToken` — a `bool`, read once, when the gRPC
    // client was built. A gRPC client built from a device handle BEFORE a later LoginAsync()
    // on that same handle released the device credential (N4.4) would keep skipping the
    // refresh guard forever, even after the handle had moved on to a real cookie session
    // that DOES have a refresh token to spend. AuthInterceptor now takes a `Func<bool>`
    // and re-evaluates it on every UNAUTHENTICATED, so the SAME interceptor instance
    // tracks the handle's credential live.

    [Fact]
    public async Task CheckAccessAsync_Unauthenticated_RefreshExemptIsEvaluatedPerCall_NotCapturedAtConstruction()
    {
        var restHandler = new RoutingHandler();
        restHandler.Map("/api/v1/auth/device", _ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """{"access_token":"device-token-abc","token_type":"Bearer","expires_in":900}""",
                Encoding.UTF8, "application/json"),
        });
        restHandler.Map("/api/v1/auth/login", _ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"user":{"organization_level":false}}""", Encoding.UTF8, "application/json"),
        });
        byte[] certPem = Encoding.ASCII.GetBytes(
            "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKZ0000000000MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n-----END CERTIFICATE-----\n");
        byte[] keyPem = Encoding.ASCII.GetBytes(
            "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n");
        var baseUrl = new Uri("https://axiam.test");
        const string tenantGuid = "22222222-2222-2222-2222-222222222222";
        var options = new AxiamClientOptions
        {
            BaseUrl = baseUrl,
            TenantId = tenantGuid,
            ClientCertificatePem = certPem,
            ClientKeyPem = keyPem,
        };
        using AxiamClient original = AxiamClient.CreateForTesting(baseUrl, tenantGuid, options, restHandler);
        using AxiamClient device = (await original.AuthenticateDeviceAsync()).Client;
        Assert.True(device.HasStaticBearerToken);

        int callCount = 0;
        var invoker = new FakeCallInvoker(handleCheck: (_, _) =>
        {
            int n = Interlocked.Increment(ref callCount);
            // Calls 1 and 2 are UNAUTHENTICATED (round 1's only attempt, round 2's first
            // attempt); call 3 (round 2's retry, after a successful refresh) succeeds.
            if (n <= 2)
            {
                throw new RpcException(new Status(StatusCode.Unauthenticated, "token expired"));
            }
            return new CheckAccessResponse { Allowed = true };
        });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("device-subject", tenantGuid);
        // Built ONCE, while the handle is still device-credentialed — the interceptor
        // must not freeze that fact for the rest of its lifetime.
        var interceptor = new AuthInterceptor(() => jwt, tenantGuid, refresh.Guard, () => device.HasStaticBearerToken);
        CallInvoker interceptedInvoker = invoker.Intercept(interceptor);
        using var grpcClient = new AxiamGrpcAuthzClient(interceptedInvoker, null, () => jwt, tenantGuid);

        // Round 1: still device-credentialed — never refreshed, exactly like the test above.
        await Assert.ThrowsAsync<AuthError>(() => grpcClient.CheckAccessAsync("documents:read", "doc-1"));
        Assert.Equal(0, refresh.Count);
        Assert.Equal(1, callCount);

        // A later LoginAsync() on the SAME handle succeeds and releases the device
        // credential (N4.4) — HasStaticBearerToken flips to false.
        await device.LoginAsync("user@example.com", "hunter2");
        Assert.False(device.HasStaticBearerToken);

        // Round 2, same interceptor instance: refreshExempt() now reads false, so
        // UNAUTHENTICATED is routed through the refresh guard again, and the retry
        // succeeds.
        bool allowed = await grpcClient.CheckAccessAsync("documents:read", "doc-1");

        Assert.True(allowed);
        Assert.Equal(1, refresh.Count);
        Assert.Equal(3, callCount); // round 1 (1) + round 2's attempt + retry (2 more)
    }

    [Fact]
    public async Task BatchCheckAsync_PreservesOrder()
    {
        var invoker = new FakeCallInvoker(handleBatch: req =>
        {
            bool[] pattern = { true, false, true };
            var response = new BatchCheckAccessResponse();
            for (int i = 0; i < req.Requests.Count; i++)
            {
                response.Results.Add(new CheckAccessResponse { Allowed = pattern[i % pattern.Length] });
            }
            return response;
        });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => jwt);

        var checks = new[]
        {
            new AxiamGrpcAuthzClient.AccessCheck("users:get", "r1"),
            new AxiamGrpcAuthzClient.AccessCheck("users:delete", "r2"),
            new AxiamGrpcAuthzClient.AccessCheck("users:list", "r3"),
        };

        IReadOnlyList<bool> results = await client.BatchCheckAsync(checks);

        Assert.Equal(new[] { true, false, true }, results);
    }

    [Fact]
    public async Task CheckAccessAsync_NoActiveSession_ThrowsAuthError_WithoutAnyRpcCall()
    {
        var invoker = new FakeCallInvoker();
        using var refresh = new RefreshCounter();

        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => null);

        await Assert.ThrowsAsync<AuthError>(() => client.CheckAccessAsync("documents:read", "doc-42"));
        Assert.Empty(invoker.ReceivedChecks);
    }

    [Fact]
    public async Task CheckAccessAsync_ResolvesWireIdentity_FromTokenClaims_NotConfiguredTenantString()
    {
        const string claimTenantId = "44444444-4444-4444-4444-444444444444";
        const string claimSubjectId = "55555555-5555-5555-5555-555555555555";
        const string configuredTenantSlug = "acme-corp"; // deliberately NOT the claim's tenant_id
        string jwt = MintUnverifiedJwt(claimSubjectId, claimTenantId);

        var invoker = new FakeCallInvoker(handleCheck: (req, _) => new CheckAccessResponse { Allowed = true });
        using var refresh = new RefreshCounter();

        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, configuredTenantSlug, () => jwt);

        await client.CheckAccessAsync("documents:read", "doc-1");

        CheckAccessRequest? received = Assert.Single(invoker.ReceivedChecks);
        Assert.Equal(claimTenantId, received!.TenantId);
        Assert.Equal(claimSubjectId, received.SubjectId);
        Assert.NotEqual(configuredTenantSlug, received.TenantId);
    }

    [Fact]
    public async Task CheckAccessAsync_ResolvesWireIdentity_ViaSignatureVerifiedJwksClaims()
    {
        var fixture = new JwksFixture();
        const string tenantId = "66666666-6666-6666-6666-666666666666";
        const string subjectId = "77777777-7777-7777-7777-777777777777";
        string jwt = fixture.SignJwt(subjectId, tenantId, roles: new[] { "member" }, expiresAt: DateTimeOffset.UtcNow.AddMinutes(15));

        using var jwksHttpClient = new HttpClient(new FakeJwksHandler(fixture.BuildJwksDocument())) { BaseAddress = new Uri("https://axiam.test") };
        var jwksVerifier = new JwksVerifier(jwksHttpClient, new Uri("https://axiam.test"), TimeSpan.FromMinutes(5));

        var invoker = new FakeCallInvoker(handleCheck: (req, _) => new CheckAccessResponse { Allowed = true });
        using var refresh = new RefreshCounter();

        // The configured tenant MUST equal the JWT's tenant_id claim for the
        // signature-verified path to succeed (JwksVerifier.VerifyAsync's mandatory
        // cross-tenant check, T-21-07) — this test proves the VERIFIED resolution path
        // itself works end-to-end (real BouncyCastle Ed25519 verification against a
        // fetched JWKS document), which the unverified-fallback tests above do not
        // exercise.
        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, tenantId, () => jwt, jwksVerifier);

        bool allowed = await client.CheckAccessAsync("documents:read", "doc-1");

        Assert.True(allowed);
        CheckAccessRequest? received = Assert.Single(invoker.ReceivedChecks);
        Assert.Equal(tenantId, received!.TenantId);
        Assert.Equal(subjectId, received.SubjectId);
    }

    // ------------------------------------------------------------------
    // Test helpers
    // ------------------------------------------------------------------

    private static AxiamGrpcAuthzClient BuildClient(
        FakeCallInvoker fakeInvoker, RefreshGuard guard, string tenantId, Func<string?> tokenAccessor,
        JwksVerifier? jwksVerifier = null, bool refreshExempt = false)
    {
        var interceptor = new AuthInterceptor(tokenAccessor, tenantId, guard, refreshExempt);
        CallInvoker invoker = fakeInvoker.Intercept(interceptor);
        return new AxiamGrpcAuthzClient(invoker, jwksVerifier, tokenAccessor, tenantId);
    }

    /// <summary>
    /// Mints a JWT-shaped (but unsigned) token that the SDK's unverified-decode fallback
    /// (used whenever no <see cref="JwksVerifier"/> is supplied) can parse — no real
    /// signature is required because that fallback path never checks one; it only reads
    /// <c>sub</c>/<c>tenant_id</c> out of the payload segment as an operational hint.
    /// </summary>
    private static string MintUnverifiedJwt(string subject, string tenantId)
    {
        string header = Base64UrlEncode(Encoding.UTF8.GetBytes("""{"alg":"none"}"""));
        string payload = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new { sub = subject, tenant_id = tenantId }));
        return $"{header}.{payload}.unsigned";
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Test-double <see cref="RefreshGuard"/> wrapper counting how many times the
    /// underlying refresh delegate actually ran — the single-flight non-vacuousness proof
    /// for the UNAUTHENTICATED-retry test.</summary>
    private sealed class RefreshCounter : IDisposable
    {
        private int _count;

        public RefreshGuard Guard { get; }

        public int Count => _count;

        public RefreshCounter()
        {
            Guard = new RefreshGuard(_ =>
            {
                Interlocked.Increment(ref _count);
                return Task.FromResult(new TokenPair(
                    Sensitive.Of("refreshed-access"),
                    Sensitive.Of("refreshed-refresh"),
                    DateTimeOffset.UtcNow.AddMinutes(15)));
            });
        }

        public void Dispose() => Guard.Dispose();
    }

    /// <summary>Serves a fixed JWKS document body for every request — a fake
    /// <c>GET /oauth2/jwks</c> backing a real <see cref="JwksVerifier"/> instance.</summary>
    private sealed class FakeJwksHandler : HttpMessageHandler
    {
        private readonly string _jwksJson;

        public FakeJwksHandler(string jwksJson) => _jwksJson = jwksJson;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_jwksJson, Encoding.UTF8, "application/json"),
            });
    }

    /// <summary>
    /// Mocked <see cref="CallInvoker"/> (Moq, over the abstract, virtual
    /// <c>CallInvoker.AsyncUnaryCall&lt;TRequest,TResponse&gt;</c> members the generated
    /// <c>AuthorizationServiceClient</c> actually calls) standing in for the wire —
    /// records every received <c>CheckAccess</c> request and answers via caller-supplied
    /// handlers, so each test can script granted/denied/error responses without a real
    /// gRPC server. <c>AsyncUnaryCall&lt;T&gt;</c> results are built exactly as
    /// <c>Grpc.Net.Client</c> itself would: a completed <see cref="Task{TResult}"/> (or a
    /// faulted one carrying an <see cref="RpcException"/>) plus trivial
    /// headers/status/trailers/dispose delegates.
    /// </summary>
    private sealed class FakeCallInvoker
    {
        private readonly Func<CheckAccessRequest, CallOptions, CheckAccessResponse> _handleCheck;
        private readonly Func<BatchCheckAccessRequest, BatchCheckAccessResponse> _handleBatch;

        public List<CheckAccessRequest> ReceivedChecks { get; } = new();

        public FakeCallInvoker(
            Func<CheckAccessRequest, CallOptions, CheckAccessResponse>? handleCheck = null,
            Func<BatchCheckAccessRequest, BatchCheckAccessResponse>? handleBatch = null)
        {
            _handleCheck = handleCheck ?? ((_, _) => new CheckAccessResponse { Allowed = true });
            _handleBatch = handleBatch ?? (req =>
            {
                var response = new BatchCheckAccessResponse();
                foreach (CheckAccessRequest item in req.Requests)
                {
                    response.Results.Add(new CheckAccessResponse { Allowed = true });
                }
                return response;
            });
        }

        /// <summary>Builds the mocked <see cref="CallInvoker"/> instance for this fake's
        /// handlers, ready to be wrapped by the production <see cref="AuthInterceptor"/>
        /// via <see cref="CallInvokerExtensions.Intercept(CallInvoker, Interceptor[])"/>.</summary>
        public CallInvoker Intercept(Interceptor interceptor)
        {
            var mock = new Mock<CallInvoker>();

            mock.Setup(m => m.AsyncUnaryCall(
                    It.IsAny<Method<CheckAccessRequest, CheckAccessResponse>>(),
                    It.IsAny<string>(),
                    It.IsAny<CallOptions>(),
                    It.IsAny<CheckAccessRequest>()))
                .Returns((Method<CheckAccessRequest, CheckAccessResponse> _, string _, CallOptions options, CheckAccessRequest request) =>
                {
                    ReceivedChecks.Add(request);
                    return RunUnary(() => _handleCheck(request, options));
                });

            mock.Setup(m => m.AsyncUnaryCall(
                    It.IsAny<Method<BatchCheckAccessRequest, BatchCheckAccessResponse>>(),
                    It.IsAny<string>(),
                    It.IsAny<CallOptions>(),
                    It.IsAny<BatchCheckAccessRequest>()))
                .Returns((Method<BatchCheckAccessRequest, BatchCheckAccessResponse> _, string _, CallOptions _, BatchCheckAccessRequest request) =>
                    RunUnary(() => _handleBatch(request)));

            return mock.Object.Intercept(interceptor);
        }

        private static AsyncUnaryCall<TResponse> RunUnary<TResponse>(Func<TResponse> handler)
        {
            Task<TResponse> responseTask;
            try
            {
                responseTask = Task.FromResult(handler());
            }
            catch (Exception ex)
            {
                responseTask = Task.FromException<TResponse>(ex);
            }

            return new AsyncUnaryCall<TResponse>(
                responseTask,
                Task.FromResult(new Metadata()),
                () => Status.DefaultSuccess,
                () => new Metadata(),
                () => { });
        }
    }
}
