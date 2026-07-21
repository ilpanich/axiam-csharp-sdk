using System.Text;
using System.Text.Json;
using System.Threading;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Grpc;
using Axiam.V1;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Moq;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;1.1 gRPC-only <c>GetUserInfo</c> regression suite: proves
/// <see cref="AxiamGrpcAuthzClient.GetUserInfoAsync"/> maps the wire
/// <c>GetUserInfoResponse</c> claim set to a typed <see cref="UserInfo"/> (always-present
/// <c>sub</c>/<c>tenant_id</c>/<c>org_id</c>; scope-gated <c>email</c>/
/// <c>preferred_username</c> surfacing as <c>null</c> when absent), drives EXACTLY ONE
/// shared-guard refresh + one retry on <c>UNAUTHENTICATED</c> (never a loop, &#167;9.3),
/// and raises <see cref="AuthError"/> client-side without any wire call when there is no
/// active session (&#167;1.1.3).
/// </summary>
/// <remarks>
/// Mirrors <see cref="GrpcAuthzClientTests"/> exactly: the SDK's C# gRPC codegen is
/// client-only (<c>GrpcServices="Client"</c>), so there is no generated service base to
/// host a real in-process server against. Instead this suite drives
/// <see cref="AxiamGrpcAuthzClient"/>'s internal test seam (a raw <see cref="CallInvoker"/>)
/// with a Moq-mocked invoker wrapped in the SAME production <see cref="AuthInterceptor"/>
/// the real client uses, so metadata-injection and single-flight-retry behavior are
/// exercised end-to-end against the interceptor's real code.
/// </remarks>
[Trait("Category", "Fast")]
public class GrpcUserInfoClientTests
{
    [Fact]
    public async Task GetUserInfoAsync_MapsAllClaims_IncludingScopedOptionals()
    {
        var invoker = new FakeUserInfoInvoker(_ => new GetUserInfoResponse
        {
            Sub = "user-1",
            TenantId = "tenant-1",
            OrgId = "org-1",
            Email = "user1@example.test",
            PreferredUsername = "user_one",
        });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => jwt);

        UserInfo info = await client.GetUserInfoAsync();

        Assert.Equal("user-1", info.Sub);
        Assert.Equal("tenant-1", info.TenantId);
        Assert.Equal("org-1", info.OrgId);
        Assert.Equal("user1@example.test", info.Email);
        Assert.Equal("user_one", info.PreferredUsername);
        Assert.Equal(0, refresh.Count);
    }

    [Fact]
    public async Task GetUserInfoAsync_AbsentOptionals_SurfaceAsNull()
    {
        // No "email"/"profile" scope on the token — the server omits both optional fields;
        // the SDK MUST surface them as null (not the empty-string proto3 default).
        var invoker = new FakeUserInfoInvoker(_ => new GetUserInfoResponse
        {
            Sub = "user-2",
            TenantId = "tenant-2",
            OrgId = "org-2",
        });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-2", "tenant-2");

        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-2", () => jwt);

        UserInfo info = await client.GetUserInfoAsync();

        Assert.Equal("user-2", info.Sub);
        Assert.Equal("tenant-2", info.TenantId);
        Assert.Equal("org-2", info.OrgId);
        Assert.Null(info.Email);
        Assert.Null(info.PreferredUsername);
    }

    [Fact]
    public async Task GetUserInfoAsync_Unauthenticated_TriggersExactlyOneRefreshThenRetries()
    {
        int callCount = 0;
        var invoker = new FakeUserInfoInvoker(_ =>
        {
            int n = Interlocked.Increment(ref callCount);
            if (n == 1)
            {
                // First attempt: expired/invalid token — the shared AuthInterceptor MUST
                // drive exactly one RefreshGuard refresh and retry exactly once (§9.3, no loop).
                throw new RpcException(new Status(StatusCode.Unauthenticated, "token expired"));
            }
            return new GetUserInfoResponse { Sub = "user-3", TenantId = "tenant-3", OrgId = "org-3" };
        });
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-3", "tenant-3");

        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-3", () => jwt);

        UserInfo info = await client.GetUserInfoAsync();

        Assert.Equal("user-3", info.Sub);
        Assert.Equal(2, callCount);      // original attempt + exactly one retry
        Assert.Equal(1, refresh.Count);  // exactly one shared-guard refresh — non-vacuous single-flight
    }

    [Fact]
    public async Task GetUserInfoAsync_PermissionDenied_MapsToAuthzError()
    {
        var invoker = new FakeUserInfoInvoker(
            _ => throw new RpcException(new Status(StatusCode.PermissionDenied, "caller lacks userinfo")));
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => jwt);

        await Assert.ThrowsAsync<AuthzError>(() => client.GetUserInfoAsync());
    }

    [Fact]
    public async Task GetUserInfoAsync_NoActiveSession_ThrowsAuthError_WithoutAnyRpcCall()
    {
        var invoker = new FakeUserInfoInvoker(_ => new GetUserInfoResponse { Sub = "x", TenantId = "y", OrgId = "z" });
        using var refresh = new RefreshCounter();

        using AxiamGrpcAuthzClient client = BuildClient(invoker, refresh.Guard, "tenant-1", () => null);

        await Assert.ThrowsAsync<AuthError>(() => client.GetUserInfoAsync());
        Assert.Equal(0, invoker.CallCount);
    }

    // ------------------------------------------------------------------
    // Test helpers (mirror GrpcAuthzClientTests)
    // ------------------------------------------------------------------

    private static AxiamGrpcAuthzClient BuildClient(
        FakeUserInfoInvoker fakeInvoker, RefreshGuard guard, string tenantId, Func<string?> tokenAccessor, JwksVerifier? jwksVerifier = null)
    {
        var interceptor = new AuthInterceptor(tokenAccessor, tenantId, guard);
        CallInvoker invoker = fakeInvoker.Intercept(interceptor);
        return new AxiamGrpcAuthzClient(invoker, jwksVerifier, tokenAccessor, tenantId);
    }

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

    /// <summary>
    /// Mocked <see cref="CallInvoker"/> (Moq, over the abstract
    /// <c>CallInvoker.AsyncUnaryCall&lt;TRequest,TResponse&gt;</c> the generated
    /// <c>UserInfoServiceClient</c> actually calls) standing in for the wire — answers
    /// every <c>GetUserInfo</c> via a caller-supplied handler, so each test scripts a
    /// canned response/fault without a real gRPC server. The <c>AsyncUnaryCall&lt;T&gt;</c>
    /// is built exactly as <c>Grpc.Net.Client</c> would: a completed (or faulted)
    /// <see cref="Task{TResult}"/> plus trivial headers/status/trailers/dispose delegates.
    /// </summary>
    private sealed class FakeUserInfoInvoker
    {
        private readonly Func<GetUserInfoRequest, GetUserInfoResponse> _handle;
        private int _callCount;

        public int CallCount => _callCount;

        public FakeUserInfoInvoker(Func<GetUserInfoRequest, GetUserInfoResponse> handle) => _handle = handle;

        public CallInvoker Intercept(Interceptor interceptor)
        {
            var mock = new Mock<CallInvoker>();

            mock.Setup(m => m.AsyncUnaryCall(
                    It.IsAny<Method<GetUserInfoRequest, GetUserInfoResponse>>(),
                    It.IsAny<string>(),
                    It.IsAny<CallOptions>(),
                    It.IsAny<GetUserInfoRequest>()))
                .Returns((Method<GetUserInfoRequest, GetUserInfoResponse> _, string _, CallOptions _, GetUserInfoRequest request) =>
                {
                    Interlocked.Increment(ref _callCount);
                    return RunUnary(() => _handle(request));
                });

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
