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
/// CONTRACT.md &#167;1.1.1, &#167;10.3 (contract 1.51): <see cref="TokenGrpcClient"/>. Same
/// fake-<see cref="CallInvoker"/>-plus-real-<see cref="AuthInterceptor"/> harness as
/// <c>GrpcAuthzClientTests</c> (the C# gRPC codegen is client-only, so there is no
/// generated <c>TokenServiceBase</c> to host a real in-process server against).
/// </summary>
[Trait("Category", "Fast")]
public class TokenGrpcClientTests
{
    private const string CallerToken = "caller-access-token";

    // ---- §1.1.1 rule 2: no caller token, no wire call ----------------------------------

    [Fact]
    public async Task ValidateTokenAsync_NoCallerSession_ThrowsAuthError_ZeroWireCalls()
    {
        var invoker = new FakeCallInvoker();
        TokenGrpcClient client = BuildClient(invoker, tokenAccessor: () => null);

        await Assert.ThrowsAsync<AuthError>(() => client.ValidateTokenAsync(Sensitive.Of("inspected")));

        Assert.Equal(0, invoker.ValidateCalls);
    }

    [Fact]
    public async Task IntrospectTokenAsync_NoCallerSession_ThrowsAuthError_ZeroWireCalls()
    {
        var invoker = new FakeCallInvoker();
        TokenGrpcClient client = BuildClient(invoker, tokenAccessor: () => null);

        await Assert.ThrowsAsync<AuthError>(() => client.IntrospectTokenAsync(Sensitive.Of("inspected")));

        Assert.Equal(0, invoker.IntrospectCalls);
    }

    // ---- §1.1.1 rule 1: the inspected token travels in the message, never the caller's --

    [Fact]
    public async Task ValidateTokenAsync_SendsTheInspectedTokenInTheMessage_NotTheCallersOwn()
    {
        ValidateTokenRequest? received = null;
        var invoker = new FakeCallInvoker(handleValidate: req =>
        {
            received = req;
            return new ValidateTokenResponse { Valid = true, TokenType = "Bearer" };
        });
        TokenGrpcClient client = BuildClient(invoker, tokenAccessor: () => CallerToken);

        await client.ValidateTokenAsync(Sensitive.Of("a-different-inspected-token"));

        Assert.NotNull(received);
        Assert.Equal("a-different-inspected-token", received!.AccessToken);
        Assert.NotEqual(CallerToken, received.AccessToken);
    }

    // ---- §1.1.1 rule 3: every field, cnf included, absent distinguished from empty -----

    [Fact]
    public async Task ValidateTokenAsync_AnUnboundToken_HasNoCnfAtAll()
    {
        var invoker = new FakeCallInvoker(handleValidate: _ => new ValidateTokenResponse
        {
            Valid = true,
            SubjectId = "user-1",
            TenantId = "tenant-1",
            OrgId = "org-1",
            Exp = 1234567890,
            TokenType = "Bearer",
            // No Cnf set.
        });
        TokenGrpcClient client = BuildClient(invoker, tokenAccessor: () => CallerToken);

        TokenValidation result = await client.ValidateTokenAsync(Sensitive.Of("t"));

        Assert.True(result.Valid);
        Assert.Null(result.Cnf);
        Assert.Equal(TokenStatus.Bearer, result.Status());
        Assert.True(result.VerifyPossession(PresentedProofs.None()));
    }

    [Fact]
    public async Task ValidateTokenAsync_ACertificateBoundToken_ReportsTokenTypeBearerRegardless()
    {
        // §1.1.1 rule 5: token_type does not tell you whether a token is bound — a
        // certificate-bound token is reported "Bearer". Boundness comes from cnf alone.
        var invoker = new FakeCallInvoker(handleValidate: _ => new ValidateTokenResponse
        {
            Valid = true,
            TokenType = "Bearer",
            Cnf = new CnfClaim { X5TS256 = "thumbprint-abc" },
        });
        TokenGrpcClient client = BuildClient(invoker, tokenAccessor: () => CallerToken);

        TokenValidation result = await client.ValidateTokenAsync(Sensitive.Of("t"));

        Assert.Equal("Bearer", result.TokenType);
        Assert.NotNull(result.Cnf);
        Assert.Equal(TokenStatus.SenderConstrained, result.Status());
        Assert.False(result.VerifyPossession(PresentedProofs.None()));
        Assert.True(result.VerifyPossession(PresentedProofs.Certificate("thumbprint-abc")));
        Assert.False(result.VerifyPossession(PresentedProofs.Certificate("a-different-thumbprint")));
    }

    // ---- §10.3 rule 3: an empty CnfClaim is refused, never read as unbound -------------

    [Fact]
    public async Task ValidateTokenAsync_AnEmptyCnfClaim_IsUnverifiable_NeverBearer()
    {
        var invoker = new FakeCallInvoker(handleValidate: _ => new ValidateTokenResponse
        {
            Valid = true,
            TokenType = "Bearer",
            Cnf = new CnfClaim(), // present, both members default ("")
        });
        TokenGrpcClient client = BuildClient(invoker, tokenAccessor: () => CallerToken);

        TokenValidation result = await client.ValidateTokenAsync(Sensitive.Of("t"));

        Assert.NotNull(result.Cnf); // present-but-empty is NOT the same as absent
        Assert.Equal(TokenStatus.Unverifiable, result.Status());
        Assert.False(result.VerifyPossession(PresentedProofs.Certificate("anything")));
        Assert.False(result.VerifyPossession(PresentedProofs.None()));
    }

    // ---- §10.3 rule 6: a token from another tenant is valid:false, not an error --------

    [Fact]
    public async Task ValidateTokenAsync_ATokenFromAnotherTenant_IsValidFalse_NotAnException()
    {
        var invoker = new FakeCallInvoker(handleValidate: _ => new ValidateTokenResponse { Valid = false });
        TokenGrpcClient client = BuildClient(invoker, tokenAccessor: () => CallerToken);

        TokenValidation result = await client.ValidateTokenAsync(Sensitive.Of("t"));

        Assert.False(result.Valid);
        Assert.Equal(TokenStatus.Inactive, result.Status());
    }

    // ---- IntrospectToken: full RFC 7662 field set + UMA permissions + X4 ---------------

    [Fact]
    public async Task IntrospectTokenAsync_CarriesEveryField()
    {
        var invoker = new FakeCallInvoker(handleIntrospect: _ =>
        {
            var response = new IntrospectTokenResponse
            {
                Active = true,
                Sub = "user-1",
                TenantId = "tenant-1",
                OrgId = "org-1",
                Iss = "https://axiam.test",
                Iat = 1000,
                Exp = 2000,
                Jti = "jti-1",
                Scope = "openid profile",
                ClientId = "client-1",
                TokenType = "Bearer",
                ExtExchangeIss = "https://foreign-idp.test",
            };
            response.Permissions.Add(new Axiam.V1.RptPermission
            {
                ResourceId = "res-1",
                Exp = 3000,
            });
            response.Permissions[0].ResourceScopes.Add("read");
            response.Permissions[0].ResourceScopes.Add("write");
            return response;
        });
        TokenGrpcClient client = BuildClient(invoker, tokenAccessor: () => CallerToken);

        TokenIntrospection result = await client.IntrospectTokenAsync(Sensitive.Of("t"));

        Assert.True(result.Active);
        Assert.Equal("user-1", result.Sub);
        Assert.Equal("openid profile", result.Scope);
        Assert.Equal("client-1", result.ClientId);
        Assert.Equal("https://foreign-idp.test", result.ExtExchangeIss);
        Assert.Single(result.Permissions);
        Assert.Equal("res-1", result.Permissions[0].ResourceId);
        Assert.Equal(new[] { "read", "write" }, result.Permissions[0].ResourceScopes);
        Assert.Equal(3000, result.Permissions[0].Exp);
    }

    // ---- UNAUTHENTICATED (the CALLER's own token) drives one shared-guard refresh ------

    [Fact]
    public async Task ValidateTokenAsync_Unauthenticated_DrivesExactlyOneSharedGuardRefreshAndRetries()
    {
        int attempt = 0;
        var invoker = new FakeCallInvoker(handleValidate: _ =>
        {
            attempt++;
            if (attempt == 1)
            {
                throw new RpcException(new Status(StatusCode.Unauthenticated, "expired"));
            }
            return new ValidateTokenResponse { Valid = true, TokenType = "Bearer" };
        });
        using var refresh = new RefreshCounter();
        TokenGrpcClient client = BuildClient(invoker, tokenAccessor: () => CallerToken, guard: refresh.Guard);

        TokenValidation result = await client.ValidateTokenAsync(Sensitive.Of("t"));

        Assert.True(result.Valid);
        Assert.Equal(2, attempt);
        Assert.Equal(1, refresh.Count);
    }

    // ---- Helpers -------------------------------------------------------------------

    private static RefreshGuard s_unexpectedRefreshGuard = new(_ => throw new InvalidOperationException("refresh not expected"));

    private static TokenGrpcClient BuildClient(
        FakeCallInvoker fakeInvoker, Func<string?> tokenAccessor, RefreshGuard? guard = null)
    {
        var interceptor = new AuthInterceptor(tokenAccessor, "tenant-1", guard ?? s_unexpectedRefreshGuard);
        CallInvoker invoker = fakeInvoker.Intercept(interceptor);
        return new TokenGrpcClient(invoker, tokenAccessor);
    }

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
                    Sensitive.Of("refreshed-access"), Sensitive.Of("refreshed-refresh"), DateTimeOffset.UtcNow.AddMinutes(15)));
            });
        }

        public void Dispose() => Guard.Dispose();
    }

    private sealed class FakeCallInvoker
    {
        private readonly Func<ValidateTokenRequest, ValidateTokenResponse> _handleValidate;
        private readonly Func<IntrospectTokenRequest, IntrospectTokenResponse> _handleIntrospect;

        public int ValidateCalls { get; private set; }
        public int IntrospectCalls { get; private set; }

        public FakeCallInvoker(
            Func<ValidateTokenRequest, ValidateTokenResponse>? handleValidate = null,
            Func<IntrospectTokenRequest, IntrospectTokenResponse>? handleIntrospect = null)
        {
            _handleValidate = handleValidate ?? (_ => new ValidateTokenResponse { Valid = true, TokenType = "Bearer" });
            _handleIntrospect = handleIntrospect ?? (_ => new IntrospectTokenResponse { Active = true, TokenType = "Bearer" });
        }

        public CallInvoker Intercept(Interceptor interceptor)
        {
            var mock = new Mock<CallInvoker>();

            mock.Setup(m => m.AsyncUnaryCall(
                    It.IsAny<Method<ValidateTokenRequest, ValidateTokenResponse>>(),
                    It.IsAny<string>(),
                    It.IsAny<CallOptions>(),
                    It.IsAny<ValidateTokenRequest>()))
                .Returns((Method<ValidateTokenRequest, ValidateTokenResponse> _, string _, CallOptions _, ValidateTokenRequest request) =>
                {
                    ValidateCalls++;
                    return RunUnary(() => _handleValidate(request));
                });

            mock.Setup(m => m.AsyncUnaryCall(
                    It.IsAny<Method<IntrospectTokenRequest, IntrospectTokenResponse>>(),
                    It.IsAny<string>(),
                    It.IsAny<CallOptions>(),
                    It.IsAny<IntrospectTokenRequest>()))
                .Returns((Method<IntrospectTokenRequest, IntrospectTokenResponse> _, string _, CallOptions _, IntrospectTokenRequest request) =>
                {
                    IntrospectCalls++;
                    return RunUnary(() => _handleIntrospect(request));
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
