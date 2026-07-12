using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.Core;
using Axiam.Sdk.Grpc;
using Axiam.Sdk.Options;
using Grpc.Core;
using Moq;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Covers <see cref="AxiamGrpcAuthzClient"/>'s public (real-channel) constructor + dispose
/// and the <c>ResolveWireIdentityAsync</c> failure branches (undecodable token, missing
/// <c>tenant_id</c>/<c>sub</c> claims) that throw BEFORE any RPC is issued — so a
/// never-invoked mocked <see cref="CallInvoker"/> suffices for those cases.
/// </summary>
[Trait("Category", "Fast")]
public class GrpcAuthzClientExtraTests
{
    private static readonly Uri BaseUrl = new("https://axiam.test");

    private static string B64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Jwt(object payload)
    {
        string header = B64Url(Encoding.UTF8.GetBytes("""{"alg":"none"}"""));
        string body = B64Url(JsonSerializer.SerializeToUtf8Bytes(payload));
        return $"{header}.{body}.unsigned";
    }

    private static AxiamGrpcAuthzClient ClientWithToken(Func<string?> tokenAccessor) =>
        new(new Mock<CallInvoker>().Object, jwksVerifier: null, tokenAccessor, "tenant-1");

    [Fact]
    public async Task CheckAccessAsync_UndecodableToken_ThrowsAuthError()
    {
        // Not a 3-segment JWT -> unverified decode yields null claims -> AuthError.
        using AxiamGrpcAuthzClient client = ClientWithToken(() => "not-a-jwt");
        await Assert.ThrowsAsync<AuthError>(() => client.CheckAccessAsync("documents:read", "doc-1"));
    }

    [Fact]
    public async Task CheckAccessAsync_TokenMissingTenantIdClaim_ThrowsAuthError()
    {
        using AxiamGrpcAuthzClient client = ClientWithToken(() => Jwt(new { sub = "user-1" }));
        await Assert.ThrowsAsync<AuthError>(() => client.CheckAccessAsync("documents:read", "doc-1"));
    }

    [Fact]
    public async Task CheckAccessAsync_TokenMissingSubClaim_AndNoOverride_ThrowsAuthError()
    {
        using AxiamGrpcAuthzClient client = ClientWithToken(() => Jwt(new { tenant_id = "tenant-1" }));
        await Assert.ThrowsAsync<AuthError>(() => client.CheckAccessAsync("documents:read", "doc-1"));
    }

    [Fact]
    public async Task BatchCheckAsync_NoActiveSession_ThrowsAuthError()
    {
        using AxiamGrpcAuthzClient client = ClientWithToken(() => null);
        await Assert.ThrowsAsync<AuthError>(() =>
            client.BatchCheckAsync(new[] { new AxiamGrpcAuthzClient.AccessCheck("documents:read", "doc-1") }));
    }

    [Fact]
    public async Task CheckAccessAsync_BlankAction_ThrowsArgumentException()
    {
        using AxiamGrpcAuthzClient client = ClientWithToken(() => Jwt(new { tenant_id = "tenant-1", sub = "user-1" }));
        await Assert.ThrowsAsync<ArgumentException>(() => client.CheckAccessAsync("  ", "doc-1"));
    }

    [Fact]
    public async Task BatchCheckAsync_NullChecks_Throws()
    {
        using AxiamGrpcAuthzClient client = ClientWithToken(() => Jwt(new { tenant_id = "tenant-1", sub = "user-1" }));
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.BatchCheckAsync(null!));
    }

    // ---- public (real GrpcChannel) constructor + dispose ----

    [Fact]
    public void PublicConstructor_BuildsOverSharedClientSession_AndDisposesCleanly()
    {
        using AxiamClient rest = BuildRestClient();
        var grpc = new AxiamGrpcAuthzClient(rest);
        grpc.Dispose(); // owns and shuts down the real channel
    }

    [Fact]
    public void PublicConstructor_WithExplicitGrpcTarget_Constructs()
    {
        using AxiamClient rest = BuildRestClient();
        using var grpc = new AxiamGrpcAuthzClient(rest, new Uri("https://grpc.axiam.test:5001"));
        Assert.NotNull(grpc);
    }

    [Fact]
    public void PublicConstructor_NullClient_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new AxiamGrpcAuthzClient(null!));
    }

    private static AxiamClient BuildRestClient()
    {
        var options = new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = "tenant-1" };
        return AxiamClient.CreateForTesting(BaseUrl, "tenant-1", options, new NoopHandler());
    }

    private sealed class NoopHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
    }
}
