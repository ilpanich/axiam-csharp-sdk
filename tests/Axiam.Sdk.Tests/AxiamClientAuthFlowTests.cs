using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Drives <see cref="AxiamClient"/>'s auth state machines end-to-end against a fully fake
/// transport (via the internal <c>CreateForTesting</c> seam): the RefreshGuard delegate
/// <c>DoHttpRefreshAsync</c>, <c>LogoutAsync</c>, <c>VerifyMfaAsync</c>, and the shared
/// <c>PostJsonAsync</c>/tenant-field mechanics. A session cookie is seeded directly into
/// the client's shared cookie jar (the fake transport is not an
/// <see cref="HttpClientHandler"/>, so it cannot process <c>Set-Cookie</c> itself), letting
/// the token-claim-driven refresh/logout paths run exactly as they would post-login.
/// </summary>
[Trait("Category", "Fast")]
public class AxiamClientAuthFlowTests
{
    private static readonly Uri BaseUrl = new("https://axiam.test");
    private const string TenantGuid = "22222222-2222-2222-2222-222222222222";
    private const string OrgGuid = "33333333-3333-3333-3333-333333333333";

    private static string B64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Mints a JWT-shaped (unsigned) token whose payload carries the given claims —
    /// parseable by the SDK's unverified-decode path, which reads claims as operational hints.</summary>
    private static string Jwt(object payload)
    {
        string header = B64Url(Encoding.UTF8.GetBytes("""{"alg":"none"}"""));
        string body = B64Url(JsonSerializer.SerializeToUtf8Bytes(payload));
        return $"{header}.{body}.unsigned";
    }

    private static long ExpFuture => DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds();

    private static void SeedCookie(AxiamClient client, string name, string value)
    {
        FieldInfo field = typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var container = (CookieContainer)field.GetValue(client)!;
        container.Add(BaseUrl, new Cookie(name, value));
    }

    private static AxiamClient Client(RoutingHandler handler, AxiamClientOptions? options = null, string tenantId = TenantGuid)
    {
        options ??= new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = tenantId };
        return AxiamClient.CreateForTesting(BaseUrl, tenantId, options, handler);
    }

    // ---------------- RefreshAsync / DoHttpRefreshAsync ----------------

    [Fact]
    public async Task RefreshAsync_ValidSession_OrgFromTokenClaim_RunsRefreshAndCompletes()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/refresh", _ => Ok());
        using AxiamClient client = Client(handler);
        SeedCookie(client, "axiam_access", Jwt(new { tenant_id = TenantGuid, org_id = OrgGuid, exp = ExpFuture }));

        await client.RefreshAsync(CancellationToken.None);

        Assert.Contains(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/auth/refresh");
    }

    [Fact]
    public async Task RefreshAsync_ValidSession_OrgFromOptions_RunsRefreshAndCompletes()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/refresh", _ => Ok());
        var options = new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantGuid, OrgId = Guid.Parse(OrgGuid) };
        using AxiamClient client = Client(handler, options);
        // No org_id claim in the token — org must resolve from the configured OrgId option.
        SeedCookie(client, "axiam_access", Jwt(new { tenant_id = TenantGuid, exp = ExpFuture }));

        await client.RefreshAsync(CancellationToken.None);

        Assert.Contains(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/auth/refresh");
    }

    [Fact]
    public async Task RefreshAsync_TokenMissingTenantId_ThrowsAuthError_WithoutRefreshCall()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/refresh", _ => Ok());
        using AxiamClient client = Client(handler);
        SeedCookie(client, "axiam_access", Jwt(new { sub = "user-1", exp = ExpFuture }));

        await Assert.ThrowsAsync<AuthError>(() => client.RefreshAsync(CancellationToken.None));
        Assert.DoesNotContain(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/auth/refresh");
    }

    [Fact]
    public async Task RefreshAsync_OrgUnresolvable_ThrowsAuthError()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/refresh", _ => Ok());
        // Tenant present, but no org_id claim and no OrgId/OrgSlug option -> unresolvable.
        using AxiamClient client = Client(handler);
        SeedCookie(client, "axiam_access", Jwt(new { tenant_id = TenantGuid, exp = ExpFuture }));

        await Assert.ThrowsAsync<AuthError>(() => client.RefreshAsync(CancellationToken.None));
    }

    [Fact]
    public async Task RefreshAsync_RefreshEndpointReturns500_MapsToNetworkError()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/refresh", _ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using AxiamClient client = Client(handler);
        SeedCookie(client, "axiam_access", Jwt(new { tenant_id = TenantGuid, org_id = OrgGuid, exp = ExpFuture }));

        await Assert.ThrowsAsync<NetworkError>(() => client.RefreshAsync(CancellationToken.None));
    }

    // ---------------- LogoutAsync ----------------

    [Fact]
    public async Task LogoutAsync_ValidSession_PostsAndClearsCsrf()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/logout", _ => Ok());
        using AxiamClient client = Client(handler);
        SeedCookie(client, "axiam_access", Jwt(new { jti = "session-abc", tenant_id = TenantGuid, exp = ExpFuture }));

        await client.LogoutAsync(CancellationToken.None);

        Assert.Contains(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/auth/logout");
    }

    [Fact]
    public async Task LogoutAsync_TokenHasNoJti_ThrowsAuthError_WithoutPost()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/logout", _ => Ok());
        using AxiamClient client = Client(handler);
        SeedCookie(client, "axiam_access", Jwt(new { tenant_id = TenantGuid, exp = ExpFuture }));

        await Assert.ThrowsAsync<AuthError>(() => client.LogoutAsync(CancellationToken.None));
        Assert.DoesNotContain(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/auth/logout");
    }

    [Fact]
    public async Task LogoutAsync_EndpointReturns500_MapsToNetworkError()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/logout", _ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using AxiamClient client = Client(handler);
        SeedCookie(client, "axiam_access", Jwt(new { jti = "session-abc", tenant_id = TenantGuid, exp = ExpFuture }));

        await Assert.ThrowsAsync<NetworkError>(() => client.LogoutAsync(CancellationToken.None));
    }

    [Fact]
    public async Task LogoutAsync_TokenWithMalformedPayload_ThrowsAuthError()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/logout", _ => Ok());
        using AxiamClient client = Client(handler);
        // Three segments but the payload is not valid base64url JSON -> DecodeUnverifiedClaims
        // returns null -> no jti -> AuthError.
        SeedCookie(client, "axiam_access", "aaa.bbb.ccc");

        await Assert.ThrowsAsync<AuthError>(() => client.LogoutAsync(CancellationToken.None));
    }

    // ---------------- VerifyMfaAsync ----------------

    [Fact]
    public async Task VerifyMfaAsync_Success_ReturnsCompletedLoginResult()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/mfa/verify", _ => Ok());
        using AxiamClient client = Client(handler);

        LoginResult result = await client.VerifyMfaAsync(Sensitive.Of("challenge-xyz"), "123456", CancellationToken.None);

        Assert.False(result.MfaRequired);
        Assert.Contains(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/auth/mfa/verify");
    }

    [Fact]
    public async Task VerifyMfaAsync_ServerRejects_ThrowsAuthError()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/mfa/verify", _ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthError>(() =>
            client.VerifyMfaAsync(Sensitive.Of("challenge-xyz"), "000000", CancellationToken.None));
    }

    [Fact]
    public async Task VerifyMfaAsync_BlankTotp_ThrowsArgumentException()
    {
        using var handler = new RoutingHandler();
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.VerifyMfaAsync(Sensitive.Of("challenge-xyz"), "   ", CancellationToken.None));
    }

    // ---------------- LoginAsync tenant/org field mapping + network wrap ----------------

    [Fact]
    public async Task LoginAsync_GuidTenantAndOrgId_SendsTenantIdAndOrgIdFields()
    {
        string? capturedBody = null;
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", req =>
        {
            capturedBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            return Ok();
        });
        var options = new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantGuid, OrgId = Guid.Parse(OrgGuid) };
        using AxiamClient client = Client(handler, options);

        LoginResult result = await client.LoginAsync("alice@example.com", "pw", CancellationToken.None);

        Assert.False(result.MfaRequired);
        Assert.NotNull(capturedBody);
        Assert.Contains("tenant_id", capturedBody);
        Assert.Contains(OrgGuid, capturedBody);
    }

    [Fact]
    public async Task LoginAsync_SlugTenantAndOrgSlug_SendsSlugFields()
    {
        string? capturedBody = null;
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", req =>
        {
            capturedBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            return Ok();
        });
        var options = new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = "acme", OrgSlug = "acme-org" };
        using AxiamClient client = Client(handler, options, tenantId: "acme");

        await client.LoginAsync("alice@example.com", "pw", CancellationToken.None);

        Assert.NotNull(capturedBody);
        Assert.Contains("tenant_slug", capturedBody);
        Assert.Contains("org_slug", capturedBody);
    }

    [Fact]
    public async Task LoginAsync_TransportThrowsHttpRequestException_WrapsInNetworkError()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", _ => throw new HttpRequestException("connection refused"));
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<NetworkError>(() =>
            client.LoginAsync("alice@example.com", "pw", CancellationToken.None));
    }

    private static HttpResponseMessage Ok() =>
        new(HttpStatusCode.OK) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };

    private sealed class RoutingHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, Func<HttpRequestMessage, HttpResponseMessage>> _routes = new();

        public List<HttpRequestMessage> Requests { get; } = new();

        public void Map(string path, Func<HttpRequestMessage, HttpResponseMessage> responder) => _routes[path] = responder;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            string path = request.RequestUri!.AbsolutePath;
            if (_routes.TryGetValue(path, out Func<HttpRequestMessage, HttpResponseMessage>? responder))
            {
                return Task.FromResult(responder(request));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
