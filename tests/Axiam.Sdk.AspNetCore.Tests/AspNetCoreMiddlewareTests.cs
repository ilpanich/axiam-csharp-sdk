using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.AspNetCore.Tests.Fixtures;
using Axiam.Sdk.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Axiam.Sdk.AspNetCore.Tests;

/// <summary>
/// SC#3 integration test: proves <see cref="AxiamAuthMiddleware"/> +
/// <see cref="AxiamPolicyHandler"/> protect real ASP.NET Core 8+ endpoints through the
/// actual authentication/authorization pipeline (<see cref="TestServer"/>, not a unit
/// stub) — no-token 401, valid-token 200 with a populated
/// <see cref="System.Security.Claims.ClaimsPrincipal"/>, wrong-tenant-token 401,
/// policy-deny 403, policy-allow 200.
/// </summary>
[Trait("Category", "Integration")]
public sealed class AspNetCoreMiddlewareTests
{
    private const string TenantId = "acme-tenant";
    private const string OtherTenantId = "other-tenant";
    private static readonly Uri BaseUrl = new("https://axiam.test");

    [Fact]
    public async Task NoToken_ProtectedEndpoint_Returns401()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ValidToken_CorrectTenant_ProtectedEndpoint_Returns200_WithClaimsPrincipal()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string userId = Guid.NewGuid().ToString();
        string token = fixture.SignJwt(userId, TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(userId, body); // proves a real ClaimsPrincipal (user_id claim) was injected
    }

    [Fact]
    public async Task WrongTenantToken_ProtectedEndpoint_Returns401()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        // Signature-valid, but for a DIFFERENT tenant than the app is configured for —
        // proves the mandatory post-signature tenant_id check (Pitfall 3).
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), OtherTenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ValidToken_PolicyDeny_Returns403()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { AllowAccess = false };
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "viewer" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync($"/documents/{Guid.NewGuid()}").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ValidToken_PolicyAllow_Returns200()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { AllowAccess = true };
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync($"/documents/{Guid.NewGuid()}").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ValidToken_LegacyPolicy_MissingRouteId_Returns400()
    {
        // The legacy "resource:action" policy string form is funneled through the same
        // AxiamPolicyHandler as the new attribute — proves the Guid.Empty fallback
        // removal (CONTRACT.md §11.2.3) applies uniformly, not just to the new form.
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/documents-no-id").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("invalid_request", body);
    }

    // --- CONTRACT.md §11 AxiamAccessAttribute matrix ---

    [Fact]
    public async Task AxiamAccessAttribute_Allow_Returns200()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { AllowAccess = true };
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync($"/attr-documents/{Guid.NewGuid()}").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task AxiamAccessAttribute_Deny_Returns403()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { AllowAccess = false };
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "viewer" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync($"/attr-documents/{Guid.NewGuid()}").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("authorization_denied", body);
    }

    [Fact]
    public async Task AxiamAccessAttribute_NoToken_Returns401()
    {
        // §11.2.1: require_access never performs its own token extraction — an
        // unauthenticated request 401s exactly like a bare [Authorize] endpoint.
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage response = await client.GetAsync($"/attr-documents/{Guid.NewGuid()}").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AxiamAccessAttribute_MissingRouteParam_Returns400()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/attr-documents-missing").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("invalid_request", body);
    }

    [Fact]
    public async Task AxiamAccessAttribute_NonUuidRouteValue_Returns400()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/attr-documents-nonguid/not-a-guid").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("invalid_request", body);
    }

    [Fact]
    public async Task AxiamAccessAttribute_ScopeAndSubjectId_AssertedOnWire()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { AllowAccess = true };
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string userId = Guid.NewGuid().ToString();
        string token = fixture.SignJwt(userId, TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        Guid docId = Guid.NewGuid();

        HttpResponseMessage response = await client.GetAsync($"/attr-documents/{docId}").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(serverHandler.LastCheckAccessRequestBody);
        JsonElement wire = serverHandler.LastCheckAccessRequestBody!.Value;
        // action = "<resource>:<action>" — CONTRACT.md §11.1's "documents"/"read" example.
        Assert.Equal("documents:read", wire.GetProperty("action").GetString());
        Assert.Equal(docId, wire.GetProperty("resource_id").GetGuid());
        Assert.Equal("team-a", wire.GetProperty("scope").GetString());
        // §11.2.2: subject_id is the REQUEST's authenticated user, never the shared
        // client's own (service-account) identity.
        Assert.Equal(Guid.Parse(userId), wire.GetProperty("subject_id").GetGuid());
    }

    [Fact]
    public async Task AxiamAccessAttribute_NetworkErrorDuringCheck_Returns503()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { ThrowNetworkErrorOnCheckAccess = true };
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync($"/attr-documents/{Guid.NewGuid()}").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("authz_unavailable", body);
    }

    // --- CSRF cookie double-submit (CR: java/spring-disabled-csrf-protection, C# analog) ---

    [Fact]
    public async Task CookieAuth_StateChangingPost_WithoutCsrfHeader_Returns403()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/protected");
        request.Headers.Add("Cookie", $"axiam_access={token}; axiam_csrf=csrf-abc");
        // No X-CSRF-Token header attached.

        HttpResponseMessage response = await client.SendAsync(request).ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task CookieAuth_StateChangingPost_WithMatchingCsrfHeader_Returns200()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string userId = Guid.NewGuid().ToString();
        string token = fixture.SignJwt(userId, TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/protected");
        request.Headers.Add("Cookie", $"axiam_access={token}; axiam_csrf=csrf-abc");
        request.Headers.Add("X-CSRF-Token", "csrf-abc");

        HttpResponseMessage response = await client.SendAsync(request).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(userId, body);
    }

    [Fact]
    public async Task BearerAuth_StateChangingPost_WithoutCsrfHeader_Returns200()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string userId = Guid.NewGuid().ToString();
        string token = fixture.SignJwt(userId, TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        // No CSRF cookie/header at all — a Bearer-header request is CSRF-immune by
        // construction (a cross-site attacker cannot set custom headers).

        HttpResponseMessage response = await client.SendAsync(request).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(userId, body);
    }

    [Fact]
    public async Task CookieAuth_Get_WithoutCsrfHeader_Returns200()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string userId = Guid.NewGuid().ToString();
        string token = fixture.SignJwt(userId, TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));

        using var request = new HttpRequestMessage(HttpMethod.Get, "/protected");
        request.Headers.Add("Cookie", $"axiam_access={token}");
        // No CSRF cookie/header — a safe method must not require one.

        HttpResponseMessage response = await client.SendAsync(request).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(userId, body);
    }

    /// <summary>
    /// Builds an in-memory ASP.NET Core 8+ host (<see cref="TestServer"/>) wiring
    /// <c>AddAxiamAspNetCore</c>, <c>UseMiddleware&lt;AxiamAuthMiddleware&gt;()</c>, an
    /// <c>[Authorize]</c>-equivalent ("/protected") endpoint, an
    /// <c>[Authorize(Policy="documents:read")]</c>-equivalent
    /// ("/documents/{id:guid}") endpoint, and the CONTRACT.md &#167;11
    /// <see cref="AxiamAccessAttribute"/> matrix ("/attr-documents/{docId:guid}" — allow/
    /// deny/scope/subject-id/network-503; "/attr-documents-missing" — no matching route
    /// value, 400; "/attr-documents-nonguid/{docId}" — non-UUID route value, 400). The
    /// shared <see cref="AxiamClient"/> is built via the internal
    /// <c>CreateForTesting</c> test-only seam pointed at <paramref name="serverHandler"/>
    /// instead of a real socket, and registered BEFORE
    /// <c>AddAxiamAspNetCore</c> is called — exercising the D-07 <c>TryAdd*</c>
    /// precedence guarantee (an explicit consumer registration always wins).
    /// </summary>
    private static async Task<IHost> CreateHostAsync(FakeAxiamServerHandler serverHandler)
    {
        AxiamClient fakeClient = AxiamClient.CreateForTesting(
            BaseUrl,
            TenantId,
            new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantId },
            serverHandler);

        IHostBuilder builder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(fakeClient); // registered first — TryAdd* below must not overwrite it
                    services.AddAxiamAspNetCore(options =>
                    {
                        options.BaseUrl = BaseUrl;
                        options.DefaultTenantId = TenantId;
                    });
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseMiddleware<AxiamAuthMiddleware>();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/protected", async context =>
                        {
                            string? userId = context.User.FindFirst("user_id")?.Value;
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync(userId ?? string.Empty).ConfigureAwait(false);
                        }).RequireAuthorization();

                        // Legacy "resource:action" policy-string form (kept working —
                        // §11 is purely additive). Now requires a resolvable "id" route
                        // value: the Guid.Empty fallback this handler used to apply for a
                        // missing route value was removed (CONTRACT.md §11.2.3).
                        endpoints.MapGet("/documents/{id:guid}", async context =>
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync("ok").ConfigureAwait(false);
                        }).RequireAuthorization("documents:read");

                        // Same legacy policy, but the route carries no "id" value at all
                        // — proves the 400 invalid_request path applies to the legacy
                        // form too, not just the new attribute.
                        endpoints.MapGet("/documents-no-id", async context =>
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync("ok").ConfigureAwait(false);
                        }).RequireAuthorization("documents:read");

                        // CONTRACT.md §11 AxiamAccessAttribute matrix — a real declarative
                        // [AxiamAccess(...)]-equivalent, exercised via RequireAuthorization
                        // (IAuthorizeData) exactly as ASP.NET Core would combine an
                        // attribute placed on a controller action.
                        endpoints.MapGet("/attr-documents/{docId:guid}", async context =>
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync("ok").ConfigureAwait(false);
                        }).RequireAuthorization(new AxiamAccessAttribute("read", "documents")
                        {
                            Scope = "team-a",
                            ResourceRouteParam = "docId",
                        });

                        // Attribute references a route value name ("docId") this route
                        // never defines at all — missing route value, 400.
                        endpoints.MapGet("/attr-documents-missing", async context =>
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync("ok").ConfigureAwait(false);
                        }).RequireAuthorization(new AxiamAccessAttribute("read", "documents")
                        {
                            ResourceRouteParam = "docId",
                        });

                        // Route value is present but not a UUID — unparseable, 400.
                        endpoints.MapGet("/attr-documents-nonguid/{docId}", async context =>
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync("ok").ConfigureAwait(false);
                        }).RequireAuthorization(new AxiamAccessAttribute("read", "documents")
                        {
                            ResourceRouteParam = "docId",
                        });

                        endpoints.MapPost("/protected", async context =>
                        {
                            string? userId = context.User.FindFirst("user_id")?.Value;
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync(userId ?? string.Empty).ConfigureAwait(false);
                        }).RequireAuthorization();
                    });
                });
            });

        return await builder.StartAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Fake AXIAM server transport: serves the JWKS document at
    /// <c>GET /oauth2/jwks</c> (backing <c>AxiamClient.JwksVerifier</c>'s local
    /// verification fast path) and a controllable allow/deny decision at
    /// <c>POST /api/v1/authz/check</c> (backing <c>AxiamClient.Authz.CheckAccessAsync</c>),
    /// optionally recording the last request body (for asserting <c>scope</c>/
    /// <c>subject_id</c> on the wire, CONTRACT.md &#167;11.2.2/&#167;11.2.4) or throwing a
    /// transport-level exception (for the &#167;11.2.5 fail-closed 503 path). Never
    /// touches a real socket — plugged in via the internal
    /// <c>AxiamClient.CreateForTesting</c> seam.
    /// </summary>
    private sealed class FakeAxiamServerHandler : HttpMessageHandler
    {
        private readonly string _jwksJson;

        public bool AllowAccess { get; set; } = true;

        /// <summary>When <c>true</c>, throws an <see cref="HttpRequestException"/> for
        /// the <c>POST /api/v1/authz/check</c> call — <c>AuthzRestClient.CheckAccessAsync</c>
        /// maps this to a <see cref="Axiam.Sdk.Core.NetworkError"/>, exercising the
        /// &#167;11.2.5 fail-closed 503 path.</summary>
        public bool ThrowNetworkErrorOnCheckAccess { get; set; }

        /// <summary>The last <c>POST /api/v1/authz/check</c> request body, captured for
        /// wire-level assertions (action/resource_id/scope/subject_id).</summary>
        public JsonElement? LastCheckAccessRequestBody { get; private set; }

        public FakeAxiamServerHandler(string jwksJson) => _jwksJson = jwksJson;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Get && request.RequestUri?.AbsolutePath == "/oauth2/jwks")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(_jwksJson, Encoding.UTF8, "application/json"),
                };
            }

            if (request.Method == HttpMethod.Post && request.RequestUri?.AbsolutePath == "/api/v1/authz/check")
            {
                if (ThrowNetworkErrorOnCheckAccess)
                {
                    throw new HttpRequestException("simulated transport failure");
                }

                if (request.Content is not null)
                {
                    string requestJson = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                    using JsonDocument requestDoc = JsonDocument.Parse(requestJson);
                    LastCheckAccessRequestBody = requestDoc.RootElement.Clone();
                }

                string body = "{\"allowed\":" + (AllowAccess ? "true" : "false") + "}";
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(body, Encoding.UTF8, "application/json"),
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }
}
