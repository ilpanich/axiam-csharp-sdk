using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Axiam.Sdk;
using Axiam.Sdk.AspNetCore.Tests.Fixtures;
using Axiam.Sdk.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Axiam.Sdk.AspNetCore.Tests;

/// <summary>
/// CONTRACT.md &#167;11 <c>require_role</c> (contract 1.68; audit finding N15): the framework-native
/// <c>[Authorize(Roles = "...")]</c> mapping is decided by the token's <c>roles</c> claim and by
/// nothing else. A client-requested OAuth2 <c>scope</c> is never a role, and a token with no
/// <c>roles</c> claim has none.
/// </summary>
[Trait("Category", "Integration")]
public sealed class RolesClaimGuardTests
{
    private const string TenantId = "acme-tenant";
    private static readonly Uri BaseUrl = new("https://axiam.test");

    private static string Token(JwksFixture fixture, object? roles, string? scope)
    {
        var payload = new Dictionary<string, object?>
        {
            ["sub"] = "user-1",
            ["tenant_id"] = TenantId,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
        };
        if (roles is not null) payload["roles"] = roles;
        if (scope is not null) payload["scope"] = scope;
        return fixture.SignIdToken(payload);
    }

    private static async Task<HttpStatusCode> GetAsync(string recipe)
    {
        var fixture = new JwksFixture();
        using IHost host = await CreateHostAsync(fixture);
        HttpClient client = host.GetTestClient();
        // The token must be signed by the key the host's JWKS serves, so it is minted per host.
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TokenFor(fixture, recipe));
        return (await client.GetAsync("/admin")).StatusCode;
    }

    private static string TokenFor(JwksFixture fixture, string recipe) => recipe switch
    {
        "scope-admin-no-roles" => Token(fixture, roles: null, scope: "openid admin"),
        "roles-admin" => Token(fixture, roles: new[] { "admin" }, scope: "openid"),
        "roles-empty-scope-admin" => Token(fixture, roles: Array.Empty<string>(), scope: "openid admin"),
        "roles-other" => Token(fixture, roles: new[] { "viewer" }, scope: "admin"),
        "roles-capital-admin" => Token(fixture, roles: new[] { "Admin" }, scope: "openid"),
        "roles-string" => Token(fixture, roles: "admin", scope: "openid"),
        _ => throw new ArgumentOutOfRangeException(nameof(recipe)),
    };

    [Fact]
    public async Task AScopeNamedLikeTheRole_WithNoRolesClaim_IsForbidden()
    {
        Assert.Equal(HttpStatusCode.Forbidden, await GetAsync("scope-admin-no-roles"));
    }

    [Fact]
    public async Task AScopeNamedLikeTheRole_WithAnEmptyRolesClaim_IsForbidden()
    {
        Assert.Equal(HttpStatusCode.Forbidden, await GetAsync("roles-empty-scope-admin"));
    }

    [Fact]
    public async Task ARolesClaimWithoutTheRole_IsForbidden_EvenWithAMatchingScope()
    {
        Assert.Equal(HttpStatusCode.Forbidden, await GetAsync("roles-other"));
    }

    [Fact]
    public async Task ARolesClaimHoldingTheRole_IsAllowed_WithoutAMatchingScope()
    {
        Assert.Equal(HttpStatusCode.OK, await GetAsync("roles-admin"));
    }

    [Fact]
    public async Task ARolesClaimHoldingAdmin_IsForbidden_ByRolesAdmin_BecauseRoleNamesAreCaseSensitive()
    {
        // CONTRACT §11.2 rule 11g: role names compare exactly, so "Admin" does not satisfy Roles = "admin".
        Assert.Equal(HttpStatusCode.Forbidden, await GetAsync("roles-capital-admin"));
    }

    [Fact]
    public async Task ARolesClaimThatIsNotAnArray_GrantsNoRole()
    {
        Assert.Equal(HttpStatusCode.Forbidden, await GetAsync("roles-string"));
    }

    private static async Task<IHost> CreateHostAsync(JwksFixture fixture)
    {
        var serverHandler = new JwksOnlyHandler(fixture.BuildJwksDocument());
        AxiamClient fakeClient = AxiamClient.CreateForTesting(
            BaseUrl, TenantId, new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantId }, serverHandler);

        IHostBuilder builder = new HostBuilder().ConfigureWebHost(webHost =>
        {
            webHost.UseTestServer();
            webHost.ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddSingleton(fakeClient);
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
                    endpoints.MapGet("/admin", () => "ok").RequireAuthorization(new AuthorizeAttribute { Roles = "admin" });
                });
            });
        });
        return await builder.StartAsync();
    }

    private sealed class JwksOnlyHandler : HttpMessageHandler
    {
        private readonly string _jwks;
        public JwksOnlyHandler(string jwks) => _jwks = jwks;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(request.RequestUri!.AbsolutePath == "/oauth2/jwks"
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(_jwks, Encoding.UTF8, "application/json") }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
