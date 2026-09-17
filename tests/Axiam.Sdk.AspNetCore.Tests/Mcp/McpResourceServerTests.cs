using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.AspNetCore.Tests.Fixtures;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Mcp;
using Axiam.Sdk.Options;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Axiam.Sdk.AspNetCore.Tests.Mcp;

/// <summary>
/// CONTRACT.md &#167;28.9 required tests 3, 4 and 5 — the three that need a real ASP.NET
/// Core pipeline — plus the regression &#167;28.9 calls out as mattering more than all
/// five: with <see cref="AxiamOptions.ResourceMetadataUrl"/> unset, nothing about
/// <see cref="AxiamAuthMiddleware"/> or the policy-authorization surface changes.
/// </summary>
[Trait("Category", "Integration")]
public sealed class McpResourceServerTests
{
    private const string TenantId = "acme-tenant";
    private const string Resource = "https://mcp.example.com/mcp";
    private const string OtherResource = "https://other.example.com/mcp";
    private const string MetadataUrl = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
    private const string MetadataPath = "/.well-known/oauth-protected-resource/mcp";
    private static readonly Uri BaseUrl = new("https://axiam.test");

    // ------------------------------------------------------------------
    // Test 3: 401 with the challenge; the document is served unauthenticated.
    // ------------------------------------------------------------------

    [Fact]
    public async Task NoCredential_Returns401_WithVector1Challenge_AndTheUnchangedJsonBody()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler, mcpEnabled: true).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal($"Bearer resource_metadata=\"{MetadataUrl}\"", response.Headers.WwwAuthenticate.ToString());
        Assert.Contains("authentication_failed", body);
        Assert.DoesNotContain("error_description", body);
    }

    [Fact]
    public async Task ExpiredToken_Returns401_WithVector2Challenge_AndTheUnchangedJsonBody()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler, mcpEnabled: true).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignIdToken(new
        {
            sub = Guid.NewGuid().ToString(),
            tenant_id = TenantId,
            aud = Resource,
            exp = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds(),
        });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal($"Bearer error=\"invalid_token\", resource_metadata=\"{MetadataUrl}\"", response.Headers.WwwAuthenticate.ToString());
        Assert.Contains("authentication_failed", body);
        Assert.DoesNotContain("error_description", body);
    }

    [Fact]
    public async Task MetadataDocument_ServedUnauthenticated_WithTheExactBody()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler, mcpEnabled: true).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage response = await client.GetAsync(MetadataPath).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        using JsonDocument parsed = JsonDocument.Parse(body);
        Assert.Equal(Resource, parsed.RootElement.GetProperty("resource").GetString());
        Assert.Equal("https://axiam.example.com", parsed.RootElement.GetProperty("authorization_servers")[0].GetString());
        Assert.Equal("header", parsed.RootElement.GetProperty("bearer_methods_supported")[0].GetString());
    }

    [Fact]
    public async Task MetadataDocument_ReachableEvenWithAGarbageCredentialAttached()
    {
        // §28.3 rule 4: identical for every caller — a caller that happened to attach a
        // stale/garbage bearer token while probing the document must not be 401ed by it.
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler, mcpEnabled: true).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-real-token");

        HttpResponseMessage response = await client.GetAsync(MetadataPath).ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ------------------------------------------------------------------
    // Test 4: 403 insufficient_scope, and the three refusals that carry no header.
    // ------------------------------------------------------------------

    [Fact]
    public async Task NoGrantDenial_OnARouteThatNamedAScope_Returns403_WithInsufficientScopeChallenge()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { ReasonCode = AxiamReasonCode.NoGrant };
        using IHost host = await CreateHostAsync(serverHandler, mcpEnabled: true).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ValidToken(fixture));

        HttpResponseMessage response = await client.GetAsync($"/attr-scoped/{Guid.NewGuid()}").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(
            $"Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"{MetadataUrl}\"",
            response.Headers.WwwAuthenticate.ToString());
        // §28.5 rule 5: the JSON body does not change — insufficient_scope is only in
        // the header.
        Assert.Contains("authorization_denied", body);
    }

    [Fact]
    public async Task DeniedByRuleDenial_OnARouteThatNamedAScope_Returns403_WithNoChallenge()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { ReasonCode = AxiamReasonCode.DeniedByRule };
        using IHost host = await CreateHostAsync(serverHandler, mcpEnabled: true).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ValidToken(fixture));

        HttpResponseMessage response = await client.GetAsync($"/attr-scoped/{Guid.NewGuid()}").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains("WWW-Authenticate"));
    }

    [Fact]
    public async Task AbsentReasonCodeDenial_OnARouteThatNamedAScope_Returns403_WithNoChallenge()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { ReasonCode = null };
        using IHost host = await CreateHostAsync(serverHandler, mcpEnabled: true).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ValidToken(fixture));

        HttpResponseMessage response = await client.GetAsync($"/attr-scoped/{Guid.NewGuid()}").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains("WWW-Authenticate"));
    }

    [Fact]
    public async Task NoGrantDenial_OnARouteWithNoScopeArgument_Returns403_WithNoChallenge()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { ReasonCode = AxiamReasonCode.NoGrant };
        using IHost host = await CreateHostAsync(serverHandler, mcpEnabled: true).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ValidToken(fixture));

        HttpResponseMessage response = await client.GetAsync($"/attr-noscope/{Guid.NewGuid()}").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains("WWW-Authenticate"));
    }

    // ------------------------------------------------------------------
    // Test 5: an `aud` that is not the resource is refused; the matching one is
    // admitted; the configuration negative fails at construction.
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(OtherResource)]
    [InlineData("axiam:user")]
    public async Task TokenWithAWrongAudience_Returns401_WithVector2Challenge(string aud)
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler, mcpEnabled: true).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignIdToken(new
        {
            sub = Guid.NewGuid().ToString(),
            tenant_id = TenantId,
            aud,
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
        });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal($"Bearer error=\"invalid_token\", resource_metadata=\"{MetadataUrl}\"", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task TokenWithTheMatchingAudience_IsAdmitted()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler, mcpEnabled: true).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ValidToken(fixture));

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ResourceMetadataUrlSet_WithoutExpectedAudience_FailsAtConstruction()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());

        // §28.5 rule 2: the invalid configuration is impossible to run, not merely
        // discouraged — the refusal happens building the middleware pipeline, before
        // any request is ever served.
        await Assert.ThrowsAsync<ValidationError>(() => CreateHostAsync(
            serverHandler,
            mcpEnabled: true,
            configureExtra: options => options.ExpectedAudience = null)).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------
    // The regression that matters more than all five (§28.9): with
    // ResourceMetadataUrl unset, every response is byte-for-byte what it was before
    // §28 existed, and carries no WWW-Authenticate header — asserted explicitly,
    // never inferred from the status alone.
    // ------------------------------------------------------------------

    [Fact]
    public async Task ResourceMetadataUrlUnset_NoResponse_EverCarriesAWwwAuthenticateHeader()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { ReasonCode = AxiamReasonCode.NoGrant };
        using IHost host = await CreateHostAsync(serverHandler, mcpEnabled: false).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage noCredential = await client.GetAsync("/protected").ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.Unauthorized, noCredential.StatusCode);
        Assert.False(noCredential.Headers.Contains("WWW-Authenticate"));

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "garbage");
        HttpResponseMessage invalidToken = await client.GetAsync("/protected").ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.Unauthorized, invalidToken.StatusCode);
        Assert.False(invalidToken.Headers.Contains("WWW-Authenticate"));

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15)));
        HttpResponseMessage deniedWithScope = await client.GetAsync($"/attr-scoped/{Guid.NewGuid()}").ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.Forbidden, deniedWithScope.StatusCode);
        Assert.False(deniedWithScope.Headers.Contains("WWW-Authenticate"));

        // The would-be metadata path is not exempted or specially handled at all when
        // §28 is off — it is an ordinary, unregistered route.
        HttpResponseMessage metadataPath = await client.GetAsync(MetadataPath).ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.NotFound, metadataPath.StatusCode);
    }

    // ------------------------------------------------------------------
    // Fixtures.
    // ------------------------------------------------------------------

    private static string ValidToken(JwksFixture fixture) => fixture.SignIdToken(new
    {
        sub = Guid.NewGuid().ToString(),
        tenant_id = TenantId,
        aud = Resource,
        exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
    });

    /// <summary>
    /// Builds an in-memory ASP.NET Core host wiring <c>AddAxiamAspNetCore</c>,
    /// <c>UseMiddleware&lt;AxiamAuthMiddleware&gt;()</c>, <c>ServeProtectedResourceMetadata</c>
    /// (only when <paramref name="mcpEnabled"/>), a bare <c>[Authorize]</c>-equivalent
    /// ("/protected"), and the two <see cref="AxiamAccessAttribute"/> routes §28.5 rule
    /// 5's tests need — one that names a scope ("/attr-scoped/{docId:guid}") and one
    /// that does not ("/attr-noscope/{docId:guid}").
    /// </summary>
    private static async Task<IHost> CreateHostAsync(
        FakeAxiamServerHandler serverHandler,
        bool mcpEnabled,
        Action<AxiamOptions>? configureExtra = null)
    {
        AxiamClient fakeClient = AxiamClient.CreateForTesting(
            BaseUrl,
            TenantId,
            new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantId, ExpectedAudience = mcpEnabled ? Resource : null },
            serverHandler);

        ProtectedResourceMetadata? metadata = mcpEnabled
            ? AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
            {
                Resource = Resource,
                AuthorizationServers = new[] { "https://axiam.example.com" },
                ScopesSupported = new[] { "mcp:read", "mcp:tools" },
            })
            : null;

        IHostBuilder builder = new HostBuilder()
            .ConfigureWebHost(webHost =>
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
                        if (mcpEnabled)
                        {
                            options.ExpectedAudience = Resource;
                            options.ResourceMetadataUrl = MetadataUrl;
                        }
                        configureExtra?.Invoke(options);
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
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync("ok").ConfigureAwait(false);
                        }).RequireAuthorization();

                        endpoints.MapGet("/attr-scoped/{docId:guid}", async context =>
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync("ok").ConfigureAwait(false);
                        }).RequireAuthorization(new AxiamAccessAttribute("tools", "mcp")
                        {
                            Scope = "mcp:tools",
                            ResourceRouteParam = "docId",
                        });

                        endpoints.MapGet("/attr-noscope/{docId:guid}", async context =>
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync("ok").ConfigureAwait(false);
                        }).RequireAuthorization(new AxiamAccessAttribute("tools", "mcp")
                        {
                            ResourceRouteParam = "docId",
                        });

                        if (metadata is not null)
                        {
                            endpoints.ServeProtectedResourceMetadata(metadata);
                        }
                    });
                });
            });

        return await builder.StartAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Fake AXIAM server transport, mirroring <c>AspNetCoreMiddlewareTests</c>'s own —
    /// duplicated rather than shared across test files, since it is a private nested
    /// type there. Serves the JWKS document and a controllable
    /// <c>allowed</c>/<c>reason_code</c> decision at <c>POST /api/v1/authz/check</c>.
    /// </summary>
    private sealed class FakeAxiamServerHandler : HttpMessageHandler
    {
        private readonly string _jwksJson;

        public bool AllowAccess { get; set; }

        /// <summary>The <c>reason_code</c> the fake check-access response carries on a
        /// denial. <c>null</c> omits the field entirely (an older-server shape).</summary>
        public string? ReasonCode { get; set; }

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
                string reasonCodeJson = ReasonCode is null ? string.Empty : $",\"reason_code\":\"{ReasonCode}\"";
                string body = $$"""{"allowed":{{(AllowAccess ? "true" : "false")}}{{reasonCodeJson}}}""";
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(body, Encoding.UTF8, "application/json"),
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }
}
