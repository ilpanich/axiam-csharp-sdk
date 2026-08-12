using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.AspNetCore.Tests.Fixtures;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
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
/// The &#167;20.3 emit half, wired into the &#167;11 policy handler.
/// </summary>
/// <remarks>
/// Everything asserted here is about the <i>deny</i> path, because that is the only
/// path that mints anything:
/// <list type="number">
///   <item>A denial with a challenger registered mints exactly one ticket and emits it.</item>
///   <item>An allow mints nothing — a handler that minted on the happy path would put a
///     Protection API call in front of every authorized request.</item>
///   <item>A minting failure still denies, without a challenge. An outage must not turn
///     a deny into a 503, and must never turn it into an allow.</item>
/// </list>
/// </remarks>
[Trait("Category", "Integration")]
public sealed class UmaChallengeTests
{
    private const string TenantId = "acme-tenant";
    private const string Pat = "pat-token-value";
    private const string Ticket = "ticket-value";
    private static readonly Uri BaseUrl = new("https://axiam.test");

    [Fact]
    public async Task Denial_MintsOneTicket_AndEmitsTheChallenge()
    {
        var fixture = new JwksFixture();
        var server = new UmaServerHandler(fixture.BuildJwksDocument()) { AllowAccess = false };
        using IHost host = await CreateHostAsync(server, WithChallenger).ConfigureAwait(false);

        HttpResponseMessage response = await GetDocumentAsync(host, fixture).ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(1, server.PermCalls);

        // The emitted header is the one this SDK's own parser consumes — the round
        // trip is the point of shipping both halves.
        Assert.True(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? values));
        UmaChallenge? parsed = UmaChallenge.Parse(string.Join(", ", values!));
        Assert.NotNull(parsed);
        Assert.Equal("invoices", parsed!.Realm);
        Assert.Equal("https://id.example", parsed.AsUri);
        Assert.NotNull(parsed.Ticket);
    }

    [Fact]
    public async Task TheTicket_AsksForTheActionThatWasRefused()
    {
        var fixture = new JwksFixture();
        var server = new UmaServerHandler(fixture.BuildJwksDocument()) { AllowAccess = false };
        using IHost host = await CreateHostAsync(server, WithChallenger).ConfigureAwait(false);

        await GetDocumentAsync(host, fixture).ConfigureAwait(false);

        // §20.2: the UMA scope is the AXIAM *action*. Asking for anything else would
        // mint a ticket for authority other than the one just refused — and would step
        // outside the grants the engine evaluated, deny rules included.
        JsonElement body = Assert.IsType<JsonElement>(server.LastPermRequestBody!);
        JsonElement first = body[0];
        Assert.Equal("documents:read", first.GetProperty("resource_scopes")[0].GetString());
        Assert.Equal(DocumentId.ToString(), first.GetProperty("resource_id").GetString());
    }

    [Fact]
    public async Task AnAllow_MintsNothing()
    {
        var fixture = new JwksFixture();
        var server = new UmaServerHandler(fixture.BuildJwksDocument()) { AllowAccess = true };
        using IHost host = await CreateHostAsync(server, WithChallenger).ConfigureAwait(false);

        HttpResponseMessage response = await GetDocumentAsync(host, fixture).ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // Minting on the happy path would put a Protection API call — and a live
        // credential — in front of every authorized request.
        Assert.Equal(0, server.PermCalls);
        Assert.False(response.Headers.Contains("WWW-Authenticate"));
    }

    [Fact]
    public async Task AMintingFailure_StillDenies_WithoutAChallenge()
    {
        var fixture = new JwksFixture();
        var server = new UmaServerHandler(fixture.BuildJwksDocument())
        {
            AllowAccess = false,
            PermStatusCode = HttpStatusCode.InternalServerError,
        };
        using IHost host = await CreateHostAsync(server, WithChallenger).ConfigureAwait(false);

        HttpResponseMessage response = await GetDocumentAsync(host, fixture).ConfigureAwait(false);

        // Failure is not escalation: the caller was going to be refused, and a
        // Protection API outage must not turn that into a 503 — nor, far worse, into
        // an allow.
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains("WWW-Authenticate"));
        Assert.True(server.PermCalls >= 1);
    }

    [Fact]
    public async Task WithoutAChallenger_ADenialIsThePlain403()
    {
        var fixture = new JwksFixture();
        var server = new UmaServerHandler(fixture.BuildJwksDocument()) { AllowAccess = false };
        using IHost host = await CreateHostAsync(server, _ => { }).ConfigureAwait(false);

        HttpResponseMessage response = await GetDocumentAsync(host, fixture).ConfigureAwait(false);

        // Opt-in means opt-in: an application that never asked for UMA semantics gets
        // no Protection API traffic from its guards.
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains("WWW-Authenticate"));
        Assert.Equal(0, server.PermCalls);
    }

    [Fact]
    public void TheChallenger_NeverRendersItsPat()
    {
        // §7: a challenger is configuration an application may reasonably log, and the
        // PAT inside it is not.
        string rendered = Challenger().ToString();

        Assert.DoesNotContain(Pat, rendered, StringComparison.Ordinal);
        Assert.Contains("invoices", rendered, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AServerIssued403OnTheCheck_AlsoCarriesAChallenge()
    {
        // §11.2.5 maps a server-issued 403 on the check call itself to the same deny
        // outcome as an allowed=false body. It is the same refusal, so it is answerable
        // with the same ticket — the two deny paths must not disagree about that.
        var fixture = new JwksFixture();
        var server = new UmaServerHandler(fixture.BuildJwksDocument())
        {
            CheckStatusCode = HttpStatusCode.Forbidden,
        };
        using IHost host = await CreateHostAsync(server, WithChallenger).ConfigureAwait(false);

        HttpResponseMessage response = await GetDocumentAsync(host, fixture).ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(1, server.PermCalls);
        Assert.True(response.Headers.Contains("WWW-Authenticate"));
    }

    [Fact]
    public async Task AnExpiredPat_DeniesWithoutAChallenge()
    {
        // 401 from the Protection API — the PAT itself is no longer good. The classic
        // way this fails in production, and the one most tempting to surface as a 500.
        var fixture = new JwksFixture();
        var server = new UmaServerHandler(fixture.BuildJwksDocument())
        {
            AllowAccess = false,
            PermStatusCode = HttpStatusCode.Unauthorized,
        };
        using IHost host = await CreateHostAsync(server, WithChallenger).ConfigureAwait(false);

        HttpResponseMessage response = await GetDocumentAsync(host, fixture).ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains("WWW-Authenticate"));
    }

    [Fact]
    public async Task APatWithoutTheProtectionScope_DeniesWithoutAChallenge()
    {
        // 403 from the Protection API — a token that authenticates but is not a PAT
        // (wrong subject kind, or missing uma_protection). §20.2 rule 1's failure mode.
        var fixture = new JwksFixture();
        var server = new UmaServerHandler(fixture.BuildJwksDocument())
        {
            AllowAccess = false,
            PermStatusCode = HttpStatusCode.Forbidden,
        };
        using IHost host = await CreateHostAsync(server, WithChallenger).ConfigureAwait(false);

        HttpResponseMessage response = await GetDocumentAsync(host, fixture).ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains("WWW-Authenticate"));
    }

    private static readonly Guid DocumentId = Guid.Parse("33333333-3333-3333-3333-333333333333");

    private static UmaChallenger Challenger() =>
        new("invoices", "https://id.example", Sensitive<string>.Wrap(Pat));

    private static void WithChallenger(IServiceCollection services) =>
        services.AddAxiamUmaChallenge(Challenger());

    private static async Task<HttpResponseMessage> GetDocumentAsync(IHost host, JwksFixture fixture)
    {
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(
            Guid.NewGuid().ToString(), TenantId, new[] { "reader" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.GetAsync($"/documents/{DocumentId}").ConfigureAwait(false);
    }

    private static async Task<IHost> CreateHostAsync(UmaServerHandler serverHandler, Action<IServiceCollection> extraServices)
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
                    services.AddSingleton(fakeClient);
                    services.AddAxiamAspNetCore(options =>
                    {
                        options.BaseUrl = BaseUrl;
                        options.DefaultTenantId = TenantId;
                    });
                    extraServices(services);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseMiddleware<AxiamAuthMiddleware>();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/documents/{id:guid}", async context =>
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync("ok").ConfigureAwait(false);
                        }).RequireAuthorization("documents:read");
                    });
                });
            });

        IHost host = await builder.StartAsync().ConfigureAwait(false);
        return host;
    }

    /// <summary>
    /// A fake AXIAM server answering JWKS, the authz check, and the Protection API's
    /// permission endpoint, recording what the latter was asked for.
    /// </summary>
    private sealed class UmaServerHandler : HttpMessageHandler
    {
        private readonly string _jwksJson;

        public UmaServerHandler(string jwksJson) => _jwksJson = jwksJson;

        public bool AllowAccess { get; set; } = true;

        /// <summary>When set, <c>POST /api/v1/authz/check</c> answers with this instead of a verdict.</summary>
        public HttpStatusCode? CheckStatusCode { get; set; }

        /// <summary>When set, <c>POST /uma2/perm</c> answers with this instead of minting.</summary>
        public HttpStatusCode? PermStatusCode { get; set; }

        public int PermCalls { get; private set; }

        public JsonElement? LastPermRequestBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = request.RequestUri?.AbsolutePath ?? string.Empty;

            if (request.Method == HttpMethod.Get && path == "/oauth2/jwks")
            {
                return Json(HttpStatusCode.OK, _jwksJson);
            }

            if (request.Method == HttpMethod.Post && path == "/uma2/perm")
            {
                PermCalls++;
                if (request.Content is not null)
                {
                    string requestJson = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                    using JsonDocument requestDoc = JsonDocument.Parse(requestJson);
                    LastPermRequestBody = requestDoc.RootElement.Clone();
                }

                return PermStatusCode is HttpStatusCode failure
                    ? Json(failure, "{\"error\":\"server_error\"}")
                    : Json(HttpStatusCode.Created, "{\"ticket\":\"" + Ticket + "\"}");
            }

            if (request.Method == HttpMethod.Post && path == "/api/v1/authz/check")
            {
                return CheckStatusCode is HttpStatusCode checkFailure
                    ? Json(checkFailure, "{\"error\":\"forbidden\",\"message\":\"simulated\"}")
                    : Json(HttpStatusCode.OK, "{\"allowed\":" + (AllowAccess ? "true" : "false") + "}");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
            new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    }
}
