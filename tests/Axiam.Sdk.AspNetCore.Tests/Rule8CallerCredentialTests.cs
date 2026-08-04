using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.AspNetCore.Tests.Fixtures;
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
/// CONTRACT.md §10.1 rule 8 — "subject of the decision" (SEC-085, §15.3.1).
/// <para>
/// Rules 1-7 ask whether the token is good. Rule 8 asks whether it is the token the
/// decision is even ABOUT. SEC-085 satisfied all seven and was still an authentication
/// bypass: the PHP guard routed a failed verification into a second, successful one
/// against the <em>application's own</em> session, so the caller was admitted as the
/// app's service account — in an IAM integration typically far more privileged than the
/// user whose request it replaced.
/// </para>
/// <para>
/// This SDK carries the structural shape SEC-085 exploited. Unlike the Go/Python guards,
/// which receive a bare verifier, <see cref="AxiamAuthMiddleware"/> is handed a whole
/// <see cref="AxiamClient"/> resolved from DI — a stateful object with a session of its
/// own — and reaches through it to <c>client.JwksVerifier</c>. It is correct today, but
/// nothing pinned that, and the client's own credential sits one property access away.
/// </para>
/// <para>
/// These tests make the substitution genuinely available before asserting it is not
/// taken: a second, fully valid token for a more privileged principal is proven to pass
/// this very pipeline, so a fallback would have succeeded had one existed. Without that
/// precondition the tests could pass merely because nothing was available to substitute,
/// which would prove nothing — the trap the PHP reference test documents at length.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class Rule8CallerCredentialTests
{
    private const string TenantId = "acme-tenant";
    private static readonly Uri BaseUrl = new("https://axiam.test");

    /// <summary>The identity an SEC-085-shaped fallback would silently admit callers as.</summary>
    private const string AppPrincipal = "app-service-account";

    [Fact]
    public async Task FailedCallerToken_IsRejected_EvenWhenAnotherValidTokenExists()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        // Precondition, asserted rather than assumed: the application's own
        // credential really does pass this pipeline, so a substitution would have
        // succeeded.
        string appToken = fixture.SignJwt(
            AppPrincipal, TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", appToken);
        HttpResponseMessage appResponse = await client.GetAsync("/protected").ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.OK, appResponse.StatusCode);

        // The caller's credential: correctly signed, right tenant, expired. It fails
        // rule 2 and nothing else, so the only way to admit it is to decide on a
        // credential the caller never presented.
        string expired = fixture.SignJwt(
            "caller-1", TenantId, new[] { "viewer" }, DateTimeOffset.UtcNow.AddMinutes(-15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", expired);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain(
            AppPrincipal,
            body,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheInjectedIdentity_IsAlwaysTheCallersOwn()
    {
        // The positive half. A guard that preferred an ambient credential would pass
        // the negative test above while still being wrong.
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        string callerId = Guid.NewGuid().ToString();
        string callerToken = fixture.SignJwt(
            callerId, TenantId, new[] { "viewer" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", callerToken);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(callerId, body);
        Assert.NotEqual(AppPrincipal, body);
    }

    [Fact]
    public async Task AGarbageCallerToken_IsRejected_AndInjectsNoIdentity()
    {
        // The consequence that made SEC-085 a bypass rather than a mere error: the
        // request continued carrying an identity. A rejected caller must leave the
        // ClaimsPrincipal empty, not merely unauthenticated.
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "not-a-real-jwt");

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain(AppPrincipal, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AForeignTenantCallerToken_IsRejected()
    {
        // Rule 4's failure mode, asserted here for the rule-8 consequence: a token
        // that is perfectly valid for ANOTHER tenant must not be swapped for one that
        // is valid for this one.
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        string foreign = fixture.SignJwt(
            "caller-1", "other-tenant", new[] { "viewer" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", foreign);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain(AppPrincipal, body, StringComparison.Ordinal);
    }

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
                        endpoints.MapGet("/protected", async context =>
                        {
                            string? userId = context.User.FindFirst("user_id")?.Value;
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync(userId ?? string.Empty).ConfigureAwait(false);
                        }).RequireAuthorization();
                    });
                });
            });

        IHost host = await builder.StartAsync().ConfigureAwait(false);
        return host;
    }
}
