using System.Net;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// <see cref="AxiamClient.SsoStartAsync"/> / <see cref="AxiamClient.SsoCompleteAsync"/>
/// (CONTRACT.md &#167;12.1 notes 6/7, &#167;5.1, &#167;12 port addendum item 12).
/// </summary>
[Trait("Category", "Fast")]
public class OidcSsoTests
{
    [Fact]
    public async Task SsoStartAsync_UsesClientTenantAndOrg_WhenNotOverridden()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/federation/oidc/start", req => OidcTestKit.JsonOk(
            """{"authorize_url":"https://idp.example/authorize?x=1","state":"fed-state-1","expires_in_secs":600}"""));
        var options = OidcTestKit.Options() with { OrgId = Guid.Parse("33333333-3333-3333-3333-333333333333") };
        AxiamClient client = OidcTestKit.Client(handler, options);

        SsoStartResult result = await client.SsoStartAsync(new SsoStartParams
        {
            FederationConfigId = "44444444-4444-4444-4444-444444444444",
            RedirectUri = "https://app.example/after-sso",
        });

        Assert.Equal("https://idp.example/authorize?x=1", result.AuthorizeUrl);
        Assert.Equal("fed-state-1", result.State);
        Assert.Equal(600, result.ExpiresInSecs);

        var request = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/api/v1/auth/federation/oidc/start");
        string body = await request.Content!.ReadAsStringAsync();
        Assert.Contains(OidcTestKit.TenantGuid, body);
        Assert.Contains("33333333-3333-3333-3333-333333333333", body);
        Assert.Contains("44444444-4444-4444-4444-444444444444", body);
    }

    [Fact]
    public async Task SsoStartAsync_UsesOrgSlugFallback_AndTenantSlugFallback_WhenClientHasNoUuidTenant()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/federation/oidc/start", req => OidcTestKit.JsonOk(
            """{"authorize_url":"https://idp.example/authorize","state":"fed-state-2","expires_in_secs":600}"""));
        // Client constructed with a SLUG tenant and OrgSlug (never OrgId/TenantId UUID) —
        // exercises both self-fallback branches (tenant_slug AND org_slug body fields).
        var options = new AxiamClientOptions { BaseUrl = OidcTestKit.BaseUrl, TenantId = "acme", OidcClientId = OidcTestKit.ClientId, OrgSlug = "acme-org" };
        AxiamClient client = OidcTestKit.Client(handler, options, tenantId: "acme");

        SsoStartResult result = await client.SsoStartAsync(new SsoStartParams
        {
            FederationConfigId = "44444444-4444-4444-4444-444444444444",
            RedirectUri = "https://app.example/after-sso",
        });

        Assert.Equal("fed-state-2", result.State);
        var request = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/api/v1/auth/federation/oidc/start");
        string body = await request.Content!.ReadAsStringAsync();
        Assert.Contains("\"tenant_slug\":\"acme\"", body);
        Assert.Contains("\"org_slug\":\"acme-org\"", body);
    }

    [Fact]
    public async Task SsoStartAsync_NoOrgContext_ThrowsAuthError_WithoutWireCall()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/federation/oidc/start", _ => throw new InvalidOperationException("must not call the wire when org context is unresolvable"));
        // No OrgId/OrgSlug configured anywhere.
        var options = new AxiamClientOptions { BaseUrl = OidcTestKit.BaseUrl, TenantId = OidcTestKit.TenantGuid };
        AxiamClient client = OidcTestKit.Client(handler, options);

        await Assert.ThrowsAsync<AuthError>(() => client.SsoStartAsync(new SsoStartParams
        {
            FederationConfigId = "44444444-4444-4444-4444-444444444444",
            RedirectUri = "https://app.example/after-sso",
        }));
    }

    [Fact]
    public async Task SsoStartAsync_401_FallsThroughToGenericMapping_NeverParsedAsOAuth2Error()
    {
        // §12 port addendum item 12: the federation error body shape is undocumented.
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/federation/oidc/start", _ => OidcTestKit.Empty(HttpStatusCode.Unauthorized));
        var options = OidcTestKit.Options() with { OrgId = Guid.Parse("33333333-3333-3333-3333-333333333333") };
        AxiamClient client = OidcTestKit.Client(handler, options);

        Exception ex = await Assert.ThrowsAsync<AuthError>(() => client.SsoStartAsync(new SsoStartParams
        {
            FederationConfigId = "44444444-4444-4444-4444-444444444444",
            RedirectUri = "https://app.example/after-sso",
        }));

        Assert.IsNotType<OAuthProtocolError>(ex);
    }

    [Fact]
    public async Task SsoCompleteAsync_HappyPath_ReturnsResult_NoIdTokenValidationApplies()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/federation/oidc/callback", req => OidcTestKit.JsonOk(
            """{"user_id":"55555555-5555-5555-5555-555555555555","session_id":"66666666-6666-6666-6666-666666666666","expires_in":900,"redirect_uri":"https://app.example/dashboard"}"""));
        AxiamClient client = OidcTestKit.Client(handler);

        SsoCompleteResult result = await client.SsoCompleteAsync(new SsoCompleteParams { State = "fed-state-1", Code = "fed-code-1" });

        Assert.Equal("55555555-5555-5555-5555-555555555555", result.UserId);
        Assert.Equal("66666666-6666-6666-6666-666666666666", result.SessionId);
        Assert.Equal(900, result.ExpiresIn);
        Assert.Equal("https://app.example/dashboard", result.RedirectUri);
    }

    [Fact]
    public async Task SsoCompleteAsync_NonOkResponse_ThrowsMappedError()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/federation/oidc/callback", _ => OidcTestKit.Empty(HttpStatusCode.Unauthorized));
        AxiamClient client = OidcTestKit.Client(handler);

        await Assert.ThrowsAsync<AuthError>(() => client.SsoCompleteAsync(new SsoCompleteParams { State = "s", Code = "c" }));
    }

    // CONTRACT.md §12.1 rule 12b (contract 1.66): the browser-binding cookie an SsoStartAsync
    // response sets is presented on the following SsoCompleteAsync from the SAME client (one §4
    // jar), and never on a second client's. A REAL HttpListener loopback server and the public
    // constructor's REAL HttpClientHandler/CookieContainer — a fake transport would sit above the
    // layer where the jar attaches cookies and prove nothing (see DeviceAuthTests).
    [Fact]
    public async Task SsoStartBindingCookie_IsPresentedOnSsoComplete_FromSameClientOnly()
    {
        string binding = new('A', 43); // 43 chars, unpadded base64url
        using var listener = new HttpListener();
        string prefix = $"http://127.0.0.1:{GetEphemeralPort()}/";
        listener.Prefixes.Add(prefix);
        listener.Start();

        var completionCookies = new List<string?>();
        var serverTask = Task.Run(async () =>
        {
            for (int i = 0; i < 3; i++)
            {
                HttpListenerContext ctx = await listener.GetContextAsync();
                string body;
                if (ctx.Request.Url!.AbsolutePath == "/api/v1/auth/federation/oidc/start")
                {
                    ctx.Response.AddHeader("Set-Cookie", $"axiam_fed_bind={binding}; Path=/; HttpOnly; SameSite=Strict");
                    body = """{"authorize_url":"https://idp.example/authorize","state":"fed-state-1","expires_in_secs":600}""";
                }
                else
                {
                    completionCookies.Add(ctx.Request.Headers["Cookie"]);
                    body = """{"user_id":"55555555-5555-5555-5555-555555555555","session_id":"66666666-6666-6666-6666-666666666666","expires_in":900,"redirect_uri":"https://app.example/dashboard"}""";
                }

                byte[] bytes = System.Text.Encoding.UTF8.GetBytes(body);
                ctx.Response.ContentType = "application/json";
                ctx.Response.ContentLength64 = bytes.Length;
                await ctx.Response.OutputStream.WriteAsync(bytes);
                ctx.Response.OutputStream.Close();
            }
        });

        try
        {
            var options = new AxiamClientOptions
            {
                BaseUrl = new Uri(prefix),
                TenantId = OidcTestKit.TenantGuid,
                OrgId = Guid.Parse("33333333-3333-3333-3333-333333333333"),
            };
            using var client = new AxiamClient(new Uri(prefix), OidcTestKit.TenantGuid, options);
            using var other = new AxiamClient(new Uri(prefix), OidcTestKit.TenantGuid, options);

            await client.SsoStartAsync(new SsoStartParams
            {
                FederationConfigId = "44444444-4444-4444-4444-444444444444",
                RedirectUri = "https://app.example/after-sso",
            });
            await client.SsoCompleteAsync(new SsoCompleteParams { State = "fed-state-1", Code = "fed-code-1" });
            await other.SsoCompleteAsync(new SsoCompleteParams { State = "fed-state-1", Code = "fed-code-1" });
            await serverTask;

            Assert.Equal(2, completionCookies.Count);
            Assert.True(
                completionCookies[0] is not null && completionCookies[0]!.Contains($"axiam_fed_bind={binding}", StringComparison.Ordinal),
                $"the completion from the starting client must present the binding cookie, got: '{completionCookies[0]}'");
            Assert.True(
                string.IsNullOrEmpty(completionCookies[1]) || !completionCookies[1]!.Contains("axiam_fed_bind", StringComparison.Ordinal),
                $"a second client must not present another client's binding cookie, got: '{completionCookies[1]}'");
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    private static int GetEphemeralPort()
    {
        using var socket = new System.Net.Sockets.Socket(
            System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }
}
