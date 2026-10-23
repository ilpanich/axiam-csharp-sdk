using System.Net;
using System.Text;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Options;
using Axiam.Sdk.Core;
using Axiam.Sdk.Rest;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Contract 1.63, CONTRACT.md &#167;6.1 rule 11, &#167;12.1 rule 3 and &#167;14.6 (third paragraph): a jar that holds
/// session cookies, then a device authorization, a device poll and a token request &#8212; neither an
/// <c>axiam_*</c> cookie nor <c>X-CSRF-Token</c> is sent. Against a real TCP server and the real primary
/// handler, because the jar is attached below any handler a test could mount.
/// </summary>
[Trait("Category", "Fast")]
public sealed class Contract163OAuth2NoCookieTests
{
    private static async Task<(DroppingServer Server, HttpClient Client, HttpClientHandler Handler)> Stack()
    {
        var server = new DroppingServer();
        HttpClientHandler handler = AxiamHttpClientFactory.CreatePrimaryHandler(null);
        var auth = new AxiamHttpMessageHandler(
            handler.CookieContainer, server.BaseUri, "acme", new RefreshGuard(_ => throw new InvalidOperationException()))
        {
            InnerHandler = handler,
        };
        var client = new HttpClient(auth, disposeHandler: false) { BaseAddress = server.BaseUri, Timeout = TimeSpan.FromSeconds(20) };
        handler.CookieContainer.Add(server.BaseUri, new Cookie("axiam_access", "session-access"));
        handler.CookieContainer.Add(server.BaseUri, new Cookie("axiam_refresh", "session-refresh"));
        handler.CookieContainer.Add(server.BaseUri, new Cookie("axiam_csrf", "csrf-value"));
        await Task.CompletedTask;
        return (server, client, handler);
    }

    /// <summary>The requests whose full path (query stripped, never a prefix) is <paramref name="path"/>.</summary>
    private static List<WireRequest> OnPath(DroppingServer server, string path) =>
        server.Requests.Where(r => r.Path.Split('?')[0] == path).ToList();

    private static Task<HttpResponseMessage> Post(HttpClient client, string path) =>
        client.PostAsync(path, new FormUrlEncodedContent(new Dictionary<string, string> { ["client_id"] = "c" }));

    /// <summary>An ordinary state-changing call carries the cookies and the CSRF header (positive control); no <c>/oauth2/*</c> request does, in either issuer form.</summary>
    [Fact]
    public async Task NoSessionCookieAndNoCsrfHeaderGoToAnOAuth2Endpoint()
    {
        (DroppingServer server, HttpClient client, HttpClientHandler handler) = await Stack();
        using (server)
        using (client)
        using (handler)
        {
            using (await Post(client, "/api/v1/auth/control"))
            {
            }

            WireRequest control = Assert.Single(server.For("/api/v1/auth/control"));
            Assert.Contains("axiam_access=session-access", control.Headers["cookie"], StringComparison.Ordinal);
            Assert.Equal("csrf-value", control.Headers["x-csrf-token"]);

            string[] paths =
            {
                "/oauth2/device_authorization",
                "/oauth2/token",
                "/oauth2/token?grant_type=urn:ietf:params:oauth:grant-type:device_code",
                "/t/11111111-1111-4111-8111-111111111111/oauth2/token",
            };
            foreach (string path in paths)
            {
                using HttpResponseMessage response = await Post(client, path);
                WireRequest sent = server.Requests.Last(r => r.Path == path.Split('?')[0]);
                Assert.False(sent.Headers.ContainsKey("cookie"), $"{path} carried a Cookie header");
                Assert.False(sent.Headers.ContainsKey("x-csrf-token"), $"{path} carried X-CSRF-Token");
            }

            // The jar itself is untouched: the next ordinary call still carries the session.
            using (await Post(client, "/api/v1/auth/control2"))
            {
            }

            Assert.Contains("axiam_access=session-access", Assert.Single(server.For("/api/v1/auth/control2")).Headers["cookie"], StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// C163-08: the same property through a real <see cref="AxiamClient"/> (its own handler stack and jar), over a
    /// real loopback server whose login sets <c>axiam_access</c> and <c>axiam_csrf</c>: after <c>LoginAsync</c>, the
    /// three <c>/oauth2/*</c> calls carry neither <c>Cookie</c> nor <c>X-CSRF-Token</c>, and a management <c>POST</c>
    /// carries both. Every lookup matches the full path.
    /// </summary>
    [Fact]
    public async Task ARealClientSendsNoCookieOrCsrfToOAuth2AfterALoginButDoesToAManagementWrite()
    {
        using var server = new DroppingServer();
        Uri baseUri = server.BaseUri;
        server.Responder = request => request.Path.Split('?')[0] switch
        {
            "/api/v1/auth/login" => new ServerReply(
                200, "{}", "Set-Cookie: axiam_access=session-access; Path=/", "Set-Cookie: axiam_csrf=csrf-value; Path=/"),
            "/.well-known/openid-configuration" => new ServerReply(200, OidcTestKit.DiscoveryJson(baseUri)),
            "/oauth2/device_authorization" => new ServerReply(200, OidcTestKit.DeviceAuthorizationJson(baseUri)),
            "/oauth2/token" => new ServerReply(200, OidcTestKit.TokenResponseJson("oauth2-access-token")),
            "/api/v1/resources" => new ServerReply(
                200, "{\"id\":\"33333333-3333-3333-3333-333333333333\",\"tenant_id\":\"22222222-2222-2222-2222-222222222222\",\"name\":\"r\",\"resource_type\":\"doc\",\"created_at\":\"2026-01-01T00:00:00Z\",\"updated_at\":\"2026-01-01T00:00:00Z\"}"),
            _ => null,
        };

        using var client = new AxiamClient(baseUri, OidcTestKit.TenantGuid, new AxiamClientOptions
        {
            BaseUrl = baseUri,
            TenantId = OidcTestKit.TenantGuid,
            OidcClientId = OidcTestKit.ClientId,
            OidcClientSecret = OidcTestKit.ClientSecret,
        });

        await client.LoginAsync("alice@example.com", "pw");
        DeviceAuthorization authorization = await client.DeviceAuthorizeAsync(new DeviceAuthorizeParams());
        await client.DevicePollAsync(new DevicePollParams(authorization.DeviceCode));
        await client.LoginClientCredentialsAsync(new LoginClientCredentialsParams());

        foreach (string path in new[] { "/oauth2/device_authorization", "/oauth2/token" })
        {
            Assert.NotEmpty(OnPath(server, path));
            foreach (WireRequest sent in OnPath(server, path))
            {
                Assert.False(sent.Headers.ContainsKey("cookie"), $"{path} carried a Cookie header");
                Assert.False(sent.Headers.ContainsKey("x-csrf-token"), $"{path} carried X-CSRF-Token");
            }
        }

        Assert.Equal(2, OnPath(server, "/oauth2/token").Count);

        // The control: the same client's next state-changing management request carries both.
        try
        {
            await client.Management.Resources.CreateAsync(new CreateResourceRequest { Name = "r", ResourceType = "doc" });
        }
        catch (Exception)
        {
            // the reply's shape is not what is under test; the request that reached the wire is
        }

        WireRequest write = Assert.Single(OnPath(server, "/api/v1/resources"));
        Assert.Contains("axiam_access=session-access", write.Headers["cookie"], StringComparison.Ordinal);
        Assert.Equal("csrf-value", write.Headers["x-csrf-token"]);
    }

    /// <summary>
    /// C163-20: the cookie-less <c>/oauth2/*</c> transport pools. Two device polls (a request the SDK itself
    /// re-sends, &#167;14.2 rule 6) arrive on one connection, not one each, and still carry no cookie.
    /// </summary>
    [Fact]
    public async Task TheCookielessTransportReusesAConnectionForDevicePolls()
    {
        using var server = new DroppingServer();
        Uri baseUri = server.BaseUri;
        server.Responder = request => request.Path.Split('?')[0] switch
        {
            "/.well-known/openid-configuration" => new ServerReply(200, OidcTestKit.DiscoveryJson(baseUri)),
            "/oauth2/token" => new ServerReply(200, OidcTestKit.TokenResponseJson("oauth2-access-token")),
            _ => null,
        };
        using var client = new AxiamClient(baseUri, OidcTestKit.TenantGuid, new AxiamClientOptions
        {
            BaseUrl = baseUri,
            TenantId = OidcTestKit.TenantGuid,
            OidcClientId = OidcTestKit.ClientId,
        });

        var code = Sensitive<string>.Wrap(OidcTestKit.DeviceCode);
        await client.DevicePollAsync(new DevicePollParams(code));
        await client.DevicePollAsync(new DevicePollParams(code));

        List<WireRequest> polls = OnPath(server, "/oauth2/token");
        Assert.Equal(2, polls.Count);
        Assert.Equal(polls[0].ConnectionId, polls[1].ConnectionId);
        Assert.All(polls, p => Assert.False(p.Headers.ContainsKey("cookie")));
    }
}
