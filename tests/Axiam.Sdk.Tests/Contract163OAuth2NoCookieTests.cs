using System.Net;
using System.Text;
using Axiam.Sdk.Auth;
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
}
