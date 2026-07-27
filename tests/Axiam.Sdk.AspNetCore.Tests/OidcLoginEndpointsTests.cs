using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.AspNetCore.Tests.Fixtures;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Options;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Axiam.Sdk.AspNetCore.Tests;

/// <summary>
/// Integration test (real <see cref="TestServer"/>, not a unit stub) for
/// <see cref="OidcLoginEndpointExtensions.MapAxiamOidcLogin"/> — CONTRACT.md &#167;12's
/// "Login with AXIAM" ASP.NET Core glue: the login-redirect endpoint, the callback
/// endpoint's full failure-mapping matrix (&#167;12 T1 reference judgment call 19), and the
/// state-store round trip that links the two requests of the flow.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OidcLoginEndpointsTests
{
    private const string TenantId = "22222222-2222-2222-2222-222222222222";
    private const string ClientId = "test-relying-party";
    private const string CallbackUrl = "https://app.example/login/axiam/callback";
    private static readonly Uri BaseUrl = new("https://axiam.test");

    [Fact]
    public async Task Login_RedirectsToAuthorizationUrl_AndSavesState()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeOidcServerHandler(fixture);
        var store = new MemoryOidcStateStore();
        using IHost host = await CreateHostAsync(serverHandler, store).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage response = await client.GetAsync("/login/axiam?return_to=/dashboard", HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Uri location = response.Headers.Location!;
        Assert.StartsWith("https://axiam.test/oauth2/authorize", location.ToString());
        Assert.Contains("client_id=" + ClientId, location.ToString());
        Assert.Equal(1, store.Size);
    }

    [Fact]
    public async Task Login_DiscoveryUnavailable_Returns503()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeOidcServerHandler(fixture) { DiscoveryUnavailable = true };
        var store = new MemoryOidcStateStore();
        using IHost host = await CreateHostAsync(serverHandler, store).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage response = await client.GetAsync("/login/axiam").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("oidc_unavailable", body);
    }

    [Fact]
    public async Task Callback_IdpError_Returns401()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeOidcServerHandler(fixture);
        var store = new MemoryOidcStateStore();
        using IHost host = await CreateHostAsync(serverHandler, store).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage response = await client.GetAsync("/login/axiam/callback?error=access_denied&error_description=user+cancelled").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("authentication_failed", body);
    }

    [Fact]
    public async Task Callback_MissingStateOrCode_Returns400()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeOidcServerHandler(fixture);
        var store = new MemoryOidcStateStore();
        using IHost host = await CreateHostAsync(serverHandler, store).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage response = await client.GetAsync("/login/axiam/callback?state=only-state").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("invalid_request", body);
    }

    [Fact]
    public async Task Callback_UnknownState_Returns401()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeOidcServerHandler(fixture);
        var store = new MemoryOidcStateStore();
        using IHost host = await CreateHostAsync(serverHandler, store).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage response = await client.GetAsync("/login/axiam/callback?state=never-issued&code=abc").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("authentication_failed", body);
    }

    [Fact]
    public async Task Callback_HappyPath_ExchangesCode_AndReturnsJsonSummary()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeOidcServerHandler(fixture);
        var store = new MemoryOidcStateStore();
        using IHost host = await CreateHostAsync(serverHandler, store).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage loginResponse = await client.GetAsync("/login/axiam", HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        string authorizeUrl = loginResponse.Headers.Location!.ToString();
        string state = ExtractQueryParam(authorizeUrl, "state");
        string nonce = ExtractQueryParam(authorizeUrl, "nonce");
        serverHandler.NextIdTokenNonce = nonce;

        HttpResponseMessage callbackResponse = await client.GetAsync($"/login/axiam/callback?state={state}&code=auth-code-1").ConfigureAwait(false);
        JsonElement body = JsonDocument.Parse(await callbackResponse.Content.ReadAsStringAsync()).RootElement;

        Assert.Equal(HttpStatusCode.OK, callbackResponse.StatusCode);
        Assert.True(body.GetProperty("authenticated").GetBoolean());
        Assert.Equal("user-1", body.GetProperty("sub").GetString());
        // Single-use: a replay of the same callback must now fail.
        HttpResponseMessage replay = await client.GetAsync($"/login/axiam/callback?state={state}&code=auth-code-1").ConfigureAwait(false);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task Callback_HappyPath_RedirectsToReturnTo_WhenCaptured()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeOidcServerHandler(fixture);
        var store = new MemoryOidcStateStore();
        using IHost host = await CreateHostAsync(serverHandler, store).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage loginResponse = await client.GetAsync("/login/axiam?return_to=/dashboard", HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        string authorizeUrl = loginResponse.Headers.Location!.ToString();
        string state = ExtractQueryParam(authorizeUrl, "state");
        serverHandler.NextIdTokenNonce = ExtractQueryParam(authorizeUrl, "nonce");

        HttpResponseMessage callbackResponse = await client.GetAsync(
            $"/login/axiam/callback?state={state}&code=auth-code-1",
            HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/dashboard", callbackResponse.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Callback_OnSuccessHook_IsInvokedWithTokensAndEntry()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeOidcServerHandler(fixture);
        var store = new MemoryOidcStateStore();
        OidcTokenSet? capturedTokens = null;
        OidcStateEntry? capturedEntry = null;
        using IHost host = await CreateHostAsync(serverHandler, store, options =>
        {
            options.OnSuccessAsync = (context, tokens, entry, ct) =>
            {
                capturedTokens = tokens;
                capturedEntry = entry;
                return Task.CompletedTask;
            };
        }).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage loginResponse = await client.GetAsync("/login/axiam", HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        string authorizeUrl = loginResponse.Headers.Location!.ToString();
        string state = ExtractQueryParam(authorizeUrl, "state");
        serverHandler.NextIdTokenNonce = ExtractQueryParam(authorizeUrl, "nonce");

        await client.GetAsync($"/login/axiam/callback?state={state}&code=auth-code-1").ConfigureAwait(false);

        Assert.NotNull(capturedTokens);
        Assert.NotNull(capturedEntry);
        Assert.Equal("user-1", capturedTokens!.IdClaims!.Sub);
    }

    [Fact]
    public async Task Callback_TokenEndpointNetworkFailure_Returns503()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeOidcServerHandler(fixture);
        var store = new MemoryOidcStateStore();
        using IHost host = await CreateHostAsync(serverHandler, store).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage loginResponse = await client.GetAsync("/login/axiam", HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        string state = ExtractQueryParam(loginResponse.Headers.Location!.ToString(), "state");
        serverHandler.TokenEndpointThrowsNetworkError = true;

        HttpResponseMessage response = await client.GetAsync($"/login/axiam/callback?state={state}&code=auth-code-1").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("oidc_unavailable", body);
    }

    [Fact]
    public async Task Callback_OAuth2ProtocolError_Returns401()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeOidcServerHandler(fixture);
        var store = new MemoryOidcStateStore();
        using IHost host = await CreateHostAsync(serverHandler, store).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage loginResponse = await client.GetAsync("/login/axiam", HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        string state = ExtractQueryParam(loginResponse.Headers.Location!.ToString(), "state");
        serverHandler.TokenEndpointReturnsInvalidGrant = true;

        HttpResponseMessage response = await client.GetAsync($"/login/axiam/callback?state={state}&code=auth-code-1").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("authentication_failed", body);
        Assert.Contains("invalid_grant", body);
    }

    private static string ExtractQueryParam(string url, string name)
    {
        var uri = new Uri(url);
        foreach (string pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] kv = pair.Split('=', 2);
            if (Uri.UnescapeDataString(kv[0]) == name)
            {
                return kv.Length > 1 ? kv[1] : string.Empty;
            }
        }
        throw new InvalidOperationException($"query parameter '{name}' not found in '{url}'");
    }

    private static async Task<IHost> CreateHostAsync(HttpMessageHandler serverHandler, MemoryOidcStateStore store, Action<AxiamOidcLoginOptions>? configureExtra = null)
    {
        AxiamClient fakeClient = AxiamClient.CreateForTesting(
            BaseUrl,
            TenantId,
            new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantId, OidcClientId = ClientId },
            serverHandler);

        IHostBuilder builder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(fakeClient);
                    services.AddSingleton<IOidcStateStore>(store);
                    services.AddAxiam(options =>
                    {
                        options.BaseUrl = BaseUrl;
                        options.DefaultTenantId = TenantId;
                    });
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapAxiamOidcLogin("/login/axiam", "/login/axiam/callback", options =>
                        {
                            options.RedirectUri = CallbackUrl;
                            configureExtra?.Invoke(options);
                        });
                    });
                });
            });

        return await builder.StartAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Fake AXIAM OIDC provider transport: serves discovery, JWKS, and a token endpoint
    /// that mints a real Ed25519-signed <c>id_token</c> matching whatever
    /// <see cref="NextIdTokenNonce"/> the test captured from the login redirect.
    /// </summary>
    private sealed class FakeOidcServerHandler : HttpMessageHandler
    {
        private readonly JwksFixture _fixture;

        public bool DiscoveryUnavailable { get; set; }
        public bool TokenEndpointThrowsNetworkError { get; set; }
        public bool TokenEndpointReturnsInvalidGrant { get; set; }
        public string NextIdTokenNonce { get; set; } = "unused";

        public FakeOidcServerHandler(JwksFixture fixture) => _fixture = fixture;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = request.RequestUri!.AbsolutePath;

            if (path == "/.well-known/openid-configuration")
            {
                if (DiscoveryUnavailable)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
                }
                return Task.FromResult(Json(HttpStatusCode.OK, DiscoveryJson()));
            }

            if (path == "/oauth2/jwks")
            {
                return Task.FromResult(Json(HttpStatusCode.OK, _fixture.BuildJwksDocument()));
            }

            if (path == "/oauth2/token")
            {
                if (TokenEndpointThrowsNetworkError)
                {
                    throw new HttpRequestException("simulated transport failure");
                }
                if (TokenEndpointReturnsInvalidGrant)
                {
                    return Task.FromResult(Json(HttpStatusCode.BadRequest,
                        """{"error":"invalid_grant","error_description":"authorization code is invalid or expired"}"""));
                }

                string idToken = _fixture.SignIdToken(new
                {
                    iss = BaseUrl.ToString().TrimEnd('/'),
                    sub = "user-1",
                    aud = ClientId,
                    exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
                    iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    nonce = NextIdTokenNonce,
                });
                string body = JsonSerializer.Serialize(new
                {
                    access_token = "access-token-1",
                    token_type = "Bearer",
                    expires_in = 900,
                    refresh_token = "refresh-token-1",
                    id_token = idToken,
                });
                return Task.FromResult(Json(HttpStatusCode.OK, body));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static string DiscoveryJson()
        {
            string origin = BaseUrl.ToString().TrimEnd('/');
            return JsonSerializer.Serialize(new
            {
                issuer = origin,
                authorization_endpoint = $"{origin}/oauth2/authorize",
                token_endpoint = $"{origin}/oauth2/token",
                userinfo_endpoint = $"{origin}/oauth2/userinfo",
                jwks_uri = $"{origin}/oauth2/jwks",
                revocation_endpoint = $"{origin}/oauth2/revoke",
                introspection_endpoint = $"{origin}/oauth2/introspect",
                response_types_supported = new[] { "code" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "EdDSA" },
                scopes_supported = new[] { "openid" },
                token_endpoint_auth_methods_supported = new[] { "client_secret_post" },
                claims_supported = new[] { "sub" },
                grant_types_supported = new[] { "authorization_code" },
            });
        }

        private static HttpResponseMessage Json(HttpStatusCode status, string json) =>
            new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }
}
