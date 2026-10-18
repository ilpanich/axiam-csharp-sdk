using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Contract 1.62, CONTRACT.md &#167;14.1 (client authentication at both endpoints), &#167;14.2 rule 5 (the
/// poll's <c>401 invalid_client</c>) and &#167;14.6's added tests, against a mocked server.
/// </summary>
/// <remarks>
/// <para>
/// This SDK implements a client secret (<c>client_secret</c> in the form body) and an mTLS client
/// certificate. It has no <c>private_key_jwt</c> client assertion (&#167;21.8) and generates no DPoP
/// proof (&#167;21.7.3), so there is nothing of either to send; the tests say so rather than skip it.
/// </para>
/// <para>
/// Which of <c>client_secret_post</c> and <c>client_secret_basic</c> a client is <i>registered</i> for is
/// the server's fact, not the SDK's: the SDK sends the same form-body secret for both, and
/// <see cref="TheSecretIsInTheBodyWhicheverMethodTheServerAdvertises"/> advertises the second one.
/// </para>
/// </remarks>
[Trait("Category", "Fast")]
public class Contract162DeviceGrantTests
{
    private const string DeviceAuthPath = "/oauth2/device_authorization";
    private const string TokenPath = "/oauth2/token";
    private const string RefreshPath = "/api/v1/auth/refresh";

    private static readonly Uri MtlsBaseUrl = new("https://mtls.axiam.test");

    private static readonly byte[] CertPem = Encoding.ASCII.GetBytes(
        "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKZ0000000000MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n-----END CERTIFICATE-----\n");

    private static readonly byte[] KeyPem = Encoding.ASCII.GetBytes(
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n");

    private static HttpResponseMessage TokenSuccess(string tokenType = "Bearer") =>
        OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("device-access-token", tokenType: tokenType));

    private static HttpResponseMessage Pending() =>
        OidcTestKit.JsonStatus(HttpStatusCode.BadRequest, OidcTestKit.OAuth2ErrorJson("authorization_pending", "pending"));

    private static HttpResponseMessage InvalidClient() =>
        OidcTestKit.JsonStatus(HttpStatusCode.Unauthorized, OidcTestKit.OAuth2ErrorJson("invalid_client", "client authentication failed"));

    private static RoutingHandler Server(string? advertisedAuthMethod = null)
    {
        var handler = new RoutingHandler();
        if (advertisedAuthMethod is null)
        {
            OidcTestKit.MapDiscovery(handler);
        }
        else
        {
            var document = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(OidcTestKit.DiscoveryJson(OidcTestKit.BaseUrl))!;
            document["token_endpoint_auth_methods_supported"] =
                JsonSerializer.SerializeToElement(new[] { advertisedAuthMethod });
            string json = JsonSerializer.Serialize(document);
            handler.Map("/.well-known/openid-configuration", _ => OidcTestKit.JsonOk(json));
        }

        handler.Map(DeviceAuthPath, _ => OidcTestKit.JsonOk(OidcTestKit.DeviceAuthorizationJson()));
        return handler;
    }

    private static DeviceLoginParams Login(Action? onCode = null) =>
        new(OnUserCode: _ => { onCode?.Invoke(); return Task.CompletedTask; });

    private static List<HttpRequestMessage> At(RoutingHandler handler, string path) =>
        handler.Requests.Where(r => r.RequestUri!.AbsolutePath == path).ToList();

    private static void AssertNoAuthorizationHeader(HttpRequestMessage request)
    {
        Assert.Null(request.Headers.Authorization);
        Assert.False(request.Headers.Contains("Authorization"));
    }

    // ------------------------------------------------------------------
    // A confidential client: the secret, in the form body, at both endpoints
    // ------------------------------------------------------------------

    /// <summary>A client with a secret sends <c>client_secret</c> in the body at <c>device_authorize</c> and at every poll, and no <c>Authorization</c> header.</summary>
    [Fact]
    public async Task AClientWithASecretSendsItInTheBodyAtBothEndpointsAndNoAuthorizationHeader()
    {
        RoutingHandler handler = Server();
        int polls = 0;
        handler.Map(TokenPath, _ => ++polls < 3 ? Pending() : TokenSuccess());
        AxiamClient client = OidcTestKit.Client(handler);   // configured with OidcTestKit.ClientSecret

        OidcTokenSet tokens = await client.DeviceLoginAsync(Login());

        Assert.NotNull(tokens);
        HttpRequestMessage authorize = Assert.Single(At(handler, DeviceAuthPath));
        Dictionary<string, string> authorizeForm = OidcTestKit.ReadForm(authorize);
        Assert.Equal(OidcTestKit.ClientSecret, authorizeForm["client_secret"]);
        Assert.Equal(OidcTestKit.ClientId, authorizeForm["client_id"]);
        AssertNoAuthorizationHeader(authorize);

        List<HttpRequestMessage> pollRequests = At(handler, TokenPath);
        Assert.Equal(3, pollRequests.Count);
        foreach (HttpRequestMessage poll in pollRequests)
        {
            Dictionary<string, string> form = OidcTestKit.ReadForm(poll);
            Assert.Equal(OidcTestKit.ClientSecret, form["client_secret"]);   // on every poll
            Assert.Equal(OidcTestKit.ClientId, form["client_id"]);           // §14.1 rule 3: the poll names its client, every time
            Assert.Equal("urn:ietf:params:oauth:grant-type:device_code", form["grant_type"]);
            AssertNoAuthorizationHeader(poll);
            Assert.DoesNotContain("tenant_id", form.Keys);                   // still a query parameter, never a body field
            Assert.Contains("tenant_id=", poll.RequestUri!.Query, StringComparison.Ordinal);
        }
    }

    /// <summary>Whichever method the server advertises (a <c>client_secret_basic</c> registration included), the SDK sends the form-body secret and never <c>Authorization: Basic</c>.</summary>
    [Theory]
    [InlineData("client_secret_post")]
    [InlineData("client_secret_basic")]
    public async Task TheSecretIsInTheBodyWhicheverMethodTheServerAdvertises(string advertised)
    {
        RoutingHandler handler = Server(advertised);
        handler.Map(TokenPath, _ => TokenSuccess());
        AxiamClient client = OidcTestKit.Client(handler);

        DeviceAuthorization authorization = await client.DeviceAuthorizeAsync(new DeviceAuthorizeParams());
        await client.DevicePollAsync(new DevicePollParams(authorization.DeviceCode));

        foreach (HttpRequestMessage request in At(handler, DeviceAuthPath).Concat(At(handler, TokenPath)))
        {
            Assert.Equal(OidcTestKit.ClientSecret, OidcTestKit.ReadForm(request)["client_secret"]);
            AssertNoAuthorizationHeader(request);
            Assert.NotEqual("Basic", request.Headers.Authorization?.Scheme);
        }
    }

    // ------------------------------------------------------------------
    // A public client: client_id and nothing else
    // ------------------------------------------------------------------

    /// <summary>A client configured with no credential sends neither a secret nor anything else at either endpoint, and is not refused client-side.</summary>
    [Fact]
    public async Task APublicClientSendsNoCredentialAtEitherEndpointAndIsNotRefused()
    {
        RoutingHandler handler = Server();
        handler.Map(TokenPath, _ => TokenSuccess());
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(clientSecret: null));

        DeviceAuthorization authorization = await client.DeviceAuthorizeAsync(new DeviceAuthorizeParams(Scope: "openid"));
        OidcTokenSet tokens = await client.DevicePollAsync(new DevicePollParams(authorization.DeviceCode));

        Assert.NotNull(tokens);
        foreach (HttpRequestMessage request in At(handler, DeviceAuthPath).Concat(At(handler, TokenPath)))
        {
            Dictionary<string, string> form = OidcTestKit.ReadForm(request);
            Assert.Equal(OidcTestKit.ClientId, form["client_id"]);
            Assert.DoesNotContain("client_secret", form.Keys);
            Assert.DoesNotContain("client_assertion", form.Keys);
            Assert.DoesNotContain("client_assertion_type", form.Keys);
            AssertNoAuthorizationHeader(request);
        }

        // The poll names its client even when it has nothing else to say.
        Assert.Equal(OidcTestKit.ClientId, OidcTestKit.ReadForm(At(handler, TokenPath).Single())["client_id"]);
    }

    // ------------------------------------------------------------------
    // mTLS: the certificate is the credential, on the connection
    // ------------------------------------------------------------------

    /// <summary>A client configured with a certificate and no secret presents it (the mutual-TLS aliases), and sends no body or header credential.</summary>
    [Fact]
    public async Task AClientWithACertificateUsesTheMutualTlsEndpointsAndSendsNoSecret()
    {
        string conventional = OidcTestKit.BaseUrl.ToString().TrimEnd('/');
        string mtls = MtlsBaseUrl.ToString().TrimEnd('/');
        var handler = new RoutingHandler();
        var document = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(OidcTestKit.DiscoveryJson(OidcTestKit.BaseUrl))!;
        document["mtls_endpoint_aliases"] = JsonSerializer.SerializeToElement(new
        {
            token_endpoint = $"{mtls}/oauth2/token",
            device_authorization_endpoint = $"{mtls}/oauth2/device_authorization",
        });
        string discovery = JsonSerializer.Serialize(document);
        handler.Map("/.well-known/openid-configuration", _ => OidcTestKit.JsonOk(discovery));
        handler.Map(DeviceAuthPath, _ => OidcTestKit.JsonOk(OidcTestKit.DeviceAuthorizationJson()));
        handler.Map(TokenPath, _ => TokenSuccess());
        AxiamClientOptions options = OidcTestKit.Options(clientSecret: null) with { ClientCertificatePem = CertPem, ClientKeyPem = KeyPem };
        AxiamClient client = OidcTestKit.Client(handler, options);

        DeviceAuthorization authorization = await client.DeviceAuthorizeAsync(new DeviceAuthorizeParams());
        await client.DevicePollAsync(new DevicePollParams(authorization.DeviceCode));

        Assert.Equal(mtls, $"{At(handler, DeviceAuthPath).Single().RequestUri!.Scheme}://{At(handler, DeviceAuthPath).Single().RequestUri!.Authority}");
        Assert.Equal(mtls, $"{At(handler, TokenPath).Single().RequestUri!.Scheme}://{At(handler, TokenPath).Single().RequestUri!.Authority}");
        Assert.NotEqual(conventional, mtls);
        foreach (HttpRequestMessage request in At(handler, DeviceAuthPath).Concat(At(handler, TokenPath)))
        {
            Dictionary<string, string> form = OidcTestKit.ReadForm(request);
            Assert.DoesNotContain("client_secret", form.Keys);   // the SDK invents no secret
            Assert.Equal(OidcTestKit.ClientId, form["client_id"]);
            AssertNoAuthorizationHeader(request);
        }
    }

    // ------------------------------------------------------------------
    // 401 invalid_client: terminal, one request, never refreshed
    // ------------------------------------------------------------------

    private static string B64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>A client holding a signed-in session, so that a <c>401</c> would enter the refresh guard if the path were not exempt.</summary>
    private static AxiamClient SignedInClient(RoutingHandler handler)
    {
        AxiamClient client = OidcTestKit.Client(handler);
        string header = B64Url(Encoding.UTF8.GetBytes("""{"alg":"none"}"""));
        string body = B64Url(JsonSerializer.SerializeToUtf8Bytes(new
        {
            sub = Guid.NewGuid().ToString(),
            tenant_id = OidcTestKit.TenantGuid,
            org_id = Guid.NewGuid().ToString(),
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
        }));
        FieldInfo field = typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var container = (CookieContainer)field.GetValue(client)!;
        container.Add(OidcTestKit.BaseUrl, new Cookie("axiam_access", $"{header}.{body}.unsigned"));
        container.Add(OidcTestKit.BaseUrl, new Cookie("axiam_refresh", "refresh-token-value"));
        return client;
    }

    /// <summary>At <c>device_authorize</c>, a <c>401 invalid_client</c> is an <see cref="OAuthProtocolError"/> after one request and does not enter the &#167;9 refresh guard.</summary>
    [Fact]
    public async Task AnInvalidClientAtDeviceAuthorizeIsTerminalAndNeverRefreshes()
    {
        RoutingHandler handler = Server();
        handler.Map(DeviceAuthPath, _ => InvalidClient());
        handler.Map(RefreshPath, _ => OidcTestKit.JsonOk("{}"));
        AxiamClient client = SignedInClient(handler);

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.DeviceAuthorizeAsync(new DeviceAuthorizeParams()));

        Assert.Equal("invalid_client", error.Error);
        Assert.Equal(1, handler.CountFor(DeviceAuthPath));
        Assert.Equal(0, handler.CountFor(RefreshPath));
    }

    /// <summary>At the poll, a <c>401 invalid_client</c> is an <see cref="OAuthProtocolError"/> after one request, is never retried by <c>device_login</c>, and does not refresh.</summary>
    [Fact]
    public async Task AnInvalidClientAtThePollIsTerminalAndNeverRefreshes()
    {
        RoutingHandler handler = Server();
        handler.Map(TokenPath, _ => InvalidClient());
        handler.Map(RefreshPath, _ => OidcTestKit.JsonOk("{}"));
        AxiamClient client = SignedInClient(handler);

        OAuthProtocolError single = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode))));
        Assert.Equal("invalid_client", single.Error);
        Assert.Equal(1, handler.CountFor(TokenPath));

        // The composed helper treats it as terminal: it neither loops nor retries.
        OAuthProtocolError composed = await Assert.ThrowsAsync<OAuthProtocolError>(() => client.DeviceLoginAsync(Login()));
        Assert.Equal("invalid_client", composed.Error);
        Assert.Equal(2, handler.CountFor(TokenPath));    // one more request, from the one poll device_login made
        Assert.Equal(0, handler.CountFor(RefreshPath));
    }

    // ------------------------------------------------------------------
    // DPoP: this SDK generates no proof, and reads token_type as given
    // ------------------------------------------------------------------

    /// <summary>A poll answered with <c>token_type: DPoP</c> is surfaced as such (&#167;21.7.1: never assume Bearer).</summary>
    [Fact]
    public async Task ADpopTokenTypeIsSurfacedAsTheServerSaidIt()
    {
        RoutingHandler handler = Server();
        handler.Map(TokenPath, _ => TokenSuccess(tokenType: "DPoP"));
        AxiamClient client = OidcTestKit.Client(handler);

        OidcTokenSet tokens = await client.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode)));

        Assert.Equal("DPoP", tokens.TokenType);
        // No proof is generated by this SDK (§21.7.3): the poll carries no DPoP header.
        Assert.False(At(handler, TokenPath).Single().Headers.Contains("DPoP"));
    }
}
