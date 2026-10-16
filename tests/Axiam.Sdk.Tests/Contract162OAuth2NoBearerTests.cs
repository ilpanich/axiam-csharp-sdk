using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Contract 1.62, CONTRACT.md &#167;6.1 rule 11, &#167;12.1 rule 3 and &#167;14.6 (finding C162-05): a session's
/// access token, or an adopted (device / &#167;6.1) bearer, is never sent as <c>Authorization</c> to an
/// <c>/oauth2/*</c> request; a credential the caller passes explicitly to that one call (RFC 7591 /
/// RFC 7592, &#167;28.12) still is.
/// </summary>
[Trait("Category", "Fast")]
public class Contract162OAuth2NoBearerTests
{
    private const string DeviceAuthPath = "/oauth2/device_authorization";
    private const string TokenPath = "/oauth2/token";
    private const string MePath = "/api/v1/auth/me";

    private static readonly byte[] CertPem = Encoding.ASCII.GetBytes(
        "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKZ0000000000MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n-----END CERTIFICATE-----\n");

    private static readonly byte[] KeyPem = Encoding.ASCII.GetBytes(
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n");

    private static RoutingHandler Server()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        handler.Map(DeviceAuthPath, _ => OidcTestKit.JsonOk(OidcTestKit.DeviceAuthorizationJson()));
        handler.Map(TokenPath, _ => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("oauth2-access-token", refreshToken: "next-refresh")));
        handler.Map(MePath, _ => OidcTestKit.JsonOk("{}"));
        handler.Map("/api/v1/auth/device", _ => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("adopted-device-bearer")));
        handler.Map("/oauth2/register", _ => OidcTestKit.JsonOk("{}"));
        handler.Map($"/t/{OidcTestKit.TenantGuid}/oauth2/token",
            _ => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("oauth2-access-token")));
        return handler;
    }

    private static string SeedSession(AxiamClient client)
    {
        string session = Secrets.Fresh();
        FieldInfo field = typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var jar = (CookieContainer)field.GetValue(client)!;
        jar.Add(OidcTestKit.BaseUrl, new Cookie("axiam_access", session));
        return session;
    }

    private static AxiamClient DeviceCapableClient(RoutingHandler handler) =>
        OidcTestKit.Client(handler, new AxiamClientOptions
        {
            BaseUrl = OidcTestKit.BaseUrl,
            TenantId = OidcTestKit.TenantGuid,
            OidcClientId = OidcTestKit.ClientId,
            OidcClientSecret = OidcTestKit.ClientSecret,
            ClientCertificatePem = CertPem,
            ClientKeyPem = KeyPem,
        });

    private static void AssertNoAuthorization(RoutingHandler handler, string path, int expectedCount)
    {
        List<HttpRequestMessage> sent = handler.Requests.Where(r => r.RequestUri!.AbsolutePath == path).ToList();
        Assert.Equal(expectedCount, sent.Count);
        foreach (HttpRequestMessage request in sent)
        {
            Assert.Null(request.Headers.Authorization);
            Assert.False(request.Headers.Contains("Authorization"));
        }
    }

    private static async Task RunTheThreeOAuth2Calls(AxiamClient client)
    {
        DeviceAuthorization authorization = await client.DeviceAuthorizeAsync(new DeviceAuthorizeParams());
        await client.DevicePollAsync(new DevicePollParams(authorization.DeviceCode));
        await client.LoginClientCredentialsAsync(new LoginClientCredentialsParams());
        await client.OidcRefreshAsync(new OidcRefreshParams { RefreshToken = Sensitive<string>.Wrap(Secrets.Fresh()) });
    }

    /// <summary>A signed-in session: the ordinary call carries it; device_authorize, device_poll, client credentials and refresh carry no <c>Authorization</c>.</summary>
    [Fact]
    public async Task ASessionBearerIsNeverSentToDeviceAuthorizeDevicePollOrATokenRequest()
    {
        RoutingHandler handler = Server();
        using AxiamClient client = OidcTestKit.Client(handler);
        string session = SeedSession(client);

        // Positive control: the session really is attached to an ordinary REST call.
        await client.TransportHttpClient.GetAsync(MePath);
        HttpRequestMessage control = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == MePath);
        Assert.Equal($"Bearer {session}", control.Headers.Authorization?.ToString());

        await RunTheThreeOAuth2Calls(client);

        AssertNoAuthorization(handler, DeviceAuthPath, 1);
        AssertNoAuthorization(handler, TokenPath, 3);   // poll, client credentials, refresh
    }

    /// <summary>An adopted &#167;6.1 device bearer: the same calls carry no <c>Authorization</c>, while an ordinary call still carries the adopted token.</summary>
    [Fact]
    public async Task AnAdoptedDeviceBearerIsNeverSentToDeviceAuthorizeDevicePollOrATokenRequest()
    {
        RoutingHandler handler = Server();
        using AxiamClient source = DeviceCapableClient(handler);
        var adopted = await source.AuthenticateDeviceAsync();
        using AxiamClient device = adopted.Client;
        handler.Requests.Clear();

        await device.TransportHttpClient.GetAsync(MePath);
        HttpRequestMessage control = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == MePath);
        Assert.Equal("Bearer adopted-device-bearer", control.Headers.Authorization?.ToString());

        await RunTheThreeOAuth2Calls(device);

        AssertNoAuthorization(handler, DeviceAuthPath, 1);
        AssertNoAuthorization(handler, TokenPath, 3);
    }

    /// <summary>The tenant-path issuer form <c>/t/{tenant_id}/oauth2/*</c> is covered too.</summary>
    [Fact]
    public async Task TheTenantPathIssuerFormCarriesNoSessionBearerEither()
    {
        RoutingHandler handler = Server();
        using AxiamClient client = OidcTestKit.Client(handler);
        SeedSession(client);

        string path = $"/t/{OidcTestKit.TenantGuid}/oauth2/token";
        await client.TransportHttpClient.PostAsync(path, new FormUrlEncodedContent(new Dictionary<string, string>()));

        AssertNoAuthorization(handler, path, 1);
    }

    /// <summary>An explicit credential on the one request (RFC 7591 initial access token, RFC 7592 <c>registration_access_token</c>) is not stripped; the session is still not substituted.</summary>
    [Fact]
    public async Task AnExplicitRegistrationCredentialOnTheOneRequestIsKept()
    {
        RoutingHandler handler = Server();
        using AxiamClient client = OidcTestKit.Client(handler);
        string session = SeedSession(client);
        string explicitToken = Secrets.Fresh();

        using var withToken = new HttpRequestMessage(HttpMethod.Post, "/oauth2/register");
        withToken.Headers.Authorization = new AuthenticationHeaderValue("Bearer", explicitToken);
        await client.TransportHttpClient.SendAsync(withToken);

        using var without = new HttpRequestMessage(HttpMethod.Post, "/oauth2/register");
        await client.TransportHttpClient.SendAsync(without);

        Assert.Equal($"Bearer {explicitToken}", handler.Requests[0].Headers.Authorization?.ToString());
        Assert.Null(handler.Requests[1].Headers.Authorization);
        Assert.NotEqual($"Bearer {session}", handler.Requests[0].Headers.Authorization?.ToString());
    }
}
