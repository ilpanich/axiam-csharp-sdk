using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// <see cref="AxiamClient.OidcBegin"/> — CONTRACT.md &#167;12.1: pure local computation, no
/// network I/O, no <c>Async</c> suffix (&#167;12.2's single deliberate exception).
/// </summary>
[Trait("Category", "Fast")]
public class OidcBeginTests
{
    private static readonly OidcConfiguration Configuration = new(
        Issuer: "https://axiam.test",
        AuthorizationEndpoint: "https://axiam.test/oauth2/authorize",
        TokenEndpoint: "https://axiam.test/oauth2/token",
        UserinfoEndpoint: "https://axiam.test/oauth2/userinfo",
        JwksUri: "https://axiam.test/oauth2/jwks",
        RevocationEndpoint: "https://axiam.test/oauth2/revoke",
        IntrospectionEndpoint: "https://axiam.test/oauth2/introspect",
        ResponseTypesSupported: new[] { "code" },
        SubjectTypesSupported: new[] { "public" },
        IdTokenSigningAlgValuesSupported: new[] { "EdDSA" },
        ScopesSupported: new[] { "openid" },
        TokenEndpointAuthMethodsSupported: new[] { "client_secret_post" },
        ClaimsSupported: new[] { "sub" },
        GrantTypesSupported: new[] { "authorization_code" });

    [Fact]
    public void OidcBegin_HasNoAsyncSuffix()
    {
        // Reflection-backed regression: CONTRACT.md §12.2's C# naming map fixes OidcBegin
        // as the single deliberate synchronous exception — no OidcBeginAsync may exist.
        Assert.Null(typeof(AxiamClient).GetMethod("OidcBeginAsync"));
        Assert.NotNull(typeof(AxiamClient).GetMethod("OidcBegin"));
    }

    [Fact]
    public void OidcBegin_BuildsUrlWithExactlyEightMandatedParams_AndOpenidScope()
    {
        using var handler = new RoutingHandler();
        AxiamClient client = OidcTestKit.Client(handler);

        AuthorizationRequest request = client.OidcBegin(Configuration, new OidcBeginParams { RedirectUri = "https://app.example/callback" });

        Dictionary<string, string> query = ParseQuery(request.Url);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal(OidcTestKit.ClientId, query["client_id"]);
        Assert.Equal("https://app.example/callback", query["redirect_uri"]);
        Assert.Equal("openid", query["scope"]);
        Assert.Equal(request.State, query["state"]);
        Assert.Equal(request.Nonce, query["nonce"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.Equal(OidcPkce.ComputeCodeChallenge(request.CodeVerifier.Reveal()), query["code_challenge"]);
    }

    private static Dictionary<string, string> ParseQuery(string url)
    {
        var uri = new Uri(url);
        var result = new Dictionary<string, string>();
        string query = uri.Query.TrimStart('?');
        if (query.Length == 0)
        {
            return result;
        }
        foreach (string pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] kv = pair.Split('=', 2);
            result[Uri.UnescapeDataString(kv[0])] = kv.Length > 1 ? Uri.UnescapeDataString(kv[1]) : string.Empty;
        }
        return result;
    }

    [Fact]
    public void OidcBegin_AddsOpenidScope_WhenCallerOmitsIt()
    {
        using var handler = new RoutingHandler();
        AxiamClient client = OidcTestKit.Client(handler);

        AuthorizationRequest request = client.OidcBegin(Configuration, new OidcBeginParams
        {
            RedirectUri = "https://app.example/callback",
            Scope = "profile email",
        });

        Assert.Contains("scope=openid%20profile%20email", request.Url);
    }

    [Fact]
    public void OidcBegin_EncodesSpacesAsPercent20_NotPlus()
    {
        using var handler = new RoutingHandler();
        AxiamClient client = OidcTestKit.Client(handler);

        AuthorizationRequest request = client.OidcBegin(Configuration, new OidcBeginParams
        {
            RedirectUri = "https://app.example/callback",
            Scope = "profile",
        });

        Assert.Contains("%20", request.Url);
        Assert.DoesNotContain("scope=openid+profile", request.Url);
    }

    [Theory]
    [InlineData("response_type")]
    [InlineData("client_id")]
    [InlineData("redirect_uri")]
    [InlineData("scope")]
    [InlineData("state")]
    [InlineData("nonce")]
    [InlineData("code_challenge")]
    [InlineData("code_challenge_method")]
    public void OidcBegin_ExtraParamOverridingReservedKey_ThrowsArgumentException_NotAuthError(string reservedKey)
    {
        using var handler = new RoutingHandler();
        AxiamClient client = OidcTestKit.Client(handler);

        var ex = Assert.Throws<ArgumentException>(() => client.OidcBegin(Configuration, new OidcBeginParams
        {
            RedirectUri = "https://app.example/callback",
            ExtraParams = new Dictionary<string, string> { [reservedKey] = "hijack" },
        }));
        Assert.Contains(reservedKey, ex.Message);
    }

    [Fact]
    public void OidcBegin_AllowsAdditionalCallerParams()
    {
        using var handler = new RoutingHandler();
        AxiamClient client = OidcTestKit.Client(handler);

        AuthorizationRequest request = client.OidcBegin(Configuration, new OidcBeginParams
        {
            RedirectUri = "https://app.example/callback",
            ExtraParams = new Dictionary<string, string> { ["prompt"] = "login" },
        });

        Assert.Contains("prompt=login", request.Url);
    }

    [Fact]
    public void OidcBegin_NoClientId_ThrowsInvalidOperationException()
    {
        using var handler = new RoutingHandler();
        var options = new Axiam.Sdk.Options.AxiamClientOptions { BaseUrl = OidcTestKit.BaseUrl, TenantId = OidcTestKit.TenantGuid };
        AxiamClient client = OidcTestKit.Client(handler, options);

        Assert.Throws<InvalidOperationException>(() => client.OidcBegin(Configuration, new OidcBeginParams { RedirectUri = "https://app.example/callback" }));
    }

    [Fact]
    public void OidcBegin_NeverStoresAnything_ReturnsFreshValuesEachCall()
    {
        using var handler = new RoutingHandler();
        AxiamClient client = OidcTestKit.Client(handler);

        AuthorizationRequest first = client.OidcBegin(Configuration, new OidcBeginParams { RedirectUri = "https://app.example/callback" });
        AuthorizationRequest second = client.OidcBegin(Configuration, new OidcBeginParams { RedirectUri = "https://app.example/callback" });

        Assert.NotEqual(first.State, second.State);
        Assert.NotEqual(first.Nonce, second.Nonce);
        Assert.NotEqual(first.CodeVerifier.Reveal(), second.CodeVerifier.Reveal());
    }
}
