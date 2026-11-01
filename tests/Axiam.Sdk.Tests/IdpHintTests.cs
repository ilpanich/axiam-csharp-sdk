using System.Net;
using System.Text;
using System.Web;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;12.1 (<c>idp_hint</c>, contract 1.65) and &#167;26.2 rule 8: the optional provider hint on
/// <see cref="AxiamClient.OidcBegin"/> (emitted as <c>axiam_idp_hint</c>) and <see cref="AxiamClient.OidcParAsync"/>
/// (pushed in the body, never on the redirect). The test names are the contract's.
/// </summary>
[Trait("Category", "Fast")]
public class IdpHintTests
{
    private const string Redirect = "https://app.example.com/callback";
    private const string RequestUri = "urn:ietf:params:oauth:request_uri:abc123";

    private static readonly OidcConfiguration Config = new(
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
        GrantTypesSupported: new[] { "authorization_code" },
        PushedAuthorizationRequestEndpoint: "https://axiam.test/oauth2/par");

    private static readonly string[] Mandated =
    {
        "client_id", "code_challenge", "code_challenge_method", "nonce", "redirect_uri", "response_type", "scope", "state",
    };

    /// <summary>The parsed parameter LIST (so a duplicate is visible), in URL order.</summary>
    private static List<KeyValuePair<string, string>> Params(string url)
    {
        var list = new List<KeyValuePair<string, string>>();
        string query = new Uri(url).Query.TrimStart('?');
        foreach (string pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] kv = pair.Split('=', 2);
            list.Add(new(Uri.UnescapeDataString(kv[0]), kv.Length > 1 ? Uri.UnescapeDataString(kv[1]) : string.Empty));
        }
        return list;
    }

    private static AxiamClient NewClient(RoutingHandler handler) => OidcTestKit.Client(handler);

    // -----------------------------------------------------------------
    // oidc_begin
    // -----------------------------------------------------------------

    [Theory]
    [InlineData("corp-okta")]
    [InlineData("0b5c2c1a-3a3c-4d7e-9a7f-5d1c1d9c4a11")]
    [InlineData("Google")] // not case-folded
    [InlineData("a b&c=d/é")] // needs percent-encoding; must round-trip through the parsed query
    public void IdpHintEmittedOnce(string hint)
    {
        using var handler = new RoutingHandler();
        using AxiamClient client = NewClient(handler);

        AuthorizationRequest request = client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect, IdpHint = hint });

        List<KeyValuePair<string, string>> parameters = Params(request.Url);
        Assert.Single(parameters, p => p.Key == "axiam_idp_hint");
        Assert.Equal(hint, parameters.Single(p => p.Key == "axiam_idp_hint").Value);
        // beside the other eight, unchanged
        Assert.Equal(Mandated.Append("axiam_idp_hint").OrderBy(k => k, StringComparer.Ordinal),
            parameters.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(OidcTestKit.ClientId, parameters.Single(p => p.Key == "client_id").Value);
        Assert.Equal(Redirect, parameters.Single(p => p.Key == "redirect_uri").Value);
        Assert.DoesNotContain(parameters, p => p.Key == "kc_idp_hint");
    }

    [Fact]
    public void IdpHintOmittedWhenUnset()
    {
        using var handler = new RoutingHandler();
        using AxiamClient client = NewClient(handler);

        AuthorizationRequest request = client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect });

        List<KeyValuePair<string, string>> parameters = Params(request.Url);
        Assert.Equal(Mandated, parameters.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
        Assert.DoesNotContain("axiam_idp_hint", request.Url);
        Assert.DoesNotContain("kc_idp_hint", request.Url);
    }

    [Fact]
    public void IdpHintNotDuplicated()
    {
        using var handler = new RoutingHandler();
        using AxiamClient client = NewClient(handler);
        var extra = new Dictionary<string, string> { ["axiam_idp_hint"] = "other", ["prompt"] = "login" };

        // Set: the option is the single source; the extra of the same name is dropped.
        AuthorizationRequest set = client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect, IdpHint = "corp-okta", ExtraParams = extra });
        List<KeyValuePair<string, string>> parameters = Params(set.Url);
        Assert.Equal("corp-okta", Assert.Single(parameters, p => p.Key == "axiam_idp_hint").Value);
        Assert.Equal("login", Assert.Single(parameters, p => p.Key == "prompt").Value);

        // Unset: the extra passes through as extras always did, still once.
        AuthorizationRequest unset = client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect, ExtraParams = extra });
        Assert.Equal("other", Assert.Single(Params(unset.Url), p => p.Key == "axiam_idp_hint").Value);
    }

    [Fact]
    public void IdpHintBounds()
    {
        using var handler = new RoutingHandler();
        using AxiamClient client = NewClient(handler);

        // Empty and 257 bytes: refused, no URL built.
        Assert.Throws<ArgumentException>(() => client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect, IdpHint = "" }));
        Assert.Throws<ArgumentException>(() => client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect, IdpHint = new string('a', 257) }));
        // Bytes, not characters: 129 two-byte characters is 258 bytes.
        Assert.Throws<ArgumentException>(() => client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect, IdpHint = new string('é', 129) }));

        // 256 bytes: accepted unchanged (ASCII, and as 128 two-byte characters).
        string ascii = new('a', 256);
        Assert.Equal(ascii, Params(client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect, IdpHint = ascii }).Url)
            .Single(p => p.Key == "axiam_idp_hint").Value);
        string twoByte = new('é', 128);
        Assert.Equal(256, Encoding.UTF8.GetByteCount(twoByte));
        Assert.Equal(twoByte, Params(client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect, IdpHint = twoByte }).Url)
            .Single(p => p.Key == "axiam_idp_hint").Value);

        // No trimming: whitespace is not empty and is sent as given.
        Assert.Equal(" x ", Params(client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect, IdpHint = " x " }).Url)
            .Single(p => p.Key == "axiam_idp_hint").Value);
    }

    // -----------------------------------------------------------------
    // oidc_par
    // -----------------------------------------------------------------

    private static async Task<(PushedAuthorizationRequest Pushed, Dictionary<string, string> Form, string RawBody)> PushAsync(string? hint)
    {
        Dictionary<string, string>? form = null;
        string? raw = null;
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        handler.Map("/oauth2/par", r =>
        {
            form = OidcTestKit.ReadForm(r);
            raw = OidcTestKit.ReadRawBody(r);
            return OidcTestKit.JsonStatus(HttpStatusCode.Created, $$"""{"request_uri":"{{RequestUri}}","expires_in":90}""");
        });
        using AxiamClient client = NewClient(handler);
        AuthorizationRequest begun = client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect });

        PushedAuthorizationRequest pushed = await client.OidcParAsync(new OidcParParams
        {
            Request = begun,
            RedirectUri = Redirect,
            Configuration = Config,
            IdpHint = hint,
        });
        return (pushed, form!, raw!);
    }

    [Fact]
    public async Task ParIdpHintInPushedBody()
    {
        (PushedAuthorizationRequest pushed, Dictionary<string, string> form, string raw) = await PushAsync("corp-okta");

        Assert.Equal("corp-okta", form["axiam_idp_hint"]);
        Assert.Single(HttpUtility.ParseQueryString(raw).GetValues("axiam_idp_hint")!); // exactly once
        Assert.DoesNotContain("kc_idp_hint", raw);
        // The redirect URL is exactly client_id and request_uri: the hint cannot leak into it.
        Assert.Equal(new[] { "client_id", "request_uri" },
            Params(pushed.Url).Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));

        // Without a hint the field is absent from the push, and the redirect is the same shape.
        (PushedAuthorizationRequest plain, Dictionary<string, string> plainForm, _) = await PushAsync(null);
        Assert.DoesNotContain("axiam_idp_hint", plainForm.Keys);
        Assert.Equal(new[] { "client_id", "request_uri" },
            Params(plain.Url).Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
    }

    private async Task<(PushedAuthorizationRequest Pushed, string Raw)> PushFromBeginAsync(string? beginHint, string? argHint)
    {
        string? raw = null;
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        handler.Map("/oauth2/par", r =>
        {
            raw = OidcTestKit.ReadRawBody(r);
            return OidcTestKit.JsonStatus(HttpStatusCode.Created, $$"""{"request_uri":"{{RequestUri}}","expires_in":90}""");
        });
        using AxiamClient client = NewClient(handler);
        AuthorizationRequest begun = client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect, IdpHint = beginHint });
        PushedAuthorizationRequest pushed = await client.OidcParAsync(new OidcParParams
        {
            Request = begun,
            RedirectUri = Redirect,
            Configuration = Config,
            IdpHint = argHint,
        });
        return (pushed, raw!);
    }

    [Fact]
    public async Task ParIdpHintFromBeginUrlPushed()
    {
        (PushedAuthorizationRequest pushed, string raw) = await PushFromBeginAsync("corp-okta", null);

        Assert.Equal(new[] { "corp-okta" }, HttpUtility.ParseQueryString(raw).GetValues("axiam_idp_hint"));
        Assert.Equal(new[] { "client_id", "request_uri" },
            Params(pushed.Url).Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
    }

    [Fact]
    public async Task ParIdpHintArgumentWins()
    {
        (_, string raw) = await PushFromBeginAsync("corp-okta", "other");

        Assert.Equal(new[] { "other" }, HttpUtility.ParseQueryString(raw).GetValues("axiam_idp_hint"));
        Assert.DoesNotContain("corp-okta", raw);
    }

    [Fact]
    public async Task ParIdpHintIsValidatedLikeOidcBegin()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        using AxiamClient client = NewClient(handler);
        AuthorizationRequest begun = client.OidcBegin(Config, new OidcBeginParams { RedirectUri = Redirect });

        await Assert.ThrowsAsync<ArgumentException>(() => client.OidcParAsync(
            new OidcParParams { Request = begun, RedirectUri = Redirect, Configuration = Config, IdpHint = "" }));
        await Assert.ThrowsAsync<ArgumentException>(() => client.OidcParAsync(
            new OidcParParams { Request = begun, RedirectUri = Redirect, Configuration = Config, IdpHint = new string('a', 257) }));
        Assert.Empty(handler.Requests); // refused before any request
    }
}
