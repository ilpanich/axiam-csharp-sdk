using System.Net;
using System.Net.Http;
using System.Web;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;26 — Pushed Authorization Requests (RFC 9126).
/// </summary>
/// <remarks>
/// Two assertions carry the section:
/// <list type="bullet">
///   <item><c>SuccessfulPush_Answers201</c> — RFC 9126 &#167;2.2 specifies <i>Created</i>.
///   A success predicate written <c>== 200</c> passes every other test in this file and
///   treats every real push as a failure.</item>
///   <item><c>RedirectUrl_CarriesExactlyTwoParameters</c> — the server refuses a request
///   that mixes a <c>request_uri</c> with inline authorization parameters rather than
///   merging them, and merging is where parameter confusion lives (&#167;26.2
///   rule 2).</item>
/// </list>
/// </remarks>
[Trait("Category", "Fast")]
public class OidcParTests
{
    private const string ParPath = "/oauth2/par";
    private const string RedirectUri = "https://app.example.com/callback";
    private const string RequestUri = "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c";

    private static HttpResponseMessage ParResponse() =>
        OidcTestKit.JsonStatus(HttpStatusCode.Created, $$"""
            {"request_uri":"{{RequestUri}}","expires_in":90}
            """);

    private static void MapPar(RoutingHandler handler, Action<HttpRequestMessage>? capture = null) =>
        handler.Map(ParPath, request =>
        {
            capture?.Invoke(request);
            return ParResponse();
        });

    private static async Task<(OidcConfiguration Config, AuthorizationRequest Begun)> BeginAsync(AxiamClient client)
    {
        OidcConfiguration config = await client.OidcDiscoverAsync();
        AuthorizationRequest begun = client.OidcBegin(config, new OidcBeginParams { RedirectUri = RedirectUri });
        return (config, begun);
    }

    // -----------------------------------------------------------------------
    // §26.1 — the push
    // -----------------------------------------------------------------------

    [Fact]
    public async Task SuccessfulPush_Answers201()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapPar(handler);
        using AxiamClient client = OidcTestKit.Client(handler);
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        PushedAuthorizationRequest pushed = await client.OidcParAsync(new OidcParParams
        {
            Request = begun,
            RedirectUri = RedirectUri,
            Configuration = config,
            Scope = "openid profile",
        });

        Assert.Equal(RequestUri, pushed.RequestUri.Reveal());
        Assert.Equal(90L, pushed.ExpiresIn);
    }

    [Fact]
    public async Task Push_GoesToTheDiscoveredEndpointWithTheTenantQuery()
    {
        HttpRequestMessage? sent = null;
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapPar(handler, r => sent = r);
        using AxiamClient client = OidcTestKit.Client(handler);
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        await client.OidcParAsync(new OidcParParams { Request = begun, RedirectUri = RedirectUri, Configuration = config });

        Assert.NotNull(sent);
        Assert.Equal(HttpMethod.Post, sent!.Method);
        Assert.Equal(ParPath, sent.RequestUri!.AbsolutePath);
        // §12.1 rule 2: the /oauth2 endpoints carry the tenant as a query parameter, and
        // PAR is one of those.
        Assert.Equal(OidcTestKit.TenantGuid, HttpUtility.ParseQueryString(sent.RequestUri.Query)["tenant_id"]);
    }

    [Fact]
    public async Task Push_CarriesEverythingOidcBeginComputed_AndGeneratesNothingNew()
    {
        Dictionary<string, string>? form = null;
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapPar(handler, r => form = OidcTestKit.ReadForm(r));
        using AxiamClient client = OidcTestKit.Client(handler);
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        PushedAuthorizationRequest pushed = await client.OidcParAsync(new OidcParParams
        {
            Request = begun,
            RedirectUri = RedirectUri,
            Configuration = config,
            Scope = "openid profile",
        });

        Assert.NotNull(form);
        // §26.2 rule 1: no second generator. state, nonce and the PKCE pair all come from
        // the AuthorizationRequest that was pushed — two sources for any of them are two
        // things that can disagree.
        Assert.Equal(begun.State, form!["state"]);
        Assert.Equal(begun.Nonce, form["nonce"]);
        Assert.Equal(begun.State, pushed.State);
        Assert.Equal(begun.Nonce, pushed.Nonce);
        Assert.Equal(begun.CodeVerifier.Reveal(), pushed.CodeVerifier.Reveal());

        Assert.Equal(OidcTestKit.ClientId, form["client_id"]);
        Assert.Equal("code", form["response_type"]);
        Assert.Equal(RedirectUri, form["redirect_uri"]);
        Assert.Equal("openid profile", form["scope"]);
        Assert.Equal("S256", form["code_challenge_method"]);
        Assert.Equal(OidcPkce.ComputeCodeChallenge(begun.CodeVerifier.Reveal()), form["code_challenge"]);
    }

    [Fact]
    public async Task ConfidentialClient_AuthenticatesThePush()
    {
        Dictionary<string, string>? form = null;
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapPar(handler, r => form = OidcTestKit.ReadForm(r));
        using AxiamClient client = OidcTestKit.Client(handler);
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        await client.OidcParAsync(new OidcParParams { Request = begun, RedirectUri = RedirectUri, Configuration = config });

        Assert.Equal(OidcTestKit.ClientSecret, form!["client_secret"]);
    }

    [Fact]
    public async Task PublicClient_PushesWithoutASecret()
    {
        Dictionary<string, string>? form = null;
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapPar(handler, r => form = OidcTestKit.ReadForm(r));
        using AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(clientSecret: null));
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        await client.OidcParAsync(new OidcParParams { Request = begun, RedirectUri = RedirectUri, Configuration = config });

        Assert.False(form!.ContainsKey("client_secret"));
    }

    [Fact]
    public async Task OpenidIsAddedToAScopeThatOmitsIt()
    {
        Dictionary<string, string>? form = null;
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapPar(handler, r => form = OidcTestKit.ReadForm(r));
        using AxiamClient client = OidcTestKit.Client(handler);
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        await client.OidcParAsync(new OidcParParams
        {
            Request = begun,
            RedirectUri = RedirectUri,
            Configuration = config,
            Scope = "profile email",
        });

        Assert.Contains("openid", form!["scope"].Split(' '));
    }

    [Fact]
    public async Task Par_DiscoversWhenGivenNoConfiguration()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapPar(handler);
        using AxiamClient client = OidcTestKit.Client(handler);
        (_, AuthorizationRequest begun) = await BeginAsync(client);

        await client.OidcParAsync(new OidcParParams { Request = begun, RedirectUri = RedirectUri });

        // The document is cached per origin (§12.3 rule 6), so passing null costs no
        // second fetch.
        Assert.Equal(1, handler.CountFor("/.well-known/openid-configuration"));
        Assert.Equal(1, handler.CountFor(ParPath));
    }

    [Fact]
    public async Task AnExplicitTenantOverridesTheClientTenant()
    {
        var other = Guid.Parse("44444444-4444-4444-4444-444444444444");
        HttpRequestMessage? sent = null;
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapPar(handler, r => sent = r);
        using AxiamClient client = OidcTestKit.Client(handler);
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        await client.OidcParAsync(new OidcParParams
        {
            Request = begun,
            RedirectUri = RedirectUri,
            Configuration = config,
            TenantId = other,
        });

        Assert.Equal(other.ToString(), HttpUtility.ParseQueryString(sent!.RequestUri!.Query)["tenant_id"]);
    }

    // -----------------------------------------------------------------------
    // §26.2 rule 2 — the redirect URL
    // -----------------------------------------------------------------------

    [Fact]
    public async Task RedirectUrl_CarriesExactlyTwoParameters()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapPar(handler);
        using AxiamClient client = OidcTestKit.Client(handler);
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        PushedAuthorizationRequest pushed = await client.OidcParAsync(new OidcParParams
        {
            Request = begun,
            RedirectUri = RedirectUri,
            Configuration = config,
            Scope = "openid",
        });

        var url = new Uri(pushed.Url);
        System.Collections.Specialized.NameValueCollection query = HttpUtility.ParseQueryString(url.Query);

        // The server REFUSES a request_uri mixed with inline parameters rather than
        // merging them — re-adding scope/state/redirect_uri here restores the
        // parameter-confusion attack (§26.2 rule 2).
        Assert.Equal(2, query.Count);
        Assert.Equal(OidcTestKit.ClientId, query["client_id"]);
        Assert.Equal(RequestUri, query["request_uri"]);
        Assert.Equal("/oauth2/authorize", url.AbsolutePath);
    }

    [Fact]
    public async Task RedirectUrl_DropsAnyQueryTheDiscoveredEndpointCarried()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapPar(handler);
        using AxiamClient client = OidcTestKit.Client(handler);
        OidcConfiguration discovered = await client.OidcDiscoverAsync();

        // An authorization_endpoint that already carries a query is legal, and its
        // parameters are exactly the ones rule 2 forbids travelling alongside a
        // request_uri.
        OidcConfiguration config = discovered with
        {
            AuthorizationEndpoint = "https://axiam.test/oauth2/authorize?audience=legacy&scope=all",
        };
        AuthorizationRequest begun = client.OidcBegin(config, new OidcBeginParams { RedirectUri = RedirectUri });

        PushedAuthorizationRequest pushed = await client.OidcParAsync(new OidcParParams
        {
            Request = begun,
            RedirectUri = RedirectUri,
            Configuration = config,
        });

        System.Collections.Specialized.NameValueCollection query =
            HttpUtility.ParseQueryString(new Uri(pushed.Url).Query);
        Assert.Equal(2, query.Count);
        Assert.Null(query["audience"]);
    }

    // -----------------------------------------------------------------------
    // refusals
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AServerWithoutPar_IsRefusedClientSideWithNoWireCall()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler, withOptionalEndpoints: false);
        using AxiamClient client = OidcTestKit.Client(handler);
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        AuthError error = await Assert.ThrowsAsync<AuthError>(() => client.OidcParAsync(
            new OidcParParams { Request = begun, RedirectUri = RedirectUri, Configuration = config }));

        Assert.Contains("pushed_authorization_request_endpoint", error.Message);
        // §12.7.2 rule 1's discipline: no URL is concatenated onto the issuer.
        Assert.Equal(0, handler.CountFor(ParPath));
    }

    [Fact]
    public async Task AnOAuthErrorBody_BecomesAnOAuthProtocolError()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        handler.Map(ParPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.BadRequest, OidcTestKit.OAuth2ErrorJson("invalid_request_uri", "bad request_uri")));
        using AxiamClient client = OidcTestKit.Client(handler);
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(() => client.OidcParAsync(
            new OidcParParams { Request = begun, RedirectUri = RedirectUri, Configuration = config }));

        Assert.Equal("invalid_request_uri", error.Error);
    }

    [Fact]
    public async Task A503_IsNotRetried()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        handler.Map(ParPath, _ => OidcTestKit.JsonStatus(HttpStatusCode.ServiceUnavailable, "{}"));
        using AxiamClient client = OidcTestKit.Client(handler);
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        await Assert.ThrowsAnyAsync<Exception>(() => client.OidcParAsync(
            new OidcParParams { Request = begun, RedirectUri = RedirectUri, Configuration = config }));

        // §26.2 rule 4: a POST that creates server state falls outside §16.2's read-only
        // eligibility. The safe recovery is a fresh push, which cannot double-consume
        // anything.
        Assert.Equal(1, handler.CountFor(ParPath));
    }

    [Fact]
    public async Task AResponseWithNoRequestUri_IsANetworkError()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        handler.Map(ParPath, _ => OidcTestKit.JsonStatus(HttpStatusCode.Created, """{"expires_in":90}"""));
        using AxiamClient client = OidcTestKit.Client(handler);
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        await Assert.ThrowsAsync<NetworkError>(() => client.OidcParAsync(
            new OidcParParams { Request = begun, RedirectUri = RedirectUri, Configuration = config }));
    }

    // -----------------------------------------------------------------------
    // §26.5 / discovery
    // -----------------------------------------------------------------------

    [Fact]
    public async Task TheRequestUriIsSensitive()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapPar(handler);
        using AxiamClient client = OidcTestKit.Client(handler);
        (OidcConfiguration config, AuthorizationRequest begun) = await BeginAsync(client);

        PushedAuthorizationRequest pushed = await client.OidcParAsync(
            new OidcParParams { Request = begun, RedirectUri = RedirectUri, Configuration = config });

        // Between the push and the redirect it is a bearer handle to a fully-formed
        // authorization request (§26.5). The URL it goes into is not secret; the bare
        // handle in a log line is.
        Assert.DoesNotContain(RequestUri, pushed.RequestUri.ToString());
        Assert.Equal(RequestUri, HttpUtility.ParseQueryString(new Uri(pushed.Url).Query)["request_uri"]);
    }

    [Fact]
    public async Task Discovery_ExposesThePushedAuthorizationRequestEndpoint()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        using AxiamClient client = OidcTestKit.Client(handler);

        OidcConfiguration config = await client.OidcDiscoverAsync();

        Assert.Equal("https://axiam.test/oauth2/par", config.PushedAuthorizationRequestEndpoint);
    }

    [Fact]
    public async Task Discovery_WithoutPar_ParsesWithANullEndpoint()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler, withOptionalEndpoints: false);
        using AxiamClient client = OidcTestKit.Client(handler);

        // Absent, not empty: §26 is optional, and an SDK that synthesized an endpoint here
        // would POST a fully-formed authorization request at a 404.
        Assert.Null((await client.OidcDiscoverAsync()).PushedAuthorizationRequestEndpoint);
    }
}
