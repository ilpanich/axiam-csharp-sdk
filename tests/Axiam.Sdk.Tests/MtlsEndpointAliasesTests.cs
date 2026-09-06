using System.Net;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// RFC 8705 &#167;5 <c>mtls_endpoint_aliases</c> — CONTRACT.md &#167;21.3 rule 2
/// (contract 1.40).
/// </summary>
/// <remarks>
/// <para>The rule has one sentence and three named ways to get it wrong, and this class is
/// organised around them rather than around the SDK's method list:</para>
/// <list type="bullet">
///   <item>a call going over mTLS prefers the alias;</item>
///   <item>a call NOT going over mTLS keeps the top-level entry;</item>
///   <item>an ABSENT member means "no separate mTLS host", never "unsupported";</item>
///   <item>only the six listed endpoints are ever aliased — not
///   <c>authorization_endpoint</c>, <c>end_session_endpoint</c> or <c>jwks_uri</c>;</item>
///   <item><c>issuer</c> is not an endpoint, does not move, and still governs <c>iss</c>
///   validation by exact string.</item>
/// </list>
/// <para>Two origins stand in for the two listeners a deployment runs. The
/// <see cref="RoutingHandler"/> routes by path and records the full URI, so choosing the
/// wrong host is a recorded call the assertion can name. The §6.1 identity is set on the
/// options — which is exactly what <c>PresentsClientCertificate</c> reads, and what a real
/// client would present on every request.</para>
/// </remarks>
[Trait("Category", "Fast")]
public class MtlsEndpointAliasesTests
{
    private static readonly Uri MtlsBaseUrl = new("https://mtls.axiam.test");

    private static string ConventionalOrigin => OidcTestKit.BaseUrl.ToString().TrimEnd('/');
    private static string MtlsOrigin => MtlsBaseUrl.ToString().TrimEnd('/');

    /// <summary>A syntactically valid PEM pair. The tests inject a transport override, so
    /// nothing parses these — what matters is that the options carry an identity, which is
    /// what <c>PresentsClientCertificate</c> reads.</summary>
    private static readonly byte[] CertPem = System.Text.Encoding.ASCII.GetBytes(
        "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKZ0000000000MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n-----END CERTIFICATE-----\n");

    private static readonly byte[] KeyPem = System.Text.Encoding.ASCII.GetBytes(
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n");

    /// <summary>All six aliases on the mTLS origin.</summary>
    private static object AllAliases() => new
    {
        token_endpoint = $"{MtlsOrigin}/oauth2/token",
        userinfo_endpoint = $"{MtlsOrigin}/oauth2/userinfo",
        revocation_endpoint = $"{MtlsOrigin}/oauth2/revoke",
        introspection_endpoint = $"{MtlsOrigin}/oauth2/introspect",
        device_authorization_endpoint = $"{MtlsOrigin}/oauth2/device_authorization",
        pushed_authorization_request_endpoint = $"{MtlsOrigin}/oauth2/par",
    };

    /// <summary>The discovery document, optionally carrying <paramref name="aliases"/>.</summary>
    private static string DiscoveryJson(object? aliases)
    {
        string baseJson = OidcTestKit.DiscoveryJson(OidcTestKit.BaseUrl);
        if (aliases is null)
        {
            return baseJson;
        }
        var document = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(baseJson)!;
        document["mtls_endpoint_aliases"] =
            JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(aliases));
        return JsonSerializer.Serialize(document);
    }

    /// <summary>Maps discovery plus every OAuth2 endpoint, each replying with a body its
    /// caller will accept.</summary>
    private static RoutingHandler Handler(object? aliases)
    {
        var handler = new RoutingHandler();
        handler.Map("/.well-known/openid-configuration", _ => OidcTestKit.JsonOk(DiscoveryJson(aliases)));
        handler.Map("/oauth2/token", _ => OidcTestKit.JsonOk(
            OidcTestKit.TokenResponseJson("access-token-value")));
        handler.Map("/oauth2/introspect", _ => OidcTestKit.JsonOk("""{"active":true}"""));
        handler.Map("/oauth2/revoke", _ => OidcTestKit.JsonOk("{}"));
        handler.Map("/oauth2/device_authorization", _ => OidcTestKit.JsonOk(
            OidcTestKit.DeviceAuthorizationJson()));
        // 201, not 200: RFC 9126 §2.2 specifies Created, and the SDK asserts exactly that.
        handler.Map("/oauth2/par", _ => OidcTestKit.JsonStatus(
            HttpStatusCode.Created,
            """{"request_uri":"urn:ietf:params:oauth:request_uri:x","expires_in":60}"""));
        return handler;
    }

    private static AxiamClient Client(RoutingHandler handler, bool mtls)
    {
        AxiamClientOptions options = OidcTestKit.Options();
        if (mtls)
        {
            options = options with { ClientCertificatePem = CertPem, ClientKeyPem = KeyPem };
        }
        return OidcTestKit.Client(handler, options);
    }

    /// <summary>The host every request to <paramref name="path"/> was sent to.</summary>
    private static List<string> HostsFor(RoutingHandler handler, string path) =>
        handler.Requests
            .Where(r => r.RequestUri!.AbsolutePath == path)
            .Select(r => $"{r.RequestUri!.Scheme}://{r.RequestUri!.Authority}")
            .ToList();

    private static void AssertOnly(RoutingHandler handler, string path, string expectedOrigin) =>
        Assert.Equal(new[] { expectedOrigin }, HostsFor(handler, path));

    // -- The document round-trips the member --------------------------------

    [Fact]
    public async Task Discovery_ExposesTheMember_WhenPublished()
    {
        using RoutingHandler handler = Handler(AllAliases());
        AxiamClient client = Client(handler, mtls: false);

        OidcConfiguration configuration = await client.OidcDiscoverAsync();

        Assert.NotNull(configuration.MtlsEndpointAliases);
        Assert.Equal($"{MtlsOrigin}/oauth2/token", configuration.MtlsEndpointAliases!.TokenEndpoint);
        // Alongside, never instead of: the conventional entry is untouched.
        Assert.Equal($"{ConventionalOrigin}/oauth2/token", configuration.TokenEndpoint);
    }

    [Fact]
    public async Task Discovery_AbsentMemberIsNull_NotAnError()
    {
        using RoutingHandler handler = Handler(aliases: null);
        AxiamClient client = Client(handler, mtls: true);

        OidcConfiguration configuration = await client.OidcDiscoverAsync();

        Assert.Null(configuration.MtlsEndpointAliases);
    }

    // -- A call over mTLS prefers the alias ---------------------------------

    [Fact]
    public async Task EveryAliasableEndpoint_GoesToTheAliasHost()
    {
        using RoutingHandler handler = Handler(AllAliases());
        AxiamClient client = Client(handler, mtls: true);

        await client.LoginClientCredentialsAsync(new LoginClientCredentialsParams());
        await client.IntrospectAsync(new IntrospectParams { Token = Sensitive<string>.Wrap("t") });
        await client.RevokeAsync(new RevokeParams { Token = Sensitive<string>.Wrap("t") });
        await client.DeviceAuthorizeAsync(new DeviceAuthorizeParams());
        OidcConfiguration configuration = await client.OidcDiscoverAsync();
        AuthorizationRequest request = client.OidcBegin(
            configuration, new OidcBeginParams { RedirectUri = "https://app.example.com/cb" });
        await client.OidcParAsync(new OidcParParams
        {
            Request = request,
            RedirectUri = "https://app.example.com/cb",
        });

        foreach (string path in new[]
                 {
                     "/oauth2/token", "/oauth2/introspect", "/oauth2/revoke",
                     "/oauth2/device_authorization", "/oauth2/par",
                 })
        {
            AssertOnly(handler, path, MtlsOrigin);
        }
    }

    // -- Consequence 1: absence means "no separate host" --------------------

    [Fact]
    public async Task MtlsClientWithNoAliases_KeepsTheTopLevelEndpoints()
    {
        using RoutingHandler handler = Handler(aliases: null);
        AxiamClient client = Client(handler, mtls: true);

        // Not an error, and not the alias origin: a deployment running
        // client_auth = optional on one listener serves both populations at the
        // conventional endpoints and correctly publishes nothing.
        await client.IntrospectAsync(new IntrospectParams { Token = Sensitive<string>.Wrap("t") });

        AssertOnly(handler, "/oauth2/introspect", ConventionalOrigin);
    }

    [Fact]
    public async Task ClientNotDoingMtls_KeepsTheTopLevelEndpoints()
    {
        using RoutingHandler handler = Handler(AllAliases());
        AxiamClient client = Client(handler, mtls: false);

        await client.RevokeAsync(new RevokeParams { Token = Sensitive<string>.Wrap("t") });

        AssertOnly(handler, "/oauth2/revoke", ConventionalOrigin);
    }

    [Fact]
    public async Task PartialAliasObject_FallsBackPerEndpoint()
    {
        // RFC 8705 §5 does not require an OP to alias all six, and the shape of this
        // member must never be why a client stops working: an object naming only
        // token_endpoint is a valid document, and every endpoint it does not name falls
        // back to the top-level entry.
        using RoutingHandler handler = Handler(new { token_endpoint = $"{MtlsOrigin}/oauth2/token" });
        AxiamClient client = Client(handler, mtls: true);

        await client.LoginClientCredentialsAsync(new LoginClientCredentialsParams());
        await client.IntrospectAsync(new IntrospectParams { Token = Sensitive<string>.Wrap("t") });

        AssertOnly(handler, "/oauth2/token", MtlsOrigin);
        AssertOnly(handler, "/oauth2/introspect", ConventionalOrigin);
    }

    [Fact]
    public async Task UnsupportedGrant_IsStillReported_WhenNeitherLevelNamesIt()
    {
        using var handler = new RoutingHandler();
        // Neither level names the device endpoint.
        var document = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            OidcTestKit.DiscoveryJson(OidcTestKit.BaseUrl))!;
        document.Remove("device_authorization_endpoint");
        document["mtls_endpoint_aliases"] = JsonSerializer.Deserialize<JsonElement>(
            JsonSerializer.Serialize(new { token_endpoint = $"{MtlsOrigin}/oauth2/token" }));
        handler.Map("/.well-known/openid-configuration",
            _ => OidcTestKit.JsonOk(JsonSerializer.Serialize(document)));
        AxiamClient client = Client(handler, mtls: true);

        // The answer is still "this server does not support the device grant" — never a
        // URL built by concatenation.
        await Assert.ThrowsAsync<AuthError>(
            () => client.DeviceAuthorizeAsync(new DeviceAuthorizeParams()));
    }

    // -- Consequence 2: no alias is ever synthesised ------------------------

    [Fact]
    public async Task FrontChannelAndJwks_AreNeverAliased()
    {
        using RoutingHandler handler = Handler(AllAliases());
        AxiamClient client = Client(handler, mtls: true);
        OidcConfiguration configuration = await client.OidcDiscoverAsync();

        // A browser sent to an mTLS host raises a native certificate-chooser dialog most
        // users cannot answer, and jwks_uri is public key material that gains nothing from
        // a handshake.
        AuthorizationRequest request = client.OidcBegin(
            configuration, new OidcBeginParams { RedirectUri = "https://app.example.com/cb" });
        Assert.StartsWith($"{ConventionalOrigin}/oauth2/authorize", request.Url, StringComparison.Ordinal);

        string logout = await client.LogoutUrlAsync(
            new LogoutUrlParams(Sensitive<string>.Wrap("not-a-real-token"), Configuration: configuration));
        Assert.StartsWith($"{ConventionalOrigin}/oauth2/end_session", logout, StringComparison.Ordinal);

        Assert.Equal($"{ConventionalOrigin}/oauth2/jwks", configuration.JwksUri);
    }

    [Fact]
    public void AliasRecord_CarriesOnlyTheSixAliasableEndpoints()
    {
        // Naming them as a closed set is what makes authorization_endpoint,
        // end_session_endpoint and jwks_uri unrepresentable rather than merely unused. A
        // seventh property here would be an alias the SDK could synthesise.
        string[] properties = typeof(MtlsEndpointAliases)
            .GetProperties()
            .Where(p => p.Name != "EqualityContract")
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            new[]
            {
                "DeviceAuthorizationEndpoint",
                "IntrospectionEndpoint",
                "PushedAuthorizationRequestEndpoint",
                "RevocationEndpoint",
                "TokenEndpoint",
                "UserinfoEndpoint",
            },
            properties);
    }

    // -- Consequence 3: issuer is never aliased -----------------------------

    [Fact]
    public async Task Issuer_DoesNotMoveWithTheEndpoints()
    {
        using RoutingHandler handler = Handler(AllAliases());
        AxiamClient client = Client(handler, mtls: true);

        OidcConfiguration configuration = await client.OidcDiscoverAsync();

        // §12.4 rule 3 compares `iss` against THIS value by exact string, for every token
        // — including one minted at an alias endpoint. An SDK that derived an expected
        // issuer from the host it called would reject every token it obtains over mTLS.
        Assert.Equal(ConventionalOrigin, configuration.Issuer);
        Assert.NotEqual(MtlsOrigin, configuration.Issuer);
    }
}
