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
/// The four public "Sign in with X" operations added by contract 1.38 —
/// <see cref="AxiamClient.SsoProvidersAsync"/>,
/// <see cref="AxiamClient.SsoStartOauth2Async"/>,
/// <see cref="AxiamClient.SsoCompleteOauth2Async"/> and
/// <see cref="AxiamClient.SsoCompleteHandoffAsync"/> (CONTRACT.md &#167;12.1).
/// </summary>
/// <remarks>
/// <para>Two kinds of assertion live here, and both are needed.</para>
/// <para>The <b>wire-shape</b> tests read the vendored <c>openapi.json</c> and assert the
/// method, path, content type and — for <c>ssoProviders</c> — the <i>parameter location</i>
/// the server declares, then assert that what this SDK actually puts on the wire matches.
/// Asserting only against the mock would pin the SDK to the test's own idea of the endpoint;
/// asserting only against the spec would not notice an SDK that agrees with the spec and
/// calls something else.</para>
/// <para>The <b>rule</b> tests cover the four &#167;12.1 notes easiest to get quietly wrong:
/// note 9 (an empty provider list is a success, not a not-found), note 10 (<c>protocol</c>
/// selects the start operation), note 12 (a handoff <c>401</c> is terminal and is never
/// retried) and rule 12a (a <c>400</c> from a start call is a configuration refusal, not
/// something to retry).</para>
/// </remarks>
[Trait("Category", "Fast")]
public class OidcLoginProvidersTests
{
    private const string ProvidersPath = "/api/v1/auth/federation/providers";
    private const string OidcStartPath = "/api/v1/auth/federation/oidc/start";
    private const string OAuth2StartPath = "/api/v1/auth/federation/oauth2/start";
    private const string OAuth2CallbackPath = "/api/v1/auth/federation/oauth2/callback";
    private const string HandoffPath = "/api/v1/auth/federation/handoff";

    private const string ConfigId = "44444444-4444-4444-4444-444444444444";
    private const string RedirectUri = "https://app.example/after-sso";
    private const string OrgGuid = "33333333-3333-3333-3333-333333333333";

    private const string StartBody =
        """{"authorize_url":"https://upstream.example/authorize","state":"s-1","expires_in_secs":600}""";

    private const string SessionBody =
        """{"user_id":"99999999-8888-7777-6666-555555555555","session_id":"12121212-3434-5656-7878-909090909090","expires_in":900,"redirect_uri":"https://app.example/after-sso"}""";

    /// <summary>The vendored spec. These tests only read it.</summary>
    private static JsonDocument OpenApi() =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(RepoRoot(), "openapi.json")));

    private static string RepoRoot()
    {
        // The test assembly runs from tests/Axiam.Sdk.Tests/bin/<cfg>/<tfm>/; the vendored
        // artifact lives at the repository root. Walk up until openapi.json is found rather
        // than hard-coding a depth, which changes with the TFM matrix.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "openapi.json")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static AxiamClient ClientWithOrgId(RoutingHandler handler) =>
        OidcTestKit.Client(handler, OidcTestKit.Options() with { OrgId = Guid.Parse(OrgGuid) });

    private static string ProviderJson(string id, string kind, string protocol) =>
        $$"""{"id":"{{id}}","provider_kind":"{{kind}}","display_name":"{{kind}}","protocol":"{{protocol}}","has_bundled_mark":true,"inherited":false}""";

    // ------------------------------------------------------------------
    // Wire shape, against openapi.json
    // ------------------------------------------------------------------

    [Fact]
    public void OpenApi_DeclaresSsoProvidersAsAGetWithNoBody()
    {
        using JsonDocument spec = OpenApi();
        JsonElement op = spec.RootElement.GetProperty("paths").GetProperty(ProvidersPath).GetProperty("get");
        Assert.False(op.TryGetProperty("requestBody", out _), "ssoProviders is a GET and must have no request body (§12.1)");
        Assert.Equal(
            "#/components/schemas/PublicFederationProvidersResponse",
            op.GetProperty("responses").GetProperty("200").GetProperty("content")
              .GetProperty("application/json").GetProperty("schema").GetProperty("$ref").GetString());
    }

    [Theory]
    [InlineData(OAuth2StartPath, "OAuth2StartRequest", "OAuth2StartResponse")]
    [InlineData(OAuth2CallbackPath, "OAuth2CallbackRequest", "SsoLoginSuccessResponse")]
    [InlineData(HandoffPath, "SsoHandoffRequest", "SsoLoginSuccessResponse")]
    public void OpenApi_DeclaresTheThreePostsWithTheirContractSchemas(string path, string request, string response)
    {
        using JsonDocument spec = OpenApi();
        JsonElement op = spec.RootElement.GetProperty("paths").GetProperty(path).GetProperty("post");
        Assert.Equal(
            $"#/components/schemas/{request}",
            op.GetProperty("requestBody").GetProperty("content").GetProperty("application/json")
              .GetProperty("schema").GetProperty("$ref").GetString());
        Assert.Equal(
            $"#/components/schemas/{response}",
            op.GetProperty("responses").GetProperty("200").GetProperty("content")
              .GetProperty("application/json").GetProperty("schema").GetProperty("$ref").GetString());
    }

    /// <summary>
    /// &#167;12.1: the provider identifiers are <b>query</b> parameters. Asserted because
    /// the neighbouring start operations take the same four in a JSON body, and the two are
    /// one copy-paste apart.
    /// </summary>
    [Fact]
    public void OpenApi_PutsTheProviderIdentifiersInTheQueryString()
    {
        using JsonDocument spec = OpenApi();
        JsonElement parameters = spec.RootElement.GetProperty("paths").GetProperty(ProvidersPath)
            .GetProperty("get").GetProperty("parameters");

        var names = new List<string>();
        foreach (JsonElement parameter in parameters.EnumerateArray())
        {
            Assert.Equal("query", parameter.GetProperty("in").GetString());
            names.Add(parameter.GetProperty("name").GetString()!);
        }
        names.Sort(StringComparer.Ordinal);
        Assert.Equal(new[] { "org_id", "org_slug", "tenant_id", "tenant_slug" }, names);
    }

    /// <summary>
    /// The six required fields plus the nullable <c>button_icon</c>, and none of the
    /// configuration a narrowed admin response would have leaked (&#167;12.1 note 9).
    /// </summary>
    [Fact]
    public void OpenApi_PublicProviderShapeMatchesTheSdkRecord()
    {
        using JsonDocument spec = OpenApi();
        JsonElement schema = spec.RootElement.GetProperty("components").GetProperty("schemas")
            .GetProperty("PublicFederationProvider");

        var required = schema.GetProperty("required").EnumerateArray().Select(e => e.GetString()!).ToList();
        required.Sort(StringComparer.Ordinal);
        Assert.Equal(
            new[] { "display_name", "has_bundled_mark", "id", "inherited", "protocol", "provider_kind" },
            required);

        JsonElement properties = schema.GetProperty("properties");
        JsonElement iconType = properties.GetProperty("button_icon").GetProperty("type");
        Assert.Contains("null", iconType.EnumerateArray().Select(e => e.GetString()));

        foreach (string absent in new[] { "client_id", "client_secret", "metadata_url", "token_endpoint" })
        {
            Assert.False(properties.TryGetProperty(absent, out _), $"the unauthenticated response must not carry {absent}");
        }
    }

    /// <summary>
    /// &#167;12.1 note 11: the verifier is generated and held server-side, so neither schema
    /// carries PKCE material and neither may the SDK.
    /// </summary>
    [Theory]
    [InlineData("OAuth2StartRequest")]
    [InlineData("OAuth2StartResponse")]
    public void OpenApi_Oauth2StartCarriesNoPkceMaterial(string schemaName)
    {
        using JsonDocument spec = OpenApi();
        JsonElement properties = spec.RootElement.GetProperty("components").GetProperty("schemas")
            .GetProperty(schemaName).GetProperty("properties");
        foreach (string pkce in new[] { "code_verifier", "code_challenge", "code_challenge_method" })
        {
            Assert.False(properties.TryGetProperty(pkce, out _), $"{schemaName} must not carry {pkce}");
        }
    }

    // ------------------------------------------------------------------
    // SsoProvidersAsync — wire shape and §12.1 note 9
    // ------------------------------------------------------------------

    [Fact]
    public async Task SsoProvidersAsync_SendsIdentifiersAsQueryParametersAndNoBody()
    {
        using var handler = new RoutingHandler();
        handler.Map(ProvidersPath, _ => OidcTestKit.JsonOk("""{"providers":[]}"""));
        // A slug-configured client, so the slug forms are what resolve. The UUID form wins
        // when both are available, exactly as it does for SsoStartAsync.
        var options = new AxiamClientOptions
        {
            BaseUrl = OidcTestKit.BaseUrl,
            TenantId = "acme",
            OidcClientId = OidcTestKit.ClientId,
            OrgSlug = "acme-org",
        };
        AxiamClient client = OidcTestKit.Client(handler, options, tenantId: "acme");

        await client.SsoProvidersAsync(new SsoProvidersParams { OrgSlug = "other-org", TenantSlug = "engineering" });

        HttpRequestMessage request = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == ProvidersPath);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Null(request.Content);
        Assert.Contains("org_slug=other-org", request.RequestUri!.Query);
        Assert.Contains("tenant_slug=engineering", request.RequestUri!.Query);
        Assert.DoesNotContain("org_id=", request.RequestUri!.Query);
    }

    [Fact]
    public async Task SsoProvidersAsync_DefaultsTheWorkspaceFromClientConfiguration()
    {
        using var handler = new RoutingHandler();
        handler.Map(ProvidersPath, _ => OidcTestKit.JsonOk("""{"providers":[]}"""));
        AxiamClient client = ClientWithOrgId(handler);

        await client.SsoProvidersAsync();

        HttpRequestMessage request = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == ProvidersPath);
        Assert.Contains($"org_id={OrgGuid}", request.RequestUri!.Query);
        Assert.Contains($"tenant_id={OidcTestKit.TenantGuid}", request.RequestUri!.Query);
    }

    /// <summary>
    /// &#167;12.1 note 9. The three cases the endpoint makes indistinguishable — unknown
    /// organization, known-but-empty, and no workspace named — are all ordinary successes.
    /// Mapping any of them to an error would restore the two-valued answer the empty list
    /// removes, and with it the organization-slug oracle.
    /// </summary>
    [Fact]
    public async Task AnEmptyProviderListIsASuccessNotAnError()
    {
        using var handler = new RoutingHandler();
        handler.Map(ProvidersPath, _ => OidcTestKit.JsonOk("""{"providers":[]}"""));
        AxiamClient client = ClientWithOrgId(handler);

        foreach (SsoProvidersParams @params in new[]
        {
            new SsoProvidersParams { OrgSlug = "no-such-organization" },
            new SsoProvidersParams { OrgId = Guid.Parse(OrgGuid), TenantId = Guid.Parse(OidcTestKit.TenantGuid) },
            new SsoProvidersParams(),
        })
        {
            FederationProviderList list = await client.SsoProvidersAsync(@params);
            Assert.Empty(list.Providers);
        }
    }

    /// <summary>
    /// The consequence of note 9 easiest to get wrong: unlike the start operations, a
    /// request resolving no organization is <b>sent</b> rather than refused client-side. A
    /// <c>400</c> for "you named nothing" against a <c>200 []</c> for an unknown slug would
    /// be that same two-valued answer by another route.
    /// </summary>
    [Fact]
    public async Task SsoProvidersAsync_SendsTheRequestEvenWithNoOrganizationContext()
    {
        using var handler = new RoutingHandler();
        handler.Map(ProvidersPath, _ => OidcTestKit.JsonOk("""{"providers":[]}"""));
        // No OrgId/OrgSlug: SsoStartAsync refuses this same client, client-side.
        var options = new AxiamClientOptions
        {
            BaseUrl = OidcTestKit.BaseUrl,
            TenantId = "acme",
            OidcClientId = OidcTestKit.ClientId,
        };
        AxiamClient client = OidcTestKit.Client(handler, options, tenantId: "acme");

        await Assert.ThrowsAsync<AuthError>(() => client.SsoStartAsync(new SsoStartParams
        {
            FederationConfigId = ConfigId,
            RedirectUri = RedirectUri,
        }));

        FederationProviderList list = await client.SsoProvidersAsync();
        Assert.Empty(list.Providers);
        Assert.Equal(1, handler.CountFor(ProvidersPath));
        Assert.Equal(0, handler.CountFor(OidcStartPath));
    }

    [Fact]
    public async Task SsoProvidersAsync_MapsEveryFieldIncludingTheNullableButtonIcon()
    {
        using var handler = new RoutingHandler();
        handler.Map(ProvidersPath, _ => OidcTestKit.JsonOk(
            """
            {"providers":[
              {"id":"11111111-1111-1111-1111-111111111111","provider_kind":"google","display_name":"Google",
               "protocol":"OidcConnect","has_bundled_mark":true,"inherited":true,"button_icon":null},
              {"id":"22222222-2222-2222-2222-222222222222","provider_kind":"generic_oauth2","display_name":"Acme SSO",
               "protocol":"OAuth2","has_bundled_mark":false,"inherited":false,
               "button_icon":"data:image/png;base64,iVBORw0KGgo="}]}
            """));
        AxiamClient client = ClientWithOrgId(handler);

        FederationProviderList list = await client.SsoProvidersAsync();

        Assert.Equal(2, list.Providers.Count);
        FederationProvider google = list.Providers[0];
        Assert.Equal("google", google.ProviderKind);
        Assert.Equal(FederationProtocols.OidcConnect, google.Protocol);
        Assert.True(google.HasBundledMark);
        // Reported so an admin surface can show that a provider is not the tenant's to
        // edit; nothing here computes it (§12.1 note 13).
        Assert.True(google.Inherited);
        Assert.Null(google.ButtonIcon);

        FederationProvider acme = list.Providers[1];
        Assert.Equal(FederationProtocols.OAuth2, acme.Protocol);
        Assert.False(acme.HasBundledMark);
        Assert.Equal("data:image/png;base64,iVBORw0KGgo=", acme.ButtonIcon);
    }

    [Fact]
    public async Task SsoProvidersAsync_NonOkStatusMapsThroughTheTaxonomy()
    {
        using var handler = new RoutingHandler();
        handler.Map(ProvidersPath, _ => OidcTestKit.Empty(HttpStatusCode.InternalServerError));
        AxiamClient client = ClientWithOrgId(handler);

        await Assert.ThrowsAsync<NetworkError>(() => client.SsoProvidersAsync());
    }

    // ------------------------------------------------------------------
    // §12.1 note 10 — protocol selects the start operation
    // ------------------------------------------------------------------

    /// <summary>
    /// All three branches, asserted on which endpoint the resulting call reached.
    /// </summary>
    /// <remarks>
    /// <c>provider_kind</c> is deliberately misleading in this fixture: the <c>Saml</c> row
    /// is <c>google</c>, the kind whose OIDC connector everybody assumes. A dispatch that
    /// read the kind would send it to the OIDC start endpoint and be caught by the
    /// per-endpoint counts.
    /// </remarks>
    [Fact]
    public async Task ProtocolSelectsTheStartOperationForAllThreeBranches()
    {
        using var handler = new RoutingHandler();
        handler.Map(ProvidersPath, _ => OidcTestKit.JsonOk(
            $$"""
            {"providers":[
              {{ProviderJson("11111111-1111-1111-1111-111111111111", "microsoft", "OidcConnect")}},
              {{ProviderJson("22222222-2222-2222-2222-222222222222", "github", "OAuth2")}},
              {{ProviderJson("55555555-5555-5555-5555-555555555555", "google", "Saml")}}]}
            """));
        handler.Map(OidcStartPath, _ => OidcTestKit.JsonOk(StartBody));
        handler.Map(OAuth2StartPath, _ => OidcTestKit.JsonOk(StartBody));
        AxiamClient client = ClientWithOrgId(handler);

        FederationProviderList list = await client.SsoProvidersAsync();
        bool samlSeen = false;
        foreach (FederationProvider provider in list.Providers)
        {
            switch (provider.Protocol)
            {
                case FederationProtocols.OidcConnect:
                    await client.SsoStartAsync(new SsoStartParams { FederationConfigId = provider.Id, RedirectUri = RedirectUri });
                    break;
                case FederationProtocols.OAuth2:
                    await client.SsoStartOauth2Async(new SsoStartOauth2Params { FederationConfigId = provider.Id, RedirectUri = RedirectUri });
                    break;
                case FederationProtocols.Saml:
                    // Saml goes to the SAML login endpoint, which §12.1 note 10 says is NOT
                    // a §12 vocabulary operation. The branch exists so a Saml provider is
                    // never quietly handed to one of the other two.
                    samlSeen = true;
                    break;
                default:
                    throw new Xunit.Sdk.XunitException($"unknown protocol {provider.Protocol}");
            }
        }

        Assert.True(samlSeen, "the Saml branch must be reachable");
        Assert.Equal(1, handler.CountFor(OidcStartPath));
        Assert.Equal(1, handler.CountFor(OAuth2StartPath));
    }

    // ------------------------------------------------------------------
    // SsoStartOauth2Async
    // ------------------------------------------------------------------

    [Fact]
    public async Task SsoStartOauth2Async_PostsTheBodyAndSendsNoPkce()
    {
        using var handler = new RoutingHandler();
        handler.Map(OAuth2StartPath, _ => OidcTestKit.JsonOk(StartBody));
        AxiamClient client = ClientWithOrgId(handler);

        SsoStartResult result = await client.SsoStartOauth2Async(new SsoStartOauth2Params
        {
            FederationConfigId = ConfigId,
            RedirectUri = RedirectUri,
        });

        Assert.Equal("s-1", result.State);
        Assert.Equal(600, result.ExpiresInSecs);

        HttpRequestMessage request = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == OAuth2StartPath);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);
        string body = await request.Content!.ReadAsStringAsync();
        Assert.Contains(ConfigId, body);
        Assert.Contains(RedirectUri, body);
        Assert.Contains(OidcTestKit.TenantGuid, body);
        Assert.Contains(OrgGuid, body);
        // §12.1 note 11: the verifier is server-side. Its absence is the contract.
        foreach (string pkce in new[] { "code_verifier", "code_challenge", "code_challenge_method" })
        {
            Assert.DoesNotContain(pkce, body);
        }
    }

    [Fact]
    public async Task SsoStartOauth2Async_RefusesClientSideWithoutOrgContext()
    {
        using var handler = new RoutingHandler();
        var options = new AxiamClientOptions
        {
            BaseUrl = OidcTestKit.BaseUrl,
            TenantId = "acme",
            OidcClientId = OidcTestKit.ClientId,
        };
        AxiamClient client = OidcTestKit.Client(handler, options, tenantId: "acme");

        AuthError error = await Assert.ThrowsAsync<AuthError>(() => client.SsoStartOauth2Async(new SsoStartOauth2Params
        {
            FederationConfigId = ConfigId,
            RedirectUri = RedirectUri,
        }));

        Assert.Contains("organization context", error.Message);
        Assert.Empty(handler.Requests);
    }

    // ------------------------------------------------------------------
    // §12.1 rule 12a — a 400 from a start call is a configuration refusal
    // ------------------------------------------------------------------

    /// <summary>
    /// On the SAML and Apple flows the identity provider never validates the SPA
    /// <c>redirect_uri</c>, so the server confines it to its own issuer origin plus
    /// <c>AXIAM__AUTH__SSO_SPA_ORIGINS</c> and answers <c>400</c> otherwise.
    /// </summary>
    /// <remarks>
    /// That <c>400</c> is a <b>configuration</b> refusal — &#167;2's <c>400</c> row, whose
    /// taxonomy member in this SDK is <see cref="NetworkError"/>, as distinct from the
    /// <see cref="AuthError"/> an unknown workspace gets. It must not be retried: the
    /// deployment will refuse the same origin every time. Asserted on both start operations,
    /// because Apple arrives over the OIDC one and a caller can reach the refusal from
    /// either entry point.
    /// </remarks>
    [Theory]
    [InlineData(OidcStartPath)]
    [InlineData(OAuth2StartPath)]
    public async Task A400FromEitherStartCallIsAConfigurationErrorAndIsNotRetried(string path)
    {
        using var handler = new RoutingHandler();
        handler.Map(path, _ => OidcTestKit.JsonStatus(HttpStatusCode.BadRequest, """{"message":"redirect_uri origin refused"}"""));
        AxiamClient client = ClientWithOrgId(handler);

        await Assert.ThrowsAsync<NetworkError>(() => path == OidcStartPath
            ? client.SsoStartAsync(new SsoStartParams { FederationConfigId = ConfigId, RedirectUri = "https://attacker.example/" })
            : client.SsoStartOauth2Async(new SsoStartOauth2Params { FederationConfigId = ConfigId, RedirectUri = "https://attacker.example/" }));

        Assert.Equal(1, handler.CountFor(path));
    }

    /// <summary>
    /// A <c>401</c> is the uniform "unknown workspace or provider" answer, and a
    /// <i>different</i> taxonomy member from the rule-12a <c>400</c>. Asserted so the two
    /// cannot quietly collapse into one.
    /// </summary>
    [Fact]
    public async Task A401FromAStartCallStaysAnAuthError()
    {
        using var handler = new RoutingHandler();
        handler.Map(OAuth2StartPath, _ => OidcTestKit.JsonStatus(HttpStatusCode.Unauthorized, """{"message":"unauthorized"}"""));
        AxiamClient client = ClientWithOrgId(handler);

        await Assert.ThrowsAsync<AuthError>(() => client.SsoStartOauth2Async(new SsoStartOauth2Params
        {
            FederationConfigId = ConfigId,
            RedirectUri = RedirectUri,
        }));
    }

    // ------------------------------------------------------------------
    // The two completions, and §12.1 note 12
    // ------------------------------------------------------------------

    [Fact]
    public async Task SsoCompleteOauth2Async_PostsStateAndCodeAndMapsTheSuccessBody()
    {
        using var handler = new RoutingHandler();
        handler.Map(OAuth2CallbackPath, _ => OidcTestKit.JsonOk(SessionBody));
        AxiamClient client = ClientWithOrgId(handler);

        SsoCompleteResult result = await client.SsoCompleteOauth2Async(new SsoCompleteOauth2Params
        {
            State = "abc",
            Code = "provider-code",
        });

        Assert.Equal("99999999-8888-7777-6666-555555555555", result.UserId);
        Assert.Equal(900, result.ExpiresIn);
        Assert.Equal(RedirectUri, result.RedirectUri);

        HttpRequestMessage request = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == OAuth2CallbackPath);
        string body = await request.Content!.ReadAsStringAsync();
        Assert.Contains("\"state\":\"abc\"", body);
        Assert.Contains("\"code\":\"provider-code\"", body);
    }

    [Fact]
    public async Task SsoCompleteHandoffAsync_PostsJustTheCode()
    {
        using var handler = new RoutingHandler();
        handler.Map(HandoffPath, _ => OidcTestKit.JsonOk(SessionBody));
        AxiamClient client = ClientWithOrgId(handler);

        SsoCompleteResult result = await client.SsoCompleteHandoffAsync(new SsoCompleteHandoffParams { Code = "handoff-code" });

        Assert.Equal("12121212-3434-5656-7878-909090909090", result.SessionId);

        HttpRequestMessage request = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == HandoffPath);
        string body = await request.Content!.ReadAsStringAsync();
        Assert.Contains("\"code\":\"handoff-code\"", body);
        Assert.DoesNotContain("state", body);
    }

    /// <summary>
    /// &#167;12.1 note 12. Unknown, expired and already-redeemed all answer the same
    /// <c>401</c>, on purpose. The code is spent either way, so a retry cannot succeed and
    /// would only widen the window in which it sits in a log.
    /// </summary>
    [Fact]
    public async Task AHandoff401IsTerminalAndIsNotRetried()
    {
        using var handler = new RoutingHandler();
        handler.Map(HandoffPath, _ => OidcTestKit.JsonStatus(HttpStatusCode.Unauthorized, """{"message":"unauthorized"}"""));
        AxiamClient client = ClientWithOrgId(handler);

        await Assert.ThrowsAsync<AuthError>(() => client.SsoCompleteHandoffAsync(
            new SsoCompleteHandoffParams { Code = "spent-or-expired-or-never-existed" }));

        Assert.Equal(1, handler.CountFor(HandoffPath));
    }

    /// <summary>
    /// The two values a caller codes against: it reads the code out of
    /// <c>?axiam_handoff=</c> and has 60 seconds to spend it.
    /// </summary>
    [Fact]
    public void TheHandoffParameterAndTtlAreWhatTheContractSays()
    {
        Assert.Equal("axiam_handoff", FederationHandoff.QueryParam);
        Assert.Equal(60L, FederationHandoff.CodeTtlSeconds);
    }

    /// <summary>
    /// &#167;12.2: C# takes the <c>Async</c> suffix on all four — every one performs network
    /// I/O, so the <c>OidcBegin</c> exception does not extend to them. Asserted on the type
    /// so a future rename cannot quietly drop the suffix.
    /// </summary>
    [Fact]
    public void AllFourOperationsCarryTheAsyncSuffix()
    {
        foreach (string name in new[]
        {
            "SsoProvidersAsync", "SsoStartOauth2Async", "SsoCompleteOauth2Async", "SsoCompleteHandoffAsync",
        })
        {
            Assert.NotNull(typeof(AxiamClient).GetMethod(name));
        }
        foreach (string unsuffixed in new[]
        {
            "SsoProviders", "SsoStartOauth2", "SsoCompleteOauth2", "SsoCompleteHandoff",
        })
        {
            Assert.Null(typeof(AxiamClient).GetMethod(unsuffixed));
        }
    }
}
