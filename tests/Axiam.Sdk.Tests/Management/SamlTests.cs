using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>The <c>saml</c> namespace — CONTRACT.md &#167;29.8's eight required tests.</summary>
public sealed class SamlTests : ManagementTestBase
{
    private static string Saml => $"/api/v1/tenants/{TenantId}/saml";

    private static JsonObject SpBody(Action<JsonObject>? edit = null)
    {
        var body = JsonNode.Parse(
            $$"""
              {"id":"{{Guid.NewGuid()}}","tenant_id":"{{TenantId}}","enabled":true,
               "display_name":"Payroll","entity_id":"https://payroll.example/sp",
               "acs_urls":[{"url":"https://payroll.example/acs","binding":"http_post","index":0,"is_default":true}],
               "slo_url":null,"slo_binding":null,"name_id_format":"persistent",
               "sign_responses":true,"encrypt_assertions":false,
               "sp_signing_cert_pem":null,"sp_encryption_cert_pem":null,
               "want_authn_requests_signed":false,"allow_idp_initiated":false,
               "attribute_mappings":[],"allowed_groups":[],
               "created_at":"2026-10-04T00:00:00Z","updated_at":"2026-10-04T00:00:00Z"}
              """)!.AsObject();
        edit?.Invoke(body);
        return body;
    }

    private static JsonObject CredentialBody(string status, Action<JsonObject>? edit = null)
    {
        var body = JsonNode.Parse(
            $$"""
              {"id":"{{Guid.NewGuid()}}","tenant_id":"{{TenantId}}","issuer_ca_id":"{{Guid.NewGuid()}}",
               "certificate_pem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
               "serial":"0a1b","fingerprint":"{{new string('a', 64)}}",
               "not_before":"2026-10-04T00:00:00Z","not_after":"2027-10-04T00:00:00Z",
               "status":"{{status}}","created_at":"2026-10-04T00:00:00Z","retired_at":null}
              """)!.AsObject();
        edit?.Invoke(body);
        return body;
    }

    private static SamlServiceProviderInput Input() => new()
    {
        AcsUrls = new[]
        {
            new AcsEndpoint { Binding = SamlBinding.HttpPost, Index = 0, IsDefault = true, Url = "https://payroll.example/acs" },
        },
        DisplayName = "Payroll",
        EntityId = "https://payroll.example/sp",
    };

    /// <summary>&#167;29.8 (1): update PUTs the whole registration; the input needs its three required members.</summary>
    [Fact]
    public async Task UpdateServiceProviderPutsTheWholeRegistration()
    {
        Guid id = Guid.NewGuid();
        Mount("GET", $"{Saml}/service-providers/{id}", 200, SpBody().ToJsonString());
        Route put = Mount("PUT", $"{Saml}/service-providers/{id}", 200,
            SpBody(b => b["display_name"] = "Payroll (EU)").ToJsonString());

        SamlServiceProvider read = await Client.Saml.GetServiceProviderAsync(id);
        SamlServiceProvider updated = await Client.Saml.UpdateServiceProviderAsync(
            id, read.ToInput() with { DisplayName = "Payroll (EU)" });

        Assert.Equal("PUT", put.Last.Method);
        JsonElement sent = put.Last.Json();
        foreach (string member in new[]
                 {
                     "acs_urls", "allow_idp_initiated", "allowed_groups", "attribute_mappings",
                     "display_name", "enabled", "encrypt_assertions", "entity_id", "name_id_format",
                     "sign_responses", "want_authn_requests_signed",
                 })
        {
            Assert.True(sent.TryGetProperty(member, out _), $"{member} not sent");
        }

        Assert.Equal("Payroll (EU)", sent.GetProperty("display_name").GetString());
        Assert.Equal("Payroll (EU)", updated.DisplayName);
        foreach (string name in new[] { "DisplayName", "EntityId", "AcsUrls" })
        {
            Assert.NotNull(typeof(SamlServiceProviderInput).GetProperty(name)!
                .GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>());
        }
    }

    /// <summary>&#167;29.8 (2): no sign_assertions member; unknown members and values decode; nothing unknown is sent back.</summary>
    [Fact]
    public async Task SignAssertionsDoesNotExistAndUnknownValuesDecode()
    {
        Guid id = Guid.NewGuid();
        JsonObject body = SpBody(b =>
        {
            b["sign_assertions"] = false;
            b["some_future_member"] = 1;
            b["acs_urls"]![0]!["binding"] = "http_artifact";
        });
        Mount("GET", $"{Saml}/service-providers/{id}", 200, body.ToJsonString());
        Route put = Mount("PUT", $"{Saml}/service-providers/{id}", 200, SpBody().ToJsonString());

        SamlServiceProvider sp = await Client.Saml.GetServiceProviderAsync(id);
        Assert.Equal(SamlBinding.Unknown, sp.AcsUrls[0].Binding);
        Assert.Null(typeof(SamlServiceProvider).GetProperty("SignAssertions"));
        Assert.Null(typeof(SamlServiceProviderInput).GetProperty("SignAssertions"));

        // An unknown value is decoded but not sent: replace it before writing back.
        SamlServiceProviderInput input = sp.ToInput();
        input = input with { AcsUrls = new[] { input.AcsUrls[0] with { Binding = SamlBinding.HttpPost } } };
        await Client.Saml.UpdateServiceProviderAsync(id, input);
        JsonElement sent = put.Last.Json();
        Assert.False(sent.TryGetProperty("sign_assertions", out _));
        Assert.False(sent.TryGetProperty("some_future_member", out _));
        Assert.Equal("http_post", sent.GetProperty("acs_urls")[0].GetProperty("binding").GetString());
    }

    /// <summary>&#167;29.8 (3): exactly one metadata member; both or neither refused locally; the draft creates unchanged.</summary>
    [Fact]
    public async Task ParseSpMetadataSendsExactlyOneMemberAndTheDraftCreates()
    {
        var draft = JsonNode.Parse(
            $$"""
              {"service_provider":{"display_name":"Imported","entity_id":"https://imported.example/sp",
                "acs_urls":[{"url":"https://imported.example/acs","binding":"http_post","index":1,"is_default":false}],
                "want_authn_requests_signed":true,
                "sp_signing_cert_pem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"},
               "signing_certificate_fingerprint":"{{new string('c', 64)}}",
               "encryption_certificate_fingerprint":null,
               "warnings":["the metadata's signature was not evaluated"]}
              """)!;
        Route parse = Mount("POST", $"{Saml}/parse-sp-metadata", 200, draft.ToJsonString());
        Route create = Mount("POST", $"{Saml}/service-providers", 201, SpBody().ToJsonString());

        SamlSpMetadataDraft fromUrl = await Client.Saml.ParseSpMetadataAsync(
            ParseSamlSpMetadata.FromUrl("https://imported.example/metadata"));
        await Client.Saml.ParseSpMetadataAsync(ParseSamlSpMetadata.FromXml("<EntityDescriptor/>"));
        await Assert.ThrowsAsync<ValidationError>(() => Client.Saml.ParseSpMetadataAsync(
            new ParseSamlSpMetadata { MetadataUrl = "https://a", MetadataXml = "<x/>" }));
        await Assert.ThrowsAsync<ValidationError>(() => Client.Saml.ParseSpMetadataAsync(new ParseSamlSpMetadata()));

        Assert.Equal(2, parse.Calls);
        Assert.Equal("""{"metadata_url":"https://imported.example/metadata"}""", parse.Requests[0].Body);
        Assert.Equal(new[] { "metadata_xml" }, parse.Requests[1].Keys());
        Assert.Equal("<EntityDescriptor/>", parse.Requests[1].Json().GetProperty("metadata_xml").GetString());
        Assert.Single(fromUrl.Warnings);

        await Client.Saml.CreateServiceProviderAsync(fromUrl.ServiceProvider);
        Assert.True(
            JsonNode.DeepEquals(draft["service_provider"], JsonNode.Parse(create.Last.Body)),
            "the draft's service_provider is sent as the create body, unchanged");
    }

    /// <summary>&#167;29.8 (4): a credential has no key member; a promotion may retire nothing.</summary>
    [Fact]
    public async Task ACredentialHasNoKeyMemberAndPromotionMayRetireNothing()
    {
        string keyMaterial = Secrets.Fresh();
        string leaked = $"-----BEGIN PRIVATE KEY-----{keyMaterial}";
        Guid id = Guid.NewGuid();
        Mount("POST", $"{Saml}/idp-credentials/{id}/retire", 200,
            CredentialBody("retired", b => b["private_key_pem"] = leaked).ToJsonString());
        Mount("POST", $"{Saml}/idp-credentials/{id}/promote", 200,
            new JsonObject { ["active"] = CredentialBody("active"), ["retired"] = null }.ToJsonString());

        SamlIdpCredential credential = await Client.Saml.RetireIdpCredentialAsync(id);
        foreach ((string label, string rendering) in new[]
                 {
                     ("ToString", credential.ToString()),
                     ("Json", JsonSerializer.Serialize(credential)),
                 })
        {
            Secrets.AssertAbsent(rendering, keyMaterial, label);
            Assert.DoesNotContain("private_key", rendering, StringComparison.OrdinalIgnoreCase);
        }

        Assert.DoesNotContain(
            typeof(SamlIdpCredential).GetProperties(),
            p => p.Name.Contains("Key", StringComparison.OrdinalIgnoreCase));

        SamlIdpCredentialPromotion promotion = await Client.Saml.PromoteIdpCredentialAsync(id);
        Assert.Null(promotion.Retired);
        Assert.Equal(SamlIdpCredentialStatus.Active, promotion.Active.Status);
    }

    /// <summary>&#167;29.8 (5): service providers page with search on every request; credentials are a plain list.</summary>
    [Fact]
    public async Task ServiceProvidersPageWithSearchAndCredentialsAreAPlainList()
    {
        Route list = MountDynamic("GET", $"{Saml}/service-providers", 200, recorded =>
        {
            int offset = int.Parse(recorded.Query["offset"], System.Globalization.CultureInfo.InvariantCulture);
            string items = offset < 2 ? $"[{SpBody().ToJsonString()}]" : "[]";
            return $$"""{"items":{{items}},"total":2,"offset":{{offset}},"limit":1}""";
        });
        Mount("GET", $"{Saml}/idp-credentials", 200,
            new JsonArray(CredentialBody("next"), CredentialBody("active")).ToJsonString());

        Page<SamlServiceProvider> page = await Client.Saml.ListServiceProvidersAsync(PageRequest.Matching(1, "payroll"));
        Assert.Equal(2, page.Total);
        IReadOnlyList<SamlServiceProvider> all = await Client.Saml.ListServiceProvidersAllAsync(PageRequest.Matching(1, "payroll"));
        Assert.Equal(2, all.Count);
        Assert.True(list.Calls >= 3);
        Assert.All(list.Requests, r => Assert.Equal("payroll", r.Query["search"]));

        IReadOnlyList<SamlIdpCredential> credentials = await Client.Saml.ListIdpCredentialsAsync();
        Assert.Equal(2, credentials.Count);
        Assert.Equal(SamlIdpCredentialStatus.Next, credentials[0].Status);
    }

    /// <summary>&#167;29.8 (6): none of the seven writes is retried on a 503 (retry-enabled client).</summary>
    [Fact]
    public async Task NoneOfTheSevenWritesIsRetriedOn503()
    {
        Guid id = Guid.NewGuid();
        Route[] routes =
        {
            Mount("POST", $"{Saml}/service-providers", 503, string.Empty),
            Mount("PUT", $"{Saml}/service-providers/{id}", 503, string.Empty),
            Mount("DELETE", $"{Saml}/service-providers/{id}", 503, string.Empty),
            Mount("POST", $"{Saml}/parse-sp-metadata", 503, string.Empty),
            Mount("POST", $"{Saml}/idp-credentials", 503, string.Empty),
            Mount("POST", $"{Saml}/idp-credentials/{id}/promote", 503, string.Empty),
            Mount("POST", $"{Saml}/idp-credentials/{id}/retire", 503, string.Empty),
        };
        SamlApi s = Client.Saml;
        await Assert.ThrowsAsync<NetworkError>(() => s.CreateServiceProviderAsync(Input()));
        await Assert.ThrowsAsync<NetworkError>(() => s.UpdateServiceProviderAsync(id, Input()));
        await Assert.ThrowsAsync<NetworkError>(() => s.DeleteServiceProviderAsync(id));
        await Assert.ThrowsAsync<NetworkError>(() => s.ParseSpMetadataAsync(ParseSamlSpMetadata.FromUrl("https://m")));
        await Assert.ThrowsAsync<NetworkError>(() => s.IssueIdpCredentialAsync(
            new IssueSamlIdpCredential { IssuerCaId = Guid.NewGuid(), Slot = SamlIdpSlot.Next }));
        await Assert.ThrowsAsync<NetworkError>(() => s.PromoteIdpCredentialAsync(id));
        await Assert.ThrowsAsync<NetworkError>(() => s.RetireIdpCredentialAsync(id));
        Assert.All(routes, r => Assert.Equal(1, r.Calls));
    }

    /// <summary>&#167;29.8 (7): 400, 409 (create and promote), 404 and 503 map per &#167;2.</summary>
    [Fact]
    public async Task StatusesMapPerSection2()
    {
        Guid id = Guid.NewGuid();
        Mount("POST", $"{Saml}/service-providers", 409, """{"error":"conflict","message":"entity_id"}""");
        Mount("PUT", $"{Saml}/service-providers/{id}", 400,
            """{"error":"validation_error","message":"entity_id is immutable: register a new service provider"}""");
        Mount("GET", $"{Saml}/service-providers/{id}", 404, """{"error":"not_found","message":"no"}""");
        Mount("POST", $"{Saml}/idp-credentials/{id}/promote", 409, """{"error":"conflict","message":"not next"}""");
        Mount("POST", $"{Saml}/parse-sp-metadata", 503, """{"error":"service_unavailable","message":"saml"}""");
        Mount("GET", $"{Saml}/idp-credentials", 401, """{"error":"unauthorized"}""");

        await Assert.ThrowsAsync<ConflictError>(() => Client.Saml.CreateServiceProviderAsync(Input()));
        ValidationError v = await Assert.ThrowsAsync<ValidationError>(() => Client.Saml.UpdateServiceProviderAsync(id, Input()));
        Assert.Contains("register a new service provider", v.Message, StringComparison.Ordinal);
        await Assert.ThrowsAsync<NotFoundError>(() => Client.Saml.GetServiceProviderAsync(id));
        await Assert.ThrowsAsync<ConflictError>(() => Client.Saml.PromoteIdpCredentialAsync(id));
        NetworkError n = await Assert.ThrowsAsync<NetworkError>(
            () => Client.Saml.ParseSpMetadataAsync(ParseSamlSpMetadata.FromXml("<x/>")));
        Assert.IsNotType<ValidationError>(n);
        await Assert.ThrowsAsync<AuthError>(() => Client.Saml.ListIdpCredentialsAsync());
    }

    /// <summary>
    /// &#167;29.8 (8): get_idp is read, not cached; a null slot is kept apart from an absent
    /// member; the configured tenant is in the path with no tenant argument.
    /// </summary>
    [Fact]
    public async Task GetIdpIsNeverCachedAndKeepsNullApartFromAbsent()
    {
        Guid active = Guid.NewGuid();
        Route idp = Mount("GET", $"{Saml}/idp", 200,
            $$"""
              {"tenant_id":"{{TenantId}}","saml_available":true,"saml_idp_enabled":true,"metadata_served":true,
               "entity_id":"https://axiam.test/saml/v2/{{TenantId}}/metadata",
               "metadata_url":"https://axiam.test/saml/v2/{{TenantId}}/metadata",
               "sso_url":"https://axiam.test/saml/v2/{{TenantId}}/sso",
               "slo_url":"https://axiam.test/saml/v2/{{TenantId}}/slo",
               "active_credential_id":"{{active}}","next_credential_id":null}
              """);

        SamlIdpInfo first = await Client.Saml.GetIdpAsync();
        SamlIdpInfo second = await Client.Saml.GetIdpAsync();
        Assert.Equal(2, idp.Calls);
        Assert.Equal($"/api/v1/tenants/{TenantId}/saml/idp", idp.Last.Path);
        Assert.Equal(active, first.ActiveCredentialId!.Value);
        Assert.False(first.ActiveCredentialId.IsNull);
        Assert.NotNull(first.NextCredentialId);
        Assert.True(first.NextCredentialId!.IsNull);
        Assert.True(second.SamlAvailable && second.SamlIdpEnabled && second.MetadataServed);
        Assert.EndsWith("/sso", second.SsoUrl, StringComparison.Ordinal);
        Assert.EndsWith("/slo", second.SloUrl, StringComparison.Ordinal);
        Assert.Equal(TenantId, second.TenantId);

        // Absent stays absent: distinct from the null above.
        Mount("GET", $"{Saml}/idp", 200,
            $$"""
              {"tenant_id":"{{TenantId}}","saml_available":false,"saml_idp_enabled":false,"metadata_served":false,
               "entity_id":"e","metadata_url":"m","sso_url":"s","slo_url":"l"}
              """);
        SamlIdpInfo sparse = await Client.Saml.GetIdpAsync();
        Assert.Null(sparse.ActiveCredentialId);
        Assert.Null(sparse.NextCredentialId);
    }
}
