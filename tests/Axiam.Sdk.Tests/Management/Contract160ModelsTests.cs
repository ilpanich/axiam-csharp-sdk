using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// CONTRACT.md &#167;27.15 (contract 1.60): <c>window_minutes</c> on the notification rules
/// (note 1, its one required test), the federation configuration's
/// <c>allow_sha1_signatures</c> and <c>idp_metadata_signing_cert_pem</c> (notes 6 and 7), and the
/// <c>federation.update_config</c> null rule (note 8), all over the wire.
/// </summary>
public sealed class Contract160ModelsTests : ManagementTestBase
{
    private const string Rules = "/api/v1/notification-rules";
    private const string Configs = "/api/v1/federation-configs";

    private static string RuleBody(int? windowMinutes) => new JsonObject
    {
        ["id"] = Guid.NewGuid().ToString(),
        ["tenant_id"] = TenantId.ToString(),
        ["name"] = "lockouts",
        ["description"] = "account lockouts",
        ["events"] = new JsonArray("account_locked"),
        ["recipient_emails"] = new JsonArray("soc@example.com"),
        ["enabled"] = true,
        ["window_minutes"] = windowMinutes,
        ["created_at"] = "2026-10-05T00:00:00Z",
        ["updated_at"] = "2026-10-05T00:00:00Z",
    }.ToJsonString();

    private static CreateNotificationRuleRequest Rule(int? windowMinutes) => new()
    {
        Name = "lockouts",
        Description = "account lockouts",
        Events = new[] { NotificationEventType.AccountLocked },
        RecipientEmails = new[] { "soc@example.com" },
        WindowMinutes = windowMinutes,
    };

    private static string ConfigBody(Action<JsonObject>? edit = null)
    {
        var body = new JsonObject
        {
            ["id"] = ExampleId.ToString(),
            ["tenant_id"] = TenantId.ToString(),
            ["provider"] = "corp-idp",
            ["protocol"] = "Saml",
            ["provider_kind"] = "saml",
            ["client_id"] = "axiam-sp",
            ["metadata_url"] = "https://idp.example/metadata",
            ["attribute_map"] = null,
            ["enabled"] = true,
            ["token_exchange"] = new JsonObject
            {
                ["accepted_audiences"] = new JsonArray(),
                ["enabled"] = false,
                ["max_token_age_secs"] = 300,
                ["scope_map"] = new JsonObject(),
                ["subject_mapping"] = "email",
            },
            ["allow_tenant_inheritance"] = false,
            ["scopes"] = new JsonArray(),
            ["effective_scopes"] = new JsonArray(),
            ["allowed_issuer_tenants"] = new JsonArray(),
            ["allowed_algorithms"] = new JsonArray(),
            ["mints_client_secret"] = false,
            ["pkce_required"] = false,
            ["has_bundled_mark"] = false,
            ["created_at"] = "2026-10-05T00:00:00Z",
            ["updated_at"] = "2026-10-05T00:00:00Z",
        };
        edit?.Invoke(body);
        return body.ToJsonString();
    }

    /// <summary>
    /// &#167;27.15 note 1's required test: <c>create</c> with <c>window_minutes</c> sends it as
    /// given — an out-of-range value too, never clamped; the server judges it — <c>create</c>
    /// without it sends no such key, and a response carrying it decodes it.
    /// </summary>
    [Fact]
    public async Task WindowMinutesIsSentAsGivenNeverClampedOmittedWhenUnsetAndDecoded()
    {
        Route create = Mount("POST", Rules, 201, RuleBody(45));

        NotificationRuleResponse created = await Client.Management.NotificationRules.CreateAsync(Rule(45));
        Assert.Equal(45, create.Last.Json().GetProperty("window_minutes").GetInt32());
        Assert.Equal(45, created.WindowMinutes);

        foreach (int outOfRange in new[] { 0, 1441, -5 })
        {
            await Client.Management.NotificationRules.CreateAsync(Rule(outOfRange));
            Assert.Equal(outOfRange, create.Last.Json().GetProperty("window_minutes").GetInt32());
        }

        await Client.Management.NotificationRules.CreateAsync(Rule(null));
        Assert.False(create.Last.Json().TryGetProperty("window_minutes", out _));

        // The server's 400 for a value outside 1 … 1440 surfaces as the validation error.
        Mount("PUT", $"{Rules}/{ExampleId}", 400, """{"error":"validation_error","message":"window_minutes: must be 1 to 1440"}""");
        await Assert.ThrowsAsync<ValidationError>(() => Client.Management.NotificationRules.UpdateAsync(
            ExampleId, new UpdateNotificationRuleRequest { WindowMinutes = 5000 }));
        Assert.Equal(5000, RouteAt("PUT", $"{Rules}/{ExampleId}").Last.Json().GetProperty("window_minutes").GetInt32());
    }

    /// <summary>
    /// &#167;27.15 note 6: <c>allow_sha1_signatures</c> absent from a response (a server before
    /// 1.0.0) decodes as <c>false</c>; present, it decodes as sent. Note 7:
    /// <c>idp_metadata_signing_cert_pem</c> decodes, <c>null</c> when unset. On <c>create</c>
    /// neither is sent unless the caller sets it.
    /// </summary>
    [Fact]
    public async Task TheFederationMembersDecodeAndAreSentOnlyWhenSet()
    {
        Mount("GET", $"{Configs}/{ExampleId}", 200, ConfigBody());
        FederationConfigResponse old = await Client.Management.Federation.GetConfigAsync(ExampleId);
        Assert.False(old.AllowSha1Signatures);
        Assert.Null(old.IdpMetadataSigningCertPem);

        const string pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        Guid other = Guid.NewGuid();
        Mount("GET", $"{Configs}/{other}", 200, ConfigBody(b =>
        {
            b["allow_sha1_signatures"] = true;
            b["idp_metadata_signing_cert_pem"] = pem;
        }));
        FederationConfigResponse current = await Client.Management.Federation.GetConfigAsync(other);
        Assert.True(current.AllowSha1Signatures);
        Assert.Equal(pem, current.IdpMetadataSigningCertPem);

        Route create = Mount("POST", Configs, 201, ConfigBody());
        var request = new CreateFederationConfigRequest
        {
            Provider = "corp-idp",
            Protocol = "Saml",
            ClientId = "axiam-sp",
            ClientSecret = Sensitive<string>.Wrap(Secrets.Fresh()),
        };
        await Client.Management.Federation.CreateConfigAsync(request);
        JsonElement sent = create.Last.Json();
        Assert.False(sent.TryGetProperty("allow_sha1_signatures", out _));
        Assert.False(sent.TryGetProperty("idp_metadata_signing_cert_pem", out _));

        await Client.Management.Federation.CreateConfigAsync(request with
        {
            AllowSha1Signatures = false,
            IdpMetadataSigningCertPem = pem,
        });
        sent = create.Last.Json();
        Assert.Equal(JsonValueKind.False, sent.GetProperty("allow_sha1_signatures").ValueKind);
        Assert.Equal(pem, sent.GetProperty("idp_metadata_signing_cert_pem").GetString());
    }

    /// <summary>
    /// &#167;27.15 note 8 with &#167;27.4 rule 5's exact key-set test: on
    /// <c>federation.update_config</c> an explicit <c>null</c> is sent as <c>null</c> (it clears)
    /// and an unset member is not sent (it is kept) — the body is exactly the members named.
    /// </summary>
    [Fact]
    public async Task UpdateConfigSendsNullOnlyForTheMemberBeingCleared()
    {
        Route put = Mount("PUT", $"{Configs}/{ExampleId}", 200, ConfigBody());

        await Client.Management.Federation.UpdateConfigAsync(ExampleId, new UpdateFederationConfigRequest
        {
            IdpMetadataSigningCertPem = JsonNullable<string>.Null,
        });
        Assert.Equal("""{"idp_metadata_signing_cert_pem":null}""", put.Last.Body);

        await Client.Management.Federation.UpdateConfigAsync(ExampleId, new UpdateFederationConfigRequest
        {
            MetadataUrl = "https://idp.example/metadata-v2",
            ButtonIcon = JsonNullable<string>.Null,
            Enabled = true,
        });
        JsonElement sent = put.Last.Json();
        Assert.Equal(
            new[] { "button_icon", "enabled", "metadata_url" },
            sent.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
        Assert.Equal(JsonValueKind.Null, sent.GetProperty("button_icon").ValueKind);
        Assert.Equal("https://idp.example/metadata-v2", sent.GetProperty("metadata_url").GetString());

        await Client.Management.Federation.UpdateConfigAsync(ExampleId, new UpdateFederationConfigRequest());
        Assert.Equal("{}", put.Last.Body);
    }
}
