using System.Reflection;
using System.Text.Json;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// The <c>directory</c> namespace — CONTRACT.md &#167;30.8's six required tests, plus the
/// sync status and the read-modify-write helper. The bind secret is generated at run time.
/// </summary>
public sealed class DirectoryTests : ManagementTestBase
{
    private static string Directory => $"/api/v1/tenants/{TenantId}/directory";

    private static string ConfigBody(string? extraMember = null) =>
        $$"""
          {"id":"{{Guid.NewGuid()}}","tenant_id":"{{TenantId}}","enabled":true,"kind":"active_directory",
           "url":"ldaps://dc.corp.example","start_tls":false,"bind_dn":"cn=svc,dc=corp",
           "base_dn":"dc=corp","user_filter":"(sAMAccountName={username})",
           "user_attribute_map":{"username":"sAMAccountName","email":"mail",
                                 "display_name":"displayName","external_id":"objectGUID"},
           "group_base_dn":null,"group_filter":null,"group_member_attribute":"member",
           "group_nesting_depth":5,"group_mappings":[],"sync_interval_secs":3600,
           "jit_provisioning":false,"trust_anchors_pem":[]{{extraMember}},
           "created_at":"2026-10-04T00:00:00Z","updated_at":"2026-10-04T00:00:00Z"}
          """;

    private static SetDirectoryConfig SetBody(string? bindSecret) => new()
    {
        BaseDn = "dc=corp",
        BindDn = "cn=svc,dc=corp",
        BindSecret = bindSecret is null ? null : Sensitive<string>.Wrap(bindSecret),
        Enabled = true,
        Kind = DirectoryKind.ActiveDirectory,
        StartTls = false,
        Url = "ldaps://dc.corp.example",
        UserFilter = "(sAMAccountName={username})",
    };

    /// <summary>&#167;30.8 (1): the bind secret reaches the wire and no rendering.</summary>
    [Fact]
    public async Task TheBindSecretReachesTheWireAndNoRendering()
    {
        string secret = Secrets.Fresh();
        SetDirectoryConfig set = SetBody(secret);
        var update = new UpdateDirectoryConfig { BindSecret = Sensitive<string>.Wrap(secret) };
        foreach ((string label, string rendering) in new[]
                 {
                     ("set ToString", set.ToString()),
                     ("set Json", JsonSerializer.Serialize(set)),
                     ("update ToString", update.ToString()),
                     ("update Json", JsonSerializer.Serialize(update)),
                     ("update interpolation", $"{update}"),
                 })
        {
            Secrets.AssertAbsent(rendering, secret, label);
        }

        Route route = Mount("PUT", Directory, 400,
            """{"error":"validation_error","message":"url: plaintext LDAP is refused"}""");
        ValidationError e = await Assert.ThrowsAsync<ValidationError>(() => Client.Directory.SetAsync(set));
        Secrets.AssertAbsent(e.ToString(), secret, "error rendering");
        Assert.Equal(secret, route.Last.Json().GetProperty("bind_secret").GetString());
    }

    /// <summary>&#167;30.8 (2): a bind secret in a response is dropped, and the type has no member for it.</summary>
    [Fact]
    public async Task ABindSecretInAResponseIsDropped()
    {
        string leaked = Secrets.Fresh();
        Mount("GET", Directory, 200, ConfigBody($",\"bind_secret\":\"{leaked}\""));

        DirectoryConfig config = await Client.Directory.GetAsync();
        Secrets.AssertAbsent(config.ToString(), leaked, "ToString");
        Secrets.AssertAbsent(JsonSerializer.Serialize(config), leaked, "Json");
        Assert.Equal("ldaps://dc.corp.example", config.Url);
        Assert.DoesNotContain(
            typeof(DirectoryConfig).GetProperties(BindingFlags.Public | BindingFlags.Instance),
            p => p.Name.Contains("Secret", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>&#167;30.8 (3): the PATCH carries exactly the members it was given; an explicit null is sent as null.</summary>
    [Fact]
    public async Task UpdateSendsExactlyTheMembersItWasGiven()
    {
        Route route = Mount("PATCH", Directory, 200, ConfigBody());
        string secret = Secrets.Fresh();

        await Client.Directory.UpdateAsync(new UpdateDirectoryConfig { Enabled = false });
        Assert.Equal("""{"enabled":false}""", route.Last.Body);

        await Client.Directory.UpdateAsync(new UpdateDirectoryConfig
        {
            Url = "ldaps://dc2.corp.example",
            BindSecret = Sensitive<string>.Wrap(secret),
        });
        Assert.Equal(new[] { "bind_secret", "url" }, route.Last.Keys());
        Assert.Equal(secret, route.Last.Json().GetProperty("bind_secret").GetString());

        await Client.Directory.UpdateAsync(new UpdateDirectoryConfig { GroupFilter = JsonNullable<string>.Null });
        Assert.Equal("""{"group_filter":null}""", route.Last.Body);

        await Client.Directory.UpdateAsync(new UpdateDirectoryConfig { GroupBaseDn = "ou=groups,dc=corp" });
        Assert.Equal("""{"group_base_dn":"ou=groups,dc=corp"}""", route.Last.Body);

        Assert.All(route.Requests, r => Assert.Equal("PATCH", r.Method));
        Assert.Equal(4, route.Calls);
    }

    /// <summary>&#167;30.8 (4): set sends every required member; a 201 and a 200 both decode.</summary>
    [Fact]
    public async Task SetSendsEveryRequiredMemberAndDecodes201And200()
    {
        foreach (int status in new[] { 201, 200 })
        {
            Route route = Mount("PUT", Directory, status, ConfigBody());
            DirectoryConfig config = await Client.Directory.SetAsync(SetBody(null));
            Assert.True(config.Enabled);
            JsonElement sent = route.Last.Json();
            foreach (string required in new[] { "enabled", "kind", "url", "start_tls", "bind_dn", "base_dn", "user_filter" })
            {
                Assert.True(sent.TryGetProperty(required, out _), $"{required} missing from the replacement");
            }

            Assert.False(sent.TryGetProperty("bind_secret", out _), "absent keeps the stored secret");
        }

        // The replacement type cannot be built without them: they are `required` members, a
        // compile-time check — what is left is to pin that they are.
        foreach (string name in new[] { "Enabled", "Kind", "Url", "StartTls", "BindDn", "BaseDn", "UserFilter" })
        {
            Assert.NotNull(typeof(SetDirectoryConfig).GetProperty(name)!
                .GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>());
        }
    }

    /// <summary>&#167;30.8 (5): a 503 to each write is one request and a NetworkError — on a retry-enabled client.</summary>
    [Fact]
    public async Task NoWriteIsRetriedOn503()
    {
        Route put = Mount("PUT", Directory, 503, string.Empty);
        Route patch = Mount("PATCH", Directory, 503, string.Empty);
        Route delete = Mount("DELETE", Directory, 503, string.Empty);
        Route link = Mount("POST", $"{Directory}/links", 503, string.Empty);

        await Assert.ThrowsAsync<NetworkError>(() => Client.Directory.SetAsync(SetBody(Secrets.Fresh())));
        await Assert.ThrowsAsync<NetworkError>(() => Client.Directory.UpdateAsync(new UpdateDirectoryConfig()));
        await Assert.ThrowsAsync<NetworkError>(() => Client.Directory.DeleteAsync());
        await Assert.ThrowsAsync<NetworkError>(
            () => Client.Directory.LinkAccountAsync(new LinkDirectoryAccount { UserId = Guid.NewGuid() }));

        Assert.Equal(1, put.Calls);
        Assert.Equal(1, patch.Calls);
        Assert.Equal(1, delete.Calls);
        Assert.Equal(1, link.Calls);
    }

    /// <summary>&#167;30.8 (6): the error mapping, and link_account's exact body and five members.</summary>
    [Fact]
    public async Task ErrorsMapPerSection2AndLinkAccountSendsOnlyTheUserId()
    {
        Mount("PUT", Directory, 400,
            """{"error":"validation_error","message":"url: changing the connection requires entering the bind secret again"}""");
        Mount("PATCH", Directory, 409, """{"error":"conflict","message":"opaque_mode"}""");
        Mount("GET", Directory, 404, """{"error":"not_found","message":"none"}""");
        Mount("DELETE", Directory, 401, """{"error":"unauthorized"}""");

        ValidationError v = await Assert.ThrowsAsync<ValidationError>(() => Client.Directory.SetAsync(SetBody(null)));
        Assert.Contains("bind secret again", v.Message, StringComparison.Ordinal);
        await Assert.ThrowsAsync<ConflictError>(() => Client.Directory.UpdateAsync(new UpdateDirectoryConfig { Enabled = true }));
        await Assert.ThrowsAsync<NotFoundError>(() => Client.Directory.GetAsync());
        AuthError auth = await Assert.ThrowsAsync<AuthError>(() => Client.Directory.DeleteAsync());
        Assert.IsNotType<OAuthProtocolError>(auth);

        Guid user = Guid.NewGuid();
        Route link = Mount("POST", $"{Directory}/links", 200,
            $$"""{"user_id":"{{user}}","directory_external_id":"3f2a-objectguid","webauthn_credentials_deleted":2,"certificates_revoked":1,"was_already_linked":false}""");
        DirectoryLinkResult result = await Client.Directory.LinkAccountAsync(new LinkDirectoryAccount { UserId = user });
        Assert.Equal($$"""{"user_id":"{{user}}"}""", link.Last.Body);
        Assert.Equal(user, result.UserId);
        Assert.Equal("3f2a-objectguid", result.DirectoryExternalId);
        Assert.Equal(2, result.WebauthnCredentialsDeleted);
        Assert.Equal(1, result.CertificatesRevoked);
        Assert.False(result.WasAlreadyLinked);
    }

    /// <summary>The sync status decodes an unknown result and the first run's nulls.</summary>
    [Fact]
    public async Task SyncStatusDecodesAnUnknownResultAndTheFirstRunNulls()
    {
        Mount("GET", $"{Directory}/sync-status", 200,
            """{"last_result":"something_new","last_attempt_at":null,"last_full_run_at":null,"full_required":true,"has_watermark":false}""");
        DirectorySyncStatus status = await Client.Directory.GetSyncStatusAsync();
        Assert.Equal("something_new", status.LastResult);
        Assert.Null(status.LastAttemptAt);
        Assert.True(status.FullRequired);
        Assert.False(status.HasWatermark);
    }

    /// <summary>The configured tenant is in the path with no tenant argument; ForTenant re-scopes.</summary>
    [Fact]
    public async Task TheTenantDefaultsFromTheClient()
    {
        Route route = Mount("GET", Directory, 200, ConfigBody());
        await Client.Directory.GetAsync();
        Assert.Equal(Directory, route.Last.Path);

        Guid other = Guid.NewGuid();
        Route scoped = Mount("GET", $"/api/v1/tenants/{other}/directory", 200, ConfigBody());
        await Client.Directory.ForTenant(other).GetAsync();
        Assert.Equal(1, scoped.Calls);
    }

    /// <summary>A read converts into the replacement body without a secret.</summary>
    [Fact]
    public void AReadConvertsIntoTheReplacementBodyWithoutASecret()
    {
        DirectoryConfig config = ManagementSupport.Decode<DirectoryConfig>("test", JsonDocument.Parse(ConfigBody()).RootElement);
        SetDirectoryConfig body = config.ToInput();
        Assert.Null(body.BindSecret);
        Assert.Equal(config.Url, body.Url);
        Assert.Equal(5, body.GroupNestingDepth);
        Assert.Equal(3600, body.SyncIntervalSecs);
        Assert.Equal("objectGUID", body.UserAttributeMap!.ExternalId);
    }

    /// <summary>JsonNullable's three states, as a value.</summary>
    [Fact]
    public void JsonNullableKeepsItsThreeStatesApart()
    {
        JsonNullable<string> value = "x";
        string? none = null;
        JsonNullable<string> fromNull = none;
        Assert.False(value.IsNull);
        Assert.Equal("x", value.Value);
        Assert.Equal("x", value.ToString());
        Assert.True(fromNull.IsNull);
        Assert.Same(JsonNullable<string>.Null, fromNull);
        Assert.Equal("null", fromNull.ToString());
        Assert.Equal(JsonNullable<string>.Of("x"), value);
        Assert.NotEqual(JsonNullable<string>.Null, value);
        Assert.False(value.Equals((object?)null));
        Assert.Equal(JsonNullable<string>.Of("x").GetHashCode(), value.GetHashCode());
        Assert.Equal(0, JsonNullable<string>.Null.GetHashCode());

        UpdateDirectoryConfig decoded = JsonSerializer.Deserialize<UpdateDirectoryConfig>(
            """{"group_filter":null,"group_base_dn":"ou=g"}""")!;
        Assert.True(decoded.GroupFilter!.IsNull);
        Assert.Equal("ou=g", decoded.GroupBaseDn!.Value);
        Assert.Null(JsonSerializer.Deserialize<UpdateDirectoryConfig>("{}")!.GroupFilter);
    }
}
