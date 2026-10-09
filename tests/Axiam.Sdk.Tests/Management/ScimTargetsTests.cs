using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// The <c>scim_targets</c> namespace — CONTRACT.md &#167;31.8's six required tests, plus the
/// open-union converters and the read-modify-write helper. The credential is generated at run time.
/// </summary>
public sealed class ScimTargetsTests : ManagementTestBase
{
    private const string Targets = "/api/v1/scim-targets";

    private static JsonObject TargetBody(Action<JsonObject>? edit = null)
    {
        var body = JsonNode.Parse(
            $$"""
              {"id":"{{Guid.NewGuid()}}","tenant_id":"{{TenantId}}","name":"Downstream HR",
               "base_url":"https://hr.example/scim/v2","enabled":true,
               "auth":{"type":"oauth2_client_credentials","token_url":"https://hr.example/token","client_id":"axiam","scope":null},
               "scope":{"type":"groups","group_ids":["{{Guid.NewGuid()}}"]},
               "push_groups":true,"user_name_from":"email","deprovision":"deactivate",
               "created_at":"2026-10-05T00:00:00Z","updated_at":"2026-10-05T00:00:00Z",
               "state":{"last_success_at":null,"last_failure_at":"2026-10-05T01:00:00Z",
                        "last_failure_reason":"downstream refused the credential",
                        "consecutive_failures":3,"dead_lettered_total":1,"last_reconciled_at":null} }
              """)!.AsObject();
        edit?.Invoke(body);
        return body;
    }

    private static ScimTargetInput Input(string? credential) => new()
    {
        Name = "Downstream HR",
        BaseUrl = "https://hr.example/scim/v2",
        Auth = new ScimTargetAuthBearer(),
        Scope = new ScimTargetScopeAllUsers(),
        Credential = credential is null ? null : Sensitive<string>.Wrap(credential),
    };

    /// <summary>&#167;31.8 (1): the credential is on the wire and in no rendering.</summary>
    [Fact]
    public async Task TheCredentialIsOnTheWireAndInNoRendering()
    {
        string credential = Secrets.Fresh();
        ScimTargetInput input = Input(credential);
        foreach ((string label, string rendering) in new[]
                 {
                     ("ToString", input.ToString()),
                     ("Json", JsonSerializer.Serialize(input)),
                     ("interpolation", $"{input}"),
                 })
        {
            Secrets.AssertAbsent(rendering, credential, label);
        }

        Route route = Mount("POST", Targets, 400, """{"error":"validation_error","message":"credential: not visible ASCII"}""");
        ValidationError e = await Assert.ThrowsAsync<ValidationError>(() => Client.ScimTargets.CreateAsync(input));
        Secrets.AssertAbsent(e.ToString(), credential, "error rendering");
        Assert.Equal(credential, route.Last.Json().GetProperty("credential").GetString());
    }

    /// <summary>&#167;31.8 (2): a credential in a response is dropped; the type has no member for it.</summary>
    [Fact]
    public async Task ACredentialInAResponseIsDropped()
    {
        string leaked = Secrets.Fresh();
        Guid id = Guid.NewGuid();
        Mount("GET", $"{Targets}/{id}", 200, TargetBody(b =>
        {
            b["credential"] = leaked;
            b["auth"]!["credential"] = leaked;
        }).ToJsonString());

        ScimTargetResponse target = await Client.ScimTargets.GetAsync(id);
        Secrets.AssertAbsent(target.ToString(), leaked, "ToString");
        Secrets.AssertAbsent(JsonSerializer.Serialize(target), leaked, "Json");
        Assert.DoesNotContain(typeof(ScimTargetResponse).GetProperties(), p => p.Name.Contains("Credential", StringComparison.Ordinal));
        Assert.DoesNotContain(typeof(ScimTargetAuthOauth2ClientCredentials).GetProperties(), p => p.Name.Contains("Credential", StringComparison.Ordinal) || p.Name.Contains("Secret", StringComparison.Ordinal));
        Assert.Equal("axiam", Assert.IsType<ScimTargetAuthOauth2ClientCredentials>(target.Auth).ClientId);
    }

    /// <summary>&#167;31.8 (3): no credential key without one; both variants of both unions keep their exact keys.</summary>
    [Fact]
    public async Task UpdateWithoutACredentialSendsNoKeyAndTheVariantsKeepTheirShape()
    {
        Guid id = Guid.NewGuid();
        Route put = Mount("PUT", $"{Targets}/{id}", 200, TargetBody().ToJsonString());

        await Client.ScimTargets.UpdateAsync(id, Input(null));
        JsonElement sent = put.Last.Json();
        Assert.False(sent.TryGetProperty("credential", out _));
        Assert.Equal("""{"type":"bearer"}""", sent.GetProperty("auth").GetRawText());
        Assert.Equal("""{"type":"all_users"}""", sent.GetProperty("scope").GetRawText());

        string credential = Secrets.Fresh();
        Guid group = Guid.NewGuid();
        await Client.ScimTargets.UpdateAsync(id, Input(credential) with
        {
            Auth = new ScimTargetAuthOauth2ClientCredentials { TokenUrl = "https://hr.example/token", ClientId = "axiam", Scope = "scim" },
            Scope = new ScimTargetScopeGroups { GroupIds = new[] { group } },
        });
        sent = put.Last.Json();
        Assert.Equal(credential, sent.GetProperty("credential").GetString());
        Assert.Equal(
            new[] { "client_id", "scope", "token_url", "type" },
            sent.GetProperty("auth").EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
        Assert.Equal("oauth2_client_credentials", sent.GetProperty("auth").GetProperty("type").GetString());
        Assert.Equal(
            new[] { "group_ids", "type" },
            sent.GetProperty("scope").EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
        Assert.Equal(group, sent.GetProperty("scope").GetProperty("group_ids")[0].GetGuid());

        foreach (string name in new[] { "Name", "BaseUrl", "Auth", "Scope" })
        {
            Assert.NotNull(typeof(ScimTargetInput).GetProperty(name)!
                .GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>());
        }
    }

    /// <summary>&#167;31.8 (4): unknown values, a null state and a new failure reason decode; the pager carries search.</summary>
    [Fact]
    public async Task UnknownValuesDecodeAndThePagerCarriesSearch()
    {
        JsonObject odd = TargetBody(b =>
        {
            b["auth"] = new JsonObject { ["type"] = "mtls", ["certificate_ref"] = "x" };
            b["scope"] = new JsonObject { ["type"] = "attribute_filter", ["filter"] = "dept eq 7" };
            b["deprovision"] = "archive";
            b["user_name_from"] = "employee_number";
            b["state"] = null;
        });
        JsonObject newReason = TargetBody(b => b["state"]!["last_failure_reason"] = "a reason this SDK has never seen");
        Route list = MountDynamic("GET", Targets, 200, recorded =>
        {
            int offset = int.Parse(recorded.Query["offset"], System.Globalization.CultureInfo.InvariantCulture);
            string items = offset == 0 ? $"[{odd.ToJsonString()}]" : offset == 1 ? $"[{newReason.ToJsonString()}]" : "[]";
            return $$"""{"items":{{items}},"total":2,"offset":{{offset}},"limit":1}""";
        });

        Page<ScimTargetResponse> page = await Client.ScimTargets.ListAsync(PageRequest.Matching(1, "hr"));
        Assert.Equal(2, page.Total);
        ScimTargetResponse first = page.Items[0];
        Assert.Equal("mtls", Assert.IsType<ScimTargetAuthUnknown>(first.Auth).Type);
        Assert.Equal("attribute_filter", Assert.IsType<ScimTargetScopeUnknown>(first.Scope).Type);
        Assert.Equal(DeprovisionPolicy.Unknown, first.Deprovision);
        Assert.Equal(UserNameSource.Unknown, first.UserNameFrom);
        Assert.Null(first.State);

        IReadOnlyList<ScimTargetResponse> all = await Client.ScimTargets.ListAllAsync(PageRequest.Matching(1, "hr"));
        Assert.Equal(2, all.Count);
        Assert.Equal("a reason this SDK has never seen", all[1].State!.LastFailureReason);
        Assert.All(list.Requests, r => Assert.Equal("hr", r.Query["search"]));
    }

    /// <summary>&#167;31.2: an unknown auth or scope arm is never sent — refused locally, no request.</summary>
    [Fact]
    public async Task AnUnknownArmIsRefusedLocally()
    {
        Guid id = Guid.NewGuid();
        Route put = Mount("PUT", $"{Targets}/{id}", 200, TargetBody().ToJsonString());
        ScimTargetAuth unknownAuth = JsonSerializer.Deserialize<ScimTargetAuth>("""{"type":"mtls"}""")!;
        ScimTargetScope unknownScope = JsonSerializer.Deserialize<ScimTargetScope>("""{"scope":"x"}""")!;
        Assert.Null(Assert.IsType<ScimTargetScopeUnknown>(unknownScope).Type);

        await Assert.ThrowsAsync<ValidationError>(() => Client.ScimTargets.UpdateAsync(id, Input(null) with { Auth = unknownAuth }));
        await Assert.ThrowsAsync<ValidationError>(() => Client.ScimTargets.UpdateAsync(id, Input(null) with { Scope = unknownScope }));
        Assert.Equal(0, put.Calls);
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ScimTargetAuth>("[]"));
    }

    /// <summary>
    /// R-21 / CS-10 (CONTRACT.md &#167;34.2 P12.2, &#167;7 rule 1): an unknown arm is refused on
    /// the request path only — a decoded <see cref="ScimTargetResponse"/> carrying one renders for
    /// a log line, as its discriminator and nothing else.
    /// </summary>
    [Fact]
    public async Task AnUnknownArmRendersForALogLineAndIsRefusedOnlyWhenSent()
    {
        Guid id = Guid.NewGuid();
        Mount("GET", $"{Targets}/{id}", 200, TargetBody(b =>
        {
            b["auth"] = new JsonObject { ["type"] = "mtls", ["certificate_ref"] = "kept-nowhere" };
            b["scope"] = new JsonObject { ["filter"] = "dept eq 7" };
        }).ToJsonString());
        ScimTargetResponse target = await Client.ScimTargets.GetAsync(id);

        JsonElement rendered = JsonSerializer.SerializeToElement(target);
        Assert.Equal("""{"type":"mtls"}""", rendered.GetProperty("auth").GetRawText());
        Assert.Equal("{}", rendered.GetProperty("scope").GetRawText());
        Assert.DoesNotContain("kept-nowhere", JsonSerializer.Serialize(target), StringComparison.Ordinal);
        Assert.Contains("mtls", JsonSerializer.Serialize(target.Auth), StringComparison.Ordinal);

        Route put = Mount("PUT", $"{Targets}/{id}", 200, TargetBody().ToJsonString());
        await Assert.ThrowsAsync<ValidationError>(() => Client.ScimTargets.UpdateAsync(id, Input(null) with { Auth = target.Auth }));
        await Assert.ThrowsAsync<ValidationError>(() => Client.ScimTargets.UpdateAsync(id, Input(null) with { Scope = target.Scope }));
        Assert.Equal(0, put.Calls);
    }

    /// <summary>&#167;31.8 (5): none of the four writes is retried on a 503 (retry-enabled client).</summary>
    [Fact]
    public async Task NoWriteIsRetriedOn503()
    {
        Guid id = Guid.NewGuid();
        Route[] routes =
        {
            Mount("POST", Targets, 503, string.Empty),
            Mount("PUT", $"{Targets}/{id}", 503, string.Empty),
            Mount("DELETE", $"{Targets}/{id}", 503, string.Empty),
            Mount("POST", $"{Targets}/{id}/reconcile", 503, string.Empty),
        };
        await Assert.ThrowsAsync<NetworkError>(() => Client.ScimTargets.CreateAsync(Input(Secrets.Fresh())));
        await Assert.ThrowsAsync<NetworkError>(() => Client.ScimTargets.UpdateAsync(id, Input(null)));
        await Assert.ThrowsAsync<NetworkError>(() => Client.ScimTargets.DeleteAsync(id));
        await Assert.ThrowsAsync<NetworkError>(() => Client.ScimTargets.ReconcileAsync(id));
        Assert.All(routes, r => Assert.Equal(1, r.Calls));
    }

    /// <summary>&#167;31.8 (6): the status mapping, and reconcile is a bodiless 202.</summary>
    [Fact]
    public async Task StatusesMapAndReconcileIsABodilessPost202()
    {
        Guid id = Guid.NewGuid();
        Mount("POST", Targets, 400, """{"error":"validation_error","message":"base_url: must be https"}""");
        Mount("PUT", $"{Targets}/{id}", 409, """{"error":"conflict","message":"the SCIM target changed since it was read"}""");
        Mount("GET", $"{Targets}/{id}", 404, """{"error":"not_found","message":"no"}""");
        Mount("DELETE", $"{Targets}/{id}", 401, """{"error":"unauthorized"}""");

        ValidationError v = await Assert.ThrowsAsync<ValidationError>(() => Client.ScimTargets.CreateAsync(Input(Secrets.Fresh())));
        Assert.Contains("must be https", v.Message, StringComparison.Ordinal);
        await Assert.ThrowsAsync<ConflictError>(() => Client.ScimTargets.UpdateAsync(id, Input(null)));
        await Assert.ThrowsAsync<NotFoundError>(() => Client.ScimTargets.GetAsync(id));
        await Assert.ThrowsAsync<AuthError>(() => Client.ScimTargets.DeleteAsync(id));

        Route reconcile = Mount("POST", $"{Targets}/{id}/reconcile", 202, $$"""{"target_id":"{{id}}","status":"started"}""");
        ScimReconcileAccepted accepted = await Client.ScimTargets.ReconcileAsync(id);
        Assert.Equal(id, accepted.TargetId);
        Assert.Equal("started", accepted.Status);
        Assert.Equal(string.Empty, reconcile.Last.Body);

        Guid other = Guid.NewGuid();
        Mount("POST", $"{Targets}/{other}/reconcile", 409, """{"error":"conflict","message":"a run holds the claim"}""");
        await Assert.ThrowsAsync<ConflictError>(() => Client.ScimTargets.ReconcileAsync(other));
    }

    /// <summary>A read converts into the replacement body without a credential.</summary>
    [Fact]
    public void AReadConvertsIntoTheReplacementBodyWithoutACredential()
    {
        ScimTargetResponse target = ManagementSupport.Decode<ScimTargetResponse>(
            "test", JsonDocument.Parse(TargetBody().ToJsonString()).RootElement);
        ScimTargetInput body = target.ToInput();
        Assert.Null(body.Credential);
        Assert.Equal(target.BaseUrl, body.BaseUrl);
        Assert.Equal(UserNameSource.Email, body.UserNameFrom);
        Assert.True(body.PushGroups);
        JsonElement encoded = JsonDocument.Parse(ManagementSupport.EncodeBody("test", body)).RootElement;
        Assert.False(encoded.TryGetProperty("credential", out _));
        Assert.Equal("groups", encoded.GetProperty("scope").GetProperty("type").GetString());
    }
}
