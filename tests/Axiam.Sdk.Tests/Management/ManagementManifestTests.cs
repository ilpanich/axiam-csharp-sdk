using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// CONTRACT.md &#167;27.6 — the declarative layer's reconciler.
/// </summary>
/// <remarks>
/// The rules under test, in order: plan writes nothing and is stable across runs;
/// validation precedes every request; ordering is derived; drift is an update and
/// omission is never a deletion; apply converges, and stops at the first failure while
/// reporting what it did not attempt.
/// </remarks>
[Trait("Category", "Fast")]
public sealed class ManagementManifestTests : ManagementTestBase
{
    private static readonly Guid RoleId = Guid.Parse("66666666-6666-4666-8666-666666666666");
    private static readonly Guid ResourceId = Guid.Parse("77777777-7777-4777-8777-777777777777");
    private static readonly Guid ArchiveId = Guid.Parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private static readonly Guid PermissionId = Guid.Parse("88888888-8888-4888-8888-888888888888");
    private static readonly Guid GroupId = Guid.Parse("99999999-9999-4999-8999-999999999999");
    private static readonly Guid MemberId = Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static readonly Guid ScopeId = Guid.Parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc");

    // A plain escaped string, not a raw literal: the content itself begins and ends
    // with a quote, which is exactly the case where counting raw-string delimiters
    // stops being readable and starts being a puzzle.
    private const string Stamps =
        "\"created_at\":\"2026-08-26T00:00:00Z\",\"updated_at\":\"2026-08-26T00:00:00Z\"";

    private void MountEmptyTenant()
    {
        foreach (string path in new[] { "resources", "permissions", "roles", "groups", "users" })
        {
            Mount("GET", $"/api/v1/{path}", 200, PageOf(null));
        }
    }

    private static ManagementManifest SampleManifest() => ManagementManifest.Builder()
        .Resource("docs", "documents", "collection")
        .Scope("docs", "draft", "draft", "Unpublished")
        .ChildResource("archive", "archive", "collection", "docs")
        .Permission("read", "document:read", "Read")
        .Role("editor", "Editor", "Edits documents")
        .Grant("editor", "read", null, "draft")
        .Group("staff", "Staff", "Everyone", "editor")
        .User("alice", "alice", "alice@example.test", Sensitive<string>.Wrap("correct-horse"))
        .AssignRole("alice", "editor")
        .AddToGroup("alice", "staff")
        .Build();

    /// <summary>&#167;27.6 rule 1: every request a plan makes is a read.</summary>
    [Fact]
    public async Task PlanIssuesNoWrite()
    {
        MountEmptyTenant();

        await Client.Management.Manifest.PlanAsync(SampleManifest());

        Assert.Empty(Unmatched());
    }

    /// <summary>&#167;27.6 rule 1: a plan run twice against an unchanged tenant is identical.</summary>
    [Fact]
    public async Task PlanIsStableAcrossRuns()
    {
        MountEmptyTenant();

        ManagementPlan first = await Client.Management.Manifest.PlanAsync(SampleManifest());
        ManagementPlan second = await Client.Management.Manifest.PlanAsync(SampleManifest());

        Assert.Equal(first.Actions, second.Actions);
    }

    /// <summary>&#167;27.6 rule 2: ordering is derived, so a child declared first still follows.</summary>
    [Fact]
    public async Task OrderingIsDerived()
    {
        MountEmptyTenant();

        ManagementPlan plan = await Client.Management.Manifest.PlanAsync(new ManagementManifest
        {
            Resources = new[]
            {
                new ManagementManifest.ResourceSpec("archive", "archive", "collection", "docs"),
                new ManagementManifest.ResourceSpec("docs", "documents", "collection"),
            },
        });

        Assert.Equal(
            new[] { "docs", "archive" },
            plan.Actions.Where(a => a.Target == PlanTarget.Resource).Select(a => a.Key));
    }

    /// <summary>&#167;27.6 rule 1: a dangling reference is refused before the first request.</summary>
    [Fact]
    public async Task ADanglingReferenceIsRefusedBeforeCalling()
    {
        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.Manifest.PlanAsync(new ManagementManifest
            {
                Roles = new[]
                {
                    new ManagementManifest.RoleSpec(
                        "editor", "Editor", "Edits", false,
                        new[] { new ManagementManifest.GrantSpec("nope") }),
                },
            }));

        Assert.Contains("which no permission declares", thrown.Message, StringComparison.Ordinal);
        Assert.Equal(0, TotalCalls());
    }

    /// <summary>A resource cycle is refused rather than looped.</summary>
    [Fact]
    public async Task AResourceCycleIsRefusedRatherThanLooped()
    {
        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.Manifest.PlanAsync(new ManagementManifest
            {
                Resources = new[]
                {
                    new ManagementManifest.ResourceSpec("a", "a", "collection", "b"),
                    new ManagementManifest.ResourceSpec("b", "b", "collection", "a"),
                },
            }));

        Assert.Contains("is its own ancestor", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>Every problem is reported at once, not one run at a time.</summary>
    [Fact]
    public async Task EveryProblemIsReportedNotJustTheFirst()
    {
        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.Manifest.PlanAsync(new ManagementManifest
            {
                Roles = new[]
                {
                    new ManagementManifest.RoleSpec(
                        "editor", "Editor", "Edits", false,
                        new[] { new ManagementManifest.GrantSpec("nope", "sideways") }),
                },
                Groups = new[]
                {
                    new ManagementManifest.GroupSpec("staff", "Staff", "All", new[] { "ghost" }),
                },
            }));

        Assert.Contains("no permission declares", thrown.Message, StringComparison.Ordinal);
        Assert.Contains("only 'allow' and 'deny' exist", thrown.Message, StringComparison.Ordinal);
        Assert.Contains("no role declares", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>&#167;27.6 rule 1: a user that must be created needs a password, known early.</summary>
    [Fact]
    public async Task AUserThatMustBeCreatedNeedsAPassword()
    {
        MountEmptyTenant();

        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.Manifest.ApplyAsync(new ManagementManifest
            {
                Users = new[]
                {
                    new ManagementManifest.UserSpec("alice", "alice", "alice@example.test"),
                },
            }));

        Assert.Contains("no InitialPassword", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>The builder catches a forward reference the record form cannot.</summary>
    [Fact]
    public void TheBuilderRefusesAForwardReference()
    {
        NetworkError thrown = Assert.Throws<NetworkError>(() =>
            ManagementManifest.Builder().Scope("docs", "draft", "draft", "Unpublished").Build());

        Assert.Contains("which no Resource(...) call has declared yet", thrown.Message,
            StringComparison.Ordinal);
    }

    /// <summary>Every builder call that names an earlier key checks it, not just the first.</summary>
    [Fact]
    public void EveryBuilderBackReferenceIsChecked()
    {
        Assert.Contains("no Role(...) call has declared yet",
            Assert.Throws<NetworkError>(() =>
                ManagementManifest.Builder().Grant("editor", "read").Build()).Message,
            StringComparison.Ordinal);
        Assert.Contains("no User(...) call has declared yet",
            Assert.Throws<NetworkError>(() =>
                ManagementManifest.Builder().AssignRole("alice", "editor").Build()).Message,
            StringComparison.Ordinal);
        Assert.Contains("no User(...) call has declared yet",
            Assert.Throws<NetworkError>(() =>
                ManagementManifest.Builder().AddToGroup("alice", "staff").Build()).Message,
            StringComparison.Ordinal);
        Assert.Contains("no Resource(...) call has declared yet",
            Assert.Throws<NetworkError>(() =>
                ManagementManifest.Builder()
                    .ChildResource("archive", "archive", "collection", "docs").Build()).Message,
            StringComparison.Ordinal);
    }

    private void MountTenantWithOneRole(string description)
    {
        foreach (string path in new[] { "resources", "permissions", "groups", "users" })
        {
            Mount("GET", $"/api/v1/{path}", 200, PageOf(null));
        }

        Mount("GET", "/api/v1/roles", 200, PageOf(RoleBody(RoleId, "Editor", description)));
        foreach (string sub in new[] { "permissions", "users", "groups" })
        {
            Mount("GET", $"/api/v1/roles/{RoleId}/{sub}", 200, "[]");
        }
    }

    private static readonly ManagementManifest OneRole = new()
    {
        Roles = new[] { new ManagementManifest.RoleSpec("editor", "Editor", "Edits documents") },
    };

    /// <summary>&#167;27.6 rule 6: a converged tenant plans nothing.</summary>
    [Fact]
    public async Task AConvergedTenantPlansNothing()
    {
        MountTenantWithOneRole("Edits documents");

        ManagementPlan plan = await Client.Management.Manifest.PlanAsync(OneRole);

        Assert.True(plan.IsConverged);
        Assert.NotEmpty(plan.Actions);
    }

    /// <summary>&#167;27.6 rule 3: a drifted field the manifest states is an update.</summary>
    [Fact]
    public async Task ADriftedFieldIsAnUpdate()
    {
        MountTenantWithOneRole("something else");

        IReadOnlyList<PlannedAction> changes =
            (await Client.Management.Manifest.PlanAsync(OneRole)).Changes;

        Assert.Single(changes);
        Assert.Equal(PlanChange.Update, changes[0].Change);
        Assert.Equal(PlanTarget.Role, changes[0].Target);
    }

    /// <summary>&#167;27.6 rule 4: a role the manifest omits is never deleted.</summary>
    [Fact]
    public async Task ARoleTheManifestOmitsIsNeverDeleted()
    {
        MountTenantWithOneRole("Edits documents");

        ManagementPlan plan = await Client.Management.Manifest.PlanAsync(ManagementManifest.Empty());

        Assert.Empty(plan.Actions);
    }

    private static string ResourceBody(Guid id, string name, string type, Guid? parent) =>
        $$"""
          {"id":"{{id}}","name":"{{name}}","resource_type":"{{type}}",
           "parent_id":{{(parent is null ? "null" : $"\"{parent}\"")}},
           "metadata":{},"tenant_id":"{{TenantId}}",{{Stamps}}}
          """;

    private static string PermissionBody(string description) =>
        $$"""
          {"id":"{{PermissionId}}","action":"document:read","description":"{{description}}",
           "tenant_id":"{{TenantId}}",{{Stamps}}}
          """;

    private static string GroupBody(string description) =>
        $$"""
          {"id":"{{GroupId}}","name":"Staff","description":"{{description}}","metadata":{},
           "tenant_id":"{{TenantId}}",{{Stamps}}}
          """;

    private static string UserBody(string email) =>
        $$"""
          {"id":"{{MemberId}}","username":"alice","email":"{{email}}","email_verified":true,
           "failed_login_attempts":0,"is_locked":false,"metadata":{},"mfa_enabled":false,
           "status":"Active","tenant_id":"{{TenantId}}",{{Stamps}}}
          """;

    private static string PageWith(params string[] items) =>
        $$"""{"items":[{{string.Join(",", items)}}],"total":{{items.Length}},"offset":0,"limit":200}""";

    private void MountCreates()
    {
        Mount("POST", "/api/v1/resources", 201, ResourceBody(ResourceId, "documents", "collection", null));
        Mount("POST", $"/api/v1/resources/{ResourceId}/scopes", 201,
            $$"""
              {"id":"{{ScopeId}}","name":"draft","description":"Unpublished",
               "resource_id":"{{ResourceId}}","tenant_id":"{{TenantId}}",{{Stamps}}}
              """);
        Mount("POST", "/api/v1/permissions", 201, PermissionBody("Read"));
        Mount("POST", "/api/v1/roles", 201, RoleBody(RoleId, "Editor", "Edits documents"));
        Mount("POST", "/api/v1/groups", 201, GroupBody("Everyone"));
        Mount("POST", "/api/v1/users", 201, UserBody("alice@example.test"));
        Mount("POST", $"/api/v1/roles/{RoleId}/permissions", 204, string.Empty);
        Mount("POST", $"/api/v1/roles/{RoleId}/users", 204, string.Empty);
        Mount("POST", $"/api/v1/roles/{RoleId}/groups", 204, string.Empty);
        Mount("POST", $"/api/v1/groups/{GroupId}/members", 204, string.Empty);
    }

    /// <summary>&#167;27.6: apply creates everything and accounts for every step.</summary>
    [Fact]
    public async Task ApplyCreatesEverythingAndReportsEveryStep()
    {
        MountEmptyTenant();
        MountCreates();

        ApplyReport report = await Client.Management.Manifest.ApplyAsync(SampleManifest());

        Assert.True(report.IsComplete, report.Failure?.Outcome.Message);
        Assert.All(report.Steps, s => Assert.Equal(ApplyStatus.Created, s.Outcome.Status));
        Assert.Equal(report.Steps.Count, report.ChangedCount);
    }

    /// <summary>&#167;27.6 rule 7: apply stops at the first failure and says what it never tried.</summary>
    [Fact]
    public async Task ApplyStopsAtTheFirstFailureAndSaysWhatWasNotAttempted()
    {
        MountEmptyTenant();
        MountCreates();
        Mount("POST", "/api/v1/permissions", 409, """{"message":"already exists"}""");

        ApplyReport report = await Client.Management.Manifest.ApplyAsync(SampleManifest());

        Assert.False(report.IsComplete);
        Assert.Equal(PlanTarget.Permission, report.Failure!.Action.Target);

        bool seenFailure = false;
        foreach (AppliedStep step in report.Steps)
        {
            if (step.Outcome.Status == ApplyStatus.Failed)
            {
                seenFailure = true;
                continue;
            }

            if (seenFailure)
            {
                Assert.Equal(ApplyStatus.NotAttempted, step.Outcome.Status);
            }
        }

        Assert.True(seenFailure);
    }

    /// <summary>Nothing declared means nothing planned and nothing sent.</summary>
    [Fact]
    public async Task ApplyingAnEmptyManifestIsClean()
    {
        MountEmptyTenant();

        ApplyReport report = await Client.Management.Manifest.ApplyAsync(ManagementManifest.Empty());

        Assert.Empty(report.Steps);
        Assert.True(report.IsComplete);
        Assert.Equal(0, report.ChangedCount);
    }

    /// <summary>A config file mentioning a password is not a request to reset one.</summary>
    [Fact]
    public async Task APasswordIsNeverSentForAUserThatAlreadyExists()
    {
        foreach (string path in new[] { "resources", "permissions", "roles", "groups" })
        {
            Mount("GET", $"/api/v1/{path}", 200, PageOf(null));
        }

        Mount("GET", "/api/v1/users", 200, PageOf(UserBody("alice@example.test")));
        Route created = Mount("POST", "/api/v1/users", 201, string.Empty);

        ApplyReport report = await Client.Management.Manifest.ApplyAsync(new ManagementManifest
        {
            Users = new[]
            {
                new ManagementManifest.UserSpec(
                    "alice", "alice", "alice@example.test", Sensitive<string>.Wrap("would-be-a-reset")),
            },
        });

        Assert.Equal(0, created.Calls);
        Assert.Single(report.Steps);
        Assert.Equal(ApplyStatus.Unchanged, report.Steps[0].Outcome.Status);
    }

    /// <summary>A deny grant must travel as deny: AXIAM's RBAC is deny-override.</summary>
    [Fact]
    public async Task ADenyGrantTravelsAsDeny()
    {
        MountEmptyTenant();
        MountCreates();
        Route grant = RouteAt("POST", $"/api/v1/roles/{RoleId}/permissions");

        await Client.Management.Manifest.ApplyAsync(ManagementManifest.Builder()
            .Permission("purge", "document:purge", "Permanently delete")
            .Role("editor", "Editor", "Edits documents")
            .Grant("editor", "purge", "deny")
            .Build());

        Assert.Equal("deny", grant.Last.Json().GetProperty("effect").GetString());
    }

    /// <summary>A global role is a role that is global; the flag reaches the wire as one.</summary>
    [Fact]
    public async Task AGlobalRoleIsCreatedGlobal()
    {
        MountEmptyTenant();
        MountCreates();
        Route created = RouteAt("POST", "/api/v1/roles");

        await Client.Management.Manifest.ApplyAsync(ManagementManifest.Builder()
            .GlobalRole("admin", "Administrator", "Everything, everywhere").Build());

        Assert.True(created.Last.Json().GetProperty("is_global").GetBoolean());
    }

    /// <summary>
    /// Mounts a tenant that already holds every entity the sample manifest declares,
    /// with the drift-bearing fields supplied by the caller.
    /// </summary>
    private void MountPopulatedTenant(
        string resourceType, string permissionDescription, string roleDescription,
        string groupDescription, string email)
    {
        Mount("GET", "/api/v1/resources", 200, PageWith(
            ResourceBody(ResourceId, "documents", resourceType, null),
            ResourceBody(ArchiveId, "archive", resourceType, ResourceId)));
        Mount("GET", $"/api/v1/resources/{ResourceId}/scopes", 200,
            $$"""
              [{"id":"{{ScopeId}}","name":"draft","description":"Unpublished",
                "resource_id":"{{ResourceId}}","tenant_id":"{{TenantId}}",{{Stamps}}}]
              """);
        Mount("GET", $"/api/v1/resources/{ArchiveId}/scopes", 200, "[]");
        Mount("GET", "/api/v1/permissions", 200, PageWith(PermissionBody(permissionDescription)));
        Mount("GET", "/api/v1/roles", 200, PageWith(RoleBody(RoleId, "Editor", roleDescription)));
        Mount("GET", $"/api/v1/roles/{RoleId}/permissions", 200,
            $$"""
              [{"effect":"allow","permission":{{PermissionBody(permissionDescription)}},
                "scope_ids":["{{ScopeId}}"],"scopes":[]}]
              """);
        Mount("GET", $"/api/v1/roles/{RoleId}/users", 200,
            $$"""[{"user":{{UserBody(email)}},"resource_id":null}]""");
        Mount("GET", $"/api/v1/roles/{RoleId}/groups", 200,
            $$"""[{"group":{{GroupBody(groupDescription)}},"resource_id":null}]""");
        Mount("GET", "/api/v1/groups", 200, PageWith(GroupBody(groupDescription)));
        Mount("GET", $"/api/v1/groups/{GroupId}/members", 200, PageWith(UserBody(email)));
        Mount("GET", "/api/v1/users", 200, PageWith(UserBody(email)));
    }

    /// <summary>
    /// &#167;27.6 rule 6: applying a manifest a second time writes nothing.
    /// </summary>
    /// <remarks>
    /// The single most important property of the declarative layer, and the one a
    /// create-from-empty test cannot show: every entity, grant, role assignment and
    /// group membership already matches, so every step must report Unchanged and no
    /// write route may be reached at all.
    /// </remarks>
    [Fact]
    public async Task ASecondApplyOfTheSameManifestWritesNothing()
    {
        MountPopulatedTenant("collection", "Read", "Edits documents", "Everyone", "alice@example.test");
        MountCreates();

        ManagementPlan plan = await Client.Management.Manifest.PlanAsync(SampleManifest());
        Assert.True(plan.IsConverged, string.Join("; ", plan.Changes.Select(c => c.Summary)));

        ApplyReport report = await Client.Management.Manifest.ApplyAsync(SampleManifest());

        Assert.True(report.IsComplete, report.Failure?.Outcome.Message);
        Assert.Equal(0, report.ChangedCount);
        Assert.All(report.Steps, s => Assert.Equal(ApplyStatus.Unchanged, s.Outcome.Status));
    }

    /// <summary>
    /// &#167;27.6 rule 3: drift is an update in place, never a delete-and-recreate.
    /// </summary>
    [Fact]
    public async Task EveryDriftedEntityIsUpdatedInPlace()
    {
        MountPopulatedTenant("folder", "stale", "stale", "stale", "stale@example.test");
        MountCreates();
        Route resource = Mount("PUT", $"/api/v1/resources/{ResourceId}", 200,
            ResourceBody(ResourceId, "documents", "collection", null));
        Route child = Mount("PUT", $"/api/v1/resources/{ArchiveId}", 200,
            ResourceBody(ArchiveId, "archive", "collection", ResourceId));
        Route permission = Mount("PUT", $"/api/v1/permissions/{PermissionId}", 200, PermissionBody("Read"));
        Route role = Mount("PUT", $"/api/v1/roles/{RoleId}", 200, RoleBody(RoleId, "Editor", "Edits documents"));
        Route group = Mount("PUT", $"/api/v1/groups/{GroupId}", 200, GroupBody("Everyone"));
        Route user = Mount("PUT", $"/api/v1/users/{MemberId}", 200, UserBody("alice@example.test"));

        ApplyReport report = await Client.Management.Manifest.ApplyAsync(SampleManifest());

        Assert.True(report.IsComplete, report.Failure?.Outcome.Message);
        Assert.Equal(1, resource.Calls);
        Assert.Equal(1, child.Calls);
        Assert.Equal(1, permission.Calls);
        Assert.Equal(1, role.Calls);
        Assert.Equal(1, group.Calls);
        Assert.Equal(1, user.Calls);
        Assert.Equal(6, report.Steps.Count(s => s.Outcome.Status == ApplyStatus.Updated));

        // §27.4 rule 5 end to end: an update carries the field that drifted and nothing
        // else, so reconciling a description cannot clear an email.
        Assert.Equal(new[] { "resource_type" }, resource.Last.Keys());
        Assert.Equal(new[] { "description" }, permission.Last.Keys());
        Assert.Equal(new[] { "description", "is_global" }, role.Last.Keys());
        Assert.Equal(new[] { "description" }, group.Last.Keys());
        Assert.Equal(new[] { "email" }, user.Last.Keys());
    }
}
