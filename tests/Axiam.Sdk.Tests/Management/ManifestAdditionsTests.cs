using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Options;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// CONTRACT.md &#167;27.6.1 (contract 1.51) — resource <c>metadata</c>, two-shape role
/// bindings, and service accounts, for the declarative manifest layer.
/// </summary>
/// <remarks>
/// <para>
/// These run against a small <b>stateful</b> fake of the tenant rather than the
/// fixed-route harness the rest of this directory uses (see
/// <see cref="ManagementTestBase"/>), because the property that matters most here —
/// <c>apply(m)</c> then <c>plan(m)</c> is all <see cref="PlanChange.NoChange"/> (&#167;27.6
/// rule 6) — only means something when the second read sees what the first write did. The
/// fake keeps the server rules the manifest depends on: one assignment per (subject, role),
/// a resource's metadata replaced whole, <c>{}</c> for a resource created with none, and a
/// <c>client_secret</c> returned by <c>create</c> and never again — mirroring
/// axiam-rust-sdk's <c>tests/manifest_additions_test.rs</c> so both SDKs prove the same
/// properties against the same fake shape.
/// </para>
/// </remarks>
[Trait("Category", "Fast")]
public sealed class ManifestAdditionsTests
{
    private static readonly Uri Base = new("https://axiam.test");
    private const string TenantSlug = "acme";
    private static readonly Guid TenantId = Guid.Parse("55555555-5555-4555-8555-555555555555");

    // ------------------------------------------------------------------------------
    // Session plumbing (duplicated in miniature from ManagementTestBase, which is
    // built around its own single fixed-route handler and cannot host this one).
    // ------------------------------------------------------------------------------

    private static AxiamClient BuildClient(TenantFake fake)
    {
        AxiamClient client = AxiamClient.CreateForTesting(
            Base,
            TenantSlug,
            new AxiamClientOptions { BaseUrl = Base, TenantId = TenantSlug },
            fake);
        SeedSession(client);
        return client;
    }

    private static void SeedSession(AxiamClient client)
    {
        var payload = new Dictionary<string, object>
        {
            ["sub"] = Guid.NewGuid().ToString(),
            ["org_id"] = Guid.NewGuid().ToString(),
            ["tenant_id"] = TenantId.ToString(),
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
        };
        SeedCookie(client, "axiam_access", Jwt(payload));
    }

    private static string B64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Jwt(object payload)
    {
        string header = B64Url(Encoding.UTF8.GetBytes("""{"alg":"none"}"""));
        string body = B64Url(JsonSerializer.SerializeToUtf8Bytes(payload));
        return $"{header}.{body}.unsigned";
    }

    private static void SeedCookie(AxiamClient client, string name, string value)
    {
        FieldInfo field = typeof(AxiamClient)
            .GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var container = (System.Net.CookieContainer)field.GetValue(client)!;
        container.Add(Base, new System.Net.Cookie(name, value));
    }

    // ------------------------------------------------------------------------------
    // Request-log helpers, mirroring the Rust reference's writes()/mark()/
    // requests_since()/body()/keys().
    // ------------------------------------------------------------------------------

    private sealed record RecordedRequest(string Method, string Path, string Query, string Body);

    private static IReadOnlyList<RecordedRequest> Writes(TenantFake fake) =>
        fake.Requests
            .Where(r => r.Method != "GET" && !r.Path.StartsWith("/api/v1/auth/", StringComparison.Ordinal))
            .ToList();

    private static int Mark(TenantFake fake) => fake.Requests.Count;

    private static IReadOnlyList<RecordedRequest> RequestsSince(TenantFake fake, int mark) =>
        fake.Requests.Skip(mark).ToList();

    private static JsonNode? BodyOf(RecordedRequest r) => r.Body.Length == 0 ? null : JsonNode.Parse(r.Body);

    private static IReadOnlyList<string> Keys(JsonNode? node) =>
        node!.AsObject().Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal).ToList();

    /// <summary>
    /// JSON value equality — order-independent for object members, order-sensitive for
    /// array elements. A local twin of <c>ManifestApi.JsonElementDeepEquals</c>, kept
    /// separate so a test never shares the one bug that could hide from both sides.
    /// </summary>
    private static bool JsonEquivalent(JsonNode? node, JsonElement expected)
    {
        using JsonDocument doc = JsonDocument.Parse(node?.ToJsonString() ?? "null");
        return JsonElementEquals(doc.RootElement, expected);
    }

    private static bool JsonElementEquals(JsonElement a, JsonElement b)
    {
        if (a.ValueKind != b.ValueKind)
        {
            return false;
        }

        switch (a.ValueKind)
        {
            case JsonValueKind.Object:
                var ap = a.EnumerateObject().ToDictionary(p => p.Name, p => p.Value, StringComparer.Ordinal);
                var bp = b.EnumerateObject().ToDictionary(p => p.Name, p => p.Value, StringComparer.Ordinal);
                return ap.Count == bp.Count
                       && ap.All(kv => bp.TryGetValue(kv.Key, out JsonElement bv) && JsonElementEquals(kv.Value, bv));
            case JsonValueKind.Array:
                JsonElement[] aa = a.EnumerateArray().ToArray();
                JsonElement[] ba = b.EnumerateArray().ToArray();
                return aa.Length == ba.Length && aa.Zip(ba, JsonElementEquals).All(x => x);
            case JsonValueKind.String:
                return a.GetString() == b.GetString();
            case JsonValueKind.Number:
                return a.GetRawText() == b.GetRawText() || a.GetDouble() == b.GetDouble();
            default:
                return true;
        }
    }

    // ------------------------------------------------------------------------------
    // §27.6.1 item 1 — metadata
    // ------------------------------------------------------------------------------

    /// <summary>
    /// <c>metadata</c> round-trips: apply, then plan, is all <c>NoChange</c>; changing one
    /// key is an <c>Update</c> whose body carries the WHOLE object. This is the regression
    /// test for the "reading metadata as never drifted" mutation named in the port task —
    /// if <c>JsonElementDeepEquals</c> always answered equal, the second Plan below would
    /// wrongly report <c>NoChange</c> instead of <c>Update</c>.
    /// </summary>
    [Fact]
    public async Task MetadataRoundTripsAndAnUpdateSendsTheWholeObject()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        JsonElement first = JsonDocument.Parse("""{"region":"eu","floor":3}""").RootElement;
        ManagementManifest manifest = ManagementManifest.Builder()
            .Resource("site", "site-1", "site", first)
            .Build();

        ApplyReport report = await client.Management.Manifest.ApplyAsync(manifest);
        Assert.True(report.IsComplete, report.Failure?.Outcome.Message);
        RecordedRequest created = Writes(fake)[0];
        Assert.True(JsonEquivalent(BodyOf(created)!["metadata"], first), "sent on Create");
        Assert.True((await client.Management.Manifest.PlanAsync(manifest)).IsConverged, "§27.6 rule 6");

        JsonElement second = JsonDocument.Parse("""{"region":"eu","floor":4}""").RootElement;
        ManagementManifest changed = ManagementManifest.Builder()
            .Resource("site", "site-1", "site", second)
            .Build();
        ManagementPlan plan = await client.Management.Manifest.PlanAsync(changed);
        Assert.Equal(PlanChange.Update, plan.Actions[0].Change);

        int mark = Mark(fake);
        await client.Management.Manifest.ApplyAsync(changed);
        RecordedRequest update = RequestsSince(fake, mark).Single(r => r.Method == "PUT");
        JsonNode? sent = BodyOf(update);
        Assert.Equal(new[] { "metadata", "resource_type" }, Keys(sent));
        Assert.True(JsonEquivalent(sent!["metadata"], second), "the whole object, never a merge");
        Assert.True((await client.Management.Manifest.PlanAsync(changed)).IsConverged);
    }

    /// <summary>A stated <c>{}</c> equals what the server stores for none; an unstated
    /// metadata is silent whatever the server holds (&#167;27.6 rule 3).</summary>
    [Fact]
    public async Task AnEmptyOrUnstatedMetadataIsNotDrift()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        fake.SeedResource("bare", new JsonObject());
        fake.SeedResource("rich", new JsonObject { ["hand"] = JsonValue.Create("made") });

        JsonElement emptyMeta = JsonDocument.Parse("{}").RootElement;
        ManagementManifest manifest = ManagementManifest.Builder()
            .Resource("a", "bare", "site", emptyMeta)
            .Resource("b", "rich", "site")
            .Build();

        ManagementPlan plan = await client.Management.Manifest.PlanAsync(manifest);
        Assert.True(plan.IsConverged, "a stated {} and an unstated metadata are not drift");
    }

    // ------------------------------------------------------------------------------
    // §27.6.1 item 2 — two-shape bindings
    // ------------------------------------------------------------------------------

    /// <summary>
    /// A resource-scoped binding with <c>inherit: false</c> sends <c>resource_id</c> and
    /// <c>inherit: false</c>; the same binding inheriting sends NO <c>inherit</c> key. This
    /// is the regression test for the "sending inherit: true explicitly" mutation: a
    /// wire-inherit computation that skipped the <c>inherit ? null : false</c> collapse
    /// would add an <c>inherit</c> key to <c>assigns[1]</c> below.
    /// </summary>
    [Fact]
    public async Task AScopedBindingSendsInheritOnlyWhenFalse()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        ManagementManifest manifest = ManagementManifest.Builder()
            .Resource("site", "site-1", "site")
            .Role("resident", "Resident", "Lives here")
            .Role("guest", "Guest", "Visits")
            .Group("g", "Residents", "All residents")
            .GroupRole("g", "resident", "site", inherit: false)
            .GroupRole("g", "guest", "site")
            .Build();

        ApplyReport report = await client.Management.Manifest.ApplyAsync(manifest);
        Assert.True(report.IsComplete, report.Failure?.Outcome.Message);

        List<JsonNode?> assigns = Writes(fake)
            .Where(r => r.Path.StartsWith("/api/v1/roles/", StringComparison.Ordinal)
                        && r.Path.EndsWith("/groups", StringComparison.Ordinal))
            .Select(BodyOf)
            .ToList();
        Assert.Equal(2, assigns.Count);
        Assert.False(assigns[0]!["inherit"]!.GetValue<bool>());
        Assert.NotNull(assigns[0]!["resource_id"]);
        Assert.Equal(new[] { "group_id", "resource_id" }, Keys(assigns[1]));
        Assert.True((await client.Management.Manifest.PlanAsync(manifest)).IsConverged);
    }

    /// <summary>
    /// Changing a binding's resource is unassign then assign, in that order, and the
    /// server binding's <c>tenant_scope</c> survives the change. This is the regression
    /// test for the "dropping tenant_scope on rebind" mutation the Go port missed — if
    /// <c>RebindAsync</c>'s assign call passed <c>null</c> instead of
    /// <c>rebind.Current.TenantScope</c>, the assertion on <c>sent[1]</c> below fails.
    /// </summary>
    [Fact]
    public async Task AChangedBindingIsUnassignThenAssignAndKeepsTenantScope()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        Guid oldSite = fake.SeedResource("site-1");
        fake.SeedResource("site-2");
        Guid role = fake.SeedRole("Concierge", isGlobal: false);
        Guid user = fake.SeedUser("ann");
        Guid scope = Guid.NewGuid();
        fake.SeedAssignment(new Assignment("users", role, user, oldSite, true, new[] { scope }));

        ManagementManifest manifest = ManagementManifest.Builder()
            .Resource("s1", "site-1", "site")
            .Resource("s2", "site-2", "site")
            .Role("concierge", "Concierge", "Concierge")
            .User("ann", "ann", "ann@example.test")
            .AssignRole("ann", "concierge", "s2")
            .Build();

        ManagementPlan plan = await client.Management.Manifest.PlanAsync(manifest);
        PlannedAction binding = plan.Actions.Single(a => a.Target == PlanTarget.UserRole);
        Assert.Equal(PlanChange.Update, binding.Change);

        int mark = Mark(fake);
        ApplyReport report = await client.Management.Manifest.ApplyAsync(manifest);
        Assert.True(report.IsComplete, report.Failure?.Outcome.Message);
        List<RecordedRequest> sent = RequestsSince(fake, mark).Where(r => r.Method != "GET").ToList();

        Assert.Equal(2, sent.Count);
        Assert.Equal("DELETE", sent[0].Method);
        Assert.Contains(oldSite.ToString(), sent[0].Query, StringComparison.Ordinal);
        Assert.Equal("POST", sent[1].Method);
        JsonNode? assignBody = BodyOf(sent[1]);
        Assert.Equal(
            new[] { scope.ToString() },
            assignBody!["tenant_scope"]!.AsArray().Select(t => t!.GetValue<string>()).ToArray());

        Assert.True((await client.Management.Manifest.PlanAsync(manifest)).IsConverged);
    }

    /// <summary>
    /// When the re-assignment fails, the previous binding is assigned again and the
    /// outcome names whether that restore succeeded. This is the regression test for the
    /// "skipping restore-on-failed-assign" mutation — an assign-half catch clause that
    /// rethrew instead of restoring would leave the subject holding neither binding, and
    /// the assertions on <c>held</c> below would fail.
    /// </summary>
    [Fact]
    public async Task AFailedReassignmentRestoresThePreviousBinding()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        Guid oldSite = fake.SeedResource("site-1");
        Guid newSite = fake.SeedResource("site-2");
        Guid role = fake.SeedRole("Concierge", isGlobal: false);
        Guid user = fake.SeedUser("ann");
        Guid scope = Guid.NewGuid();
        fake.SeedAssignment(new Assignment("users", role, user, oldSite, false, new[] { scope }));
        fake.RefuseAssignAt = newSite;

        ManagementManifest manifest = ManagementManifest.Builder()
            .Resource("s1", "site-1", "site")
            .Resource("s2", "site-2", "site")
            .Role("concierge", "Concierge", "Concierge")
            .User("ann", "ann", "ann@example.test")
            .AssignRole("ann", "concierge", "s2")
            .Build();

        ApplyReport report = await client.Management.Manifest.ApplyAsync(manifest);

        AppliedStep step = report.Steps.Single(s => s.Action.Target == PlanTarget.UserRole);
        Assert.Equal(ApplyStatus.Failed, step.Outcome.Status);
        Assert.Contains("refuses", step.Outcome.Message, StringComparison.Ordinal);
        Assert.Equal(true, step.Outcome.RestoreSucceeded);
        Assert.False(report.IsComplete);

        Assignment held = fake.Assignments.Single(a => a.Subject == user);
        Assert.Equal(oldSite, held.ResourceId);
        Assert.False(held.Inherit, "same inherit");
        Assert.Equal(new[] { scope }, held.TenantScope);
    }

    /// <summary>
    /// One role bound twice to one subject is a state the server cannot hold — rejected
    /// with zero wire calls, naming the subject and the role. Asserts the SPECIFIC message
    /// content and the specific zero-calls count, per the Go-port lesson: a test whose only
    /// possible failure is not the one it names can pass for the wrong reason. This is the
    /// regression test for the "removing the bound-twice check" mutation.
    /// </summary>
    [Fact]
    public async Task OneRoleBoundTwiceToOneSubjectIsRefusedWithNoWireCall()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        int before = Mark(fake);
        ManagementManifest manifest = ManagementManifest.Builder()
            .Resource("s1", "site-1", "site")
            .Resource("s2", "site-2", "site")
            .Role("resident", "Resident", "Lives here")
            .User("ann", "ann", "ann@example.test")
            .AssignRole("ann", "resident", "s1")
            .AssignRole("ann", "resident", "s2")
            .Build();

        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => client.Management.Manifest.PlanAsync(manifest));

        Assert.Contains("'ann'", thrown.Message, StringComparison.Ordinal);
        Assert.Contains("'resident'", thrown.Message, StringComparison.Ordinal);
        Assert.Contains("more than once", thrown.Message, StringComparison.Ordinal);
        Assert.Equal(before, Mark(fake));

        // Plain and scoped at once is the same impossibility.
        ManagementManifest mixed = ManagementManifest.Builder()
            .Resource("s1", "site-1", "site")
            .Role("resident", "Resident", "Lives here")
            .Group("g", "G", "G")
            .GroupRole("g", "resident")
            .GroupRole("g", "resident", "s1")
            .Build();

        await Assert.ThrowsAsync<NetworkError>(() => client.Management.Manifest.PlanAsync(mixed));
        Assert.Equal(before, Mark(fake));
    }

    /// <summary>A global role bound with <c>inherit: false</c> is refused by the server;
    /// the manifest says so first when the role is in it.</summary>
    [Fact]
    public async Task AGlobalRoleBoundHereOnlyIsRefusedClientSide()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        int before = Mark(fake);
        ManagementManifest manifest = ManagementManifest.Builder()
            .Resource("s1", "site-1", "site")
            .GlobalRole("admin", "Admin", "Everything")
            .Group("g", "G", "G")
            .GroupRole("g", "admin", "s1", inherit: false)
            .Build();

        await Assert.ThrowsAsync<NetworkError>(() => client.Management.Manifest.PlanAsync(manifest));
        Assert.Equal(before, Mark(fake));
    }

    /// <summary>A plain binding whose server assignment is scoped is an <c>Update</c>: the
    /// string shape means "no resource" (&#167;27.6.1 item 2).</summary>
    [Fact]
    public async Task APlainBindingOverAScopedAssignmentIsAnUpdate()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        Guid site = fake.SeedResource("site-1");
        Guid role = fake.SeedRole("Resident", isGlobal: false);
        Guid user = fake.SeedUser("ann");
        fake.SeedAssignment(new Assignment("users", role, user, site, true, null));

        ManagementManifest manifest = ManagementManifest.Builder()
            .Role("resident", "Resident", "Resident")
            .User("ann", "ann", "ann@example.test")
            .AssignRole("ann", "resident")
            .Build();

        ManagementPlan plan = await client.Management.Manifest.PlanAsync(manifest);
        PlannedAction binding = plan.Actions.Single(a => a.Target == PlanTarget.UserRole);
        Assert.Equal(PlanChange.Update, binding.Change);
    }

    /// <summary>
    /// Flipping <c>inherit</c> on a group's and a service account's binding is the same
    /// unassign-then-assign as for a user: each kind's own unassign route, then an assign
    /// carrying the new flag, and the next plan converges.
    /// </summary>
    [Fact]
    public async Task AFlippedInheritRebindsGroupsAndServiceAccountsToo()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        Guid site = fake.SeedResource("site-1");
        Guid role = fake.SeedRole("Concierge", isGlobal: false);
        Guid sa = fake.SeedServiceAccount("gate-controller");
        Guid group = fake.SeedGroup("Staff");
        fake.SeedAssignment(new Assignment("groups", role, group, site, true, null));
        fake.SeedAssignment(new Assignment("service-accounts", role, sa, site, true, null));

        ManagementManifest manifest = ManagementManifest.Builder()
            .Resource("site", "site-1", "site")
            .Role("concierge", "Concierge", "Concierge")
            .Group("staff", "Staff", "Staff")
            .GroupRole("staff", "concierge", "site", inherit: false)
            .ServiceAccount("gate", "gate-controller")
            .AssignServiceAccountRole("gate", "concierge", "site", inherit: false)
            .Build();

        int mark = Mark(fake);
        ApplyReport report = await client.Management.Manifest.ApplyAsync(manifest);
        Assert.True(report.IsComplete, report.Failure?.Outcome.Message);

        List<string> deletes = RequestsSince(fake, mark)
            .Where(r => r.Method == "DELETE")
            .Select(r => r.Path)
            .ToList();
        Assert.Equal(
            new[] { $"/api/v1/roles/{role}/groups/{group}", $"/api/v1/roles/{role}/service-accounts/{sa}" },
            deletes);
        Assert.All(fake.Assignments, a => Assert.False(a.Inherit));
        Assert.True((await client.Management.Manifest.PlanAsync(manifest)).IsConverged);
    }

    // ------------------------------------------------------------------------------
    // §27.6.1 item 3 and §27.5 rule 5 — service accounts
    // ------------------------------------------------------------------------------

    /// <summary>
    /// A service-account <c>Create</c> outcome carries <c>client_secret</c> as
    /// <c>Sensitive&lt;T&gt;</c> — and still does when a later action of the same
    /// <c>apply</c> fails. A second <c>apply</c> is <c>NoChange</c> and never rotates the
    /// secret. This is the regression test for the "discarding the created account's
    /// response" mutation — if <c>ExecuteAsync</c> dropped
    /// <c>res.CreatedServiceAccounts</c> instead of reading it back, or read it only on a
    /// COMPLETE apply, <c>CreatedServiceAccounts()</c> below would come back empty.
    /// </summary>
    [Fact]
    public async Task ACreatedServiceAccountsSecretSurvivesALaterFailureAndIsNeverRotated()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        Guid site = fake.SeedResource("site-1");
        fake.RefuseAssignAt = site;

        ManagementManifest manifest = ManagementManifest.Builder()
            .Resource("s1", "site-1", "site")
            .Role("gate", "Gate", "Opens the gate")
            .ServiceAccount("ctl", "gate-controller", "Opens the gate")
            .AssignServiceAccountRole("ctl", "gate", "s1")
            .Build();

        ApplyReport report = await client.Management.Manifest.ApplyAsync(manifest);

        Assert.False(report.IsComplete, "the binding after the account failed");
        ServiceAccountCreatedResponse created = report.CreatedServiceAccounts().Single();
        Assert.StartsWith("secret-of-", created.ClientSecret.Reveal(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret-of-", created.ToString(), StringComparison.Ordinal);

        var steps = report.Steps.ToList();
        int accountAt = steps.FindIndex(s => s.Action.Target == PlanTarget.ServiceAccount);
        int bindingAt = steps.FindIndex(s => s.Action.Target == PlanTarget.ServiceAccountRole);
        Assert.True(accountAt >= 0 && bindingAt >= 0 && accountAt < bindingAt, "§27.6 rule 5: account before its binding");

        // Fix the cause and re-apply: the account is NoChange, and nothing rotates.
        fake.RefuseAssignAt = null;
        ApplyReport secondReport = await client.Management.Manifest.ApplyAsync(manifest);
        Assert.True(secondReport.IsComplete, secondReport.Failure?.Outcome.Message);
        AppliedStep account = secondReport.Steps.Single(s => s.Action.Target == PlanTarget.ServiceAccount);
        Assert.Equal(PlanChange.NoChange, account.Action.Change);
        Assert.Empty(secondReport.CreatedServiceAccounts());
        Assert.DoesNotContain(fake.Requests, r => r.Path.EndsWith("/rotate-secret", StringComparison.Ordinal));
        Assert.True((await client.Management.Manifest.PlanAsync(manifest)).IsConverged);
    }

    /// <summary>The name is the natural key and the server does not enforce it: two
    /// existing accounts with the stated name make <c>apply</c> fail before any write.</summary>
    [Fact]
    public async Task AnAmbiguousServiceAccountNameFailsPlanBeforeAnyWrite()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        fake.SeedServiceAccount("gate-controller");
        fake.SeedServiceAccount("gate-controller");

        ManagementManifest manifest = ManagementManifest.Builder()
            .ServiceAccount("ctl", "gate-controller")
            .Build();

        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => client.Management.Manifest.ApplyAsync(manifest));

        Assert.Contains("more than one existing account", thrown.Message, StringComparison.Ordinal);
        Assert.Empty(Writes(fake));
    }

    /// <summary>A stated description that drifts is a sparse <c>Update</c> of that field
    /// alone; an unstated one is silent.</summary>
    [Fact]
    public async Task OnlyAStatedDescriptionIsReconciled()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        fake.SeedServiceAccount("gate-controller");

        ManagementManifest silent = ManagementManifest.Builder()
            .ServiceAccount("ctl", "gate-controller")
            .Build();
        Assert.True((await client.Management.Manifest.PlanAsync(silent)).IsConverged);

        ManagementManifest stated = ManagementManifest.Builder()
            .ServiceAccount("ctl", "gate-controller", "Opens the gate")
            .Build();
        await client.Management.Manifest.ApplyAsync(stated);

        RecordedRequest update = Writes(fake).Single(r => r.Method == "PUT");
        Assert.Equal(new[] { "description" }, Keys(BodyOf(update)));
        Assert.True((await client.Management.Manifest.PlanAsync(stated)).IsConverged);
    }

    /// <summary>&#167;27.6 rule 6 over all three additions at once — the test worth more
    /// than any other in this section.</summary>
    [Fact]
    public async Task ApplyThenPlanConvergesWithEveryAddition()
    {
        var fake = new TenantFake();
        using AxiamClient client = BuildClient(fake);
        JsonElement metadata = JsonDocument.Parse("""{"k":1}""").RootElement;

        ManagementManifest manifest = ManagementManifest.Builder()
            .Resource("site", "site-1", "site", metadata)
            .ChildResource("flat", "flat-7", "apartment", "site")
            .Role("resident", "Resident", "Lives here")
            .Role("concierge", "Concierge", "Runs the site")
            .Group("staff", "Staff", "Staff", "concierge")
            .User("ann", "ann", "ann@example.test", Sensitive<string>.Wrap(Guid.NewGuid().ToString()))
            .AssignRole("ann", "resident", "flat", inherit: false)
            .ServiceAccount("ctl", "gate-controller")
            .AssignServiceAccountRole("ctl", "concierge", "site", inherit: false)
            .Build();

        ApplyReport report = await client.Management.Manifest.ApplyAsync(manifest);
        Assert.True(report.IsComplete, report.Failure?.Outcome.Message);

        ManagementPlan plan = await client.Management.Manifest.PlanAsync(manifest);
        Assert.True(plan.IsConverged, string.Join("; ", plan.Changes.Select(c => c.Summary)));
    }

    /// <summary>
    /// A guard on the fake itself: it refuses a second assignment of the same role to the
    /// same subject, the server property the "bound twice" rule is about — so the tests
    /// above are not passing against a fake more permissive than the real server.
    /// </summary>
    [Fact]
    public async Task TheFakeEnforcesOneAssignmentPerSubjectAndRole()
    {
        var fake = new TenantFake();
        Guid role = fake.SeedRole("R", isGlobal: false);
        Guid user = fake.SeedUser("u");
        using var http = new HttpClient(fake) { BaseAddress = Base };

        var statuses = new List<int>();
        for (int i = 0; i < 2; i++)
        {
            HttpResponseMessage response = await http.PostAsync(
                $"/api/v1/roles/{role}/users",
                new StringContent($$"""{"user_id":"{{user}}"}""", Encoding.UTF8, "application/json"));
            statuses.Add((int)response.StatusCode);
        }

        Assert.Equal(new[] { 204, 409 }, statuses);
    }

    // ================================================================================
    // The fake tenant
    // ================================================================================

    private sealed record Assignment(
        string Kind, Guid Role, Guid Subject, Guid? ResourceId, bool Inherit, IReadOnlyList<Guid>? TenantScope);

    /// <summary>
    /// A small stateful fake of one tenant's management API, just enough of it to prove
    /// &#167;27.6's convergence property end to end. See the remark on
    /// <see cref="ManifestAdditionsTests"/> for why this exists alongside
    /// <see cref="ManagementTestBase"/> rather than instead of it.
    /// </summary>
    private sealed class TenantFake : HttpMessageHandler
    {
        private const string Now = "2026-09-24T00:00:00Z";

        internal readonly List<JsonObject> Resources = new();
        internal readonly List<JsonObject> Roles = new();
        internal readonly List<JsonObject> Groups = new();
        internal readonly List<JsonObject> Users = new();
        internal readonly List<JsonObject> ServiceAccounts = new();
        internal readonly List<Assignment> Assignments = new();
        internal readonly List<RecordedRequest> Requests = new();

        /// <summary>Refuses an assign that names this resource, with a 400 — the fault the
        /// binding-update restore is tested against.</summary>
        internal Guid? RefuseAssignAt;

        private static JsonNode Str(string s) => JsonValue.Create(s)!;

        private static JsonNode? StrOrNull(string? s) => s is null ? null : JsonValue.Create(s);

        private static JsonNode Bool(bool b) => JsonValue.Create(b)!;

        private static JsonNode GuidNode(Guid g) => JsonValue.Create(g.ToString())!;

        private static JsonNode? GuidOrNull(Guid? g) => g is null ? null : JsonValue.Create(g.Value.ToString());

        private static Guid? NodeGuid(JsonNode? node) => node is null ? null : Guid.Parse(node.GetValue<string>());

        internal Guid SeedResource(
            string name, JsonObject? metadata = null, Guid? parent = null, string resourceType = "site")
        {
            Guid id = Guid.NewGuid();
            Resources.Add(new JsonObject
            {
                ["id"] = GuidNode(id),
                ["tenant_id"] = GuidNode(TenantId),
                ["name"] = Str(name),
                ["resource_type"] = Str(resourceType),
                ["parent_id"] = GuidOrNull(parent),
                ["metadata"] = (metadata ?? new JsonObject()).DeepClone(),
                ["created_at"] = Str(Now),
                ["updated_at"] = Str(Now),
            });
            return id;
        }

        internal Guid SeedRole(string name, bool isGlobal)
        {
            Guid id = Guid.NewGuid();
            Roles.Add(new JsonObject
            {
                ["id"] = GuidNode(id),
                ["tenant_id"] = GuidNode(TenantId),
                ["name"] = Str(name),
                ["description"] = Str(name),
                ["is_global"] = Bool(isGlobal),
                ["created_at"] = Str(Now),
                ["updated_at"] = Str(Now),
            });
            return id;
        }

        internal Guid SeedUser(string username)
        {
            Guid id = Guid.NewGuid();
            Users.Add(UserJson(id, username));
            return id;
        }

        internal Guid SeedGroup(string name)
        {
            Guid id = Guid.NewGuid();
            Groups.Add(new JsonObject
            {
                ["id"] = GuidNode(id),
                ["tenant_id"] = GuidNode(TenantId),
                ["name"] = Str(name),
                ["description"] = Str(name),
                ["metadata"] = new JsonObject(),
                ["created_at"] = Str(Now),
                ["updated_at"] = Str(Now),
            });
            return id;
        }

        internal Guid SeedServiceAccount(string name)
        {
            Guid id = Guid.NewGuid();
            ServiceAccounts.Add(SaJson(id, name, null));
            return id;
        }

        internal void SeedAssignment(Assignment a) => Assignments.Add(a);

        private static JsonObject UserJson(Guid id, string username) => new()
        {
            ["id"] = GuidNode(id),
            ["tenant_id"] = GuidNode(TenantId),
            ["username"] = Str(username),
            ["email"] = Str($"{username}@example.test"),
            ["status"] = Str("Active"),
            ["mfa_enabled"] = Bool(false),
            ["email_verified"] = Bool(true),
            ["metadata"] = new JsonObject(),
            ["failed_login_attempts"] = JsonValue.Create(0)!,
            ["is_locked"] = Bool(false),
            ["created_at"] = Str(Now),
            ["updated_at"] = Str(Now),
        };

        private static JsonObject SaJson(Guid id, string name, string? description) => new()
        {
            ["id"] = GuidNode(id),
            ["tenant_id"] = GuidNode(TenantId),
            ["name"] = Str(name),
            ["description"] = StrOrNull(description),
            ["client_id"] = Str($"client-{id}"),
            ["status"] = Str("Active"),
            ["created_at"] = Str(Now),
            ["updated_at"] = Str(Now),
        };

        private static JsonNode Page(IEnumerable<JsonObject> items)
        {
            List<JsonObject> list = items.ToList();
            return new JsonObject
            {
                ["items"] = new JsonArray(list.Select(i => (JsonNode)i.DeepClone()).ToArray()),
                ["total"] = JsonValue.Create(list.Count)!,
                ["offset"] = JsonValue.Create(0)!,
                ["limit"] = JsonValue.Create(200)!,
            };
        }

        private static Guid? ParseQueryGuid(string rawQuery, string key)
        {
            foreach (string pair in rawQuery.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = pair.IndexOf('=', StringComparison.Ordinal);
                if (eq > 0 && Uri.UnescapeDataString(pair[..eq]) == key)
                {
                    return Guid.TryParse(Uri.UnescapeDataString(pair[(eq + 1)..]), out Guid g) ? g : null;
                }
            }

            return null;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = request.RequestUri!.AbsolutePath;
            string method = request.Method.Method;
            string query = request.RequestUri.Query;
            string bodyText = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            Requests.Add(new RecordedRequest(method, path, query, bodyText));
            JsonNode? body = bodyText.Length > 0 ? JsonNode.Parse(bodyText) : null;

            string[] segments = path.StartsWith("/api/v1/", StringComparison.Ordinal)
                ? path["/api/v1/".Length..].Split('/', StringSplitOptions.RemoveEmptyEntries)
                : Array.Empty<string>();

            static HttpResponseMessage Json(int status, JsonNode? node) => new((HttpStatusCode)status)
            {
                Content = new StringContent(node?.ToJsonString() ?? string.Empty, Encoding.UTF8, "application/json"),
            };

            static HttpResponseMessage Text(int status, string text) =>
                new((HttpStatusCode)status) { Content = new StringContent(text) };

            static HttpResponseMessage Empty(int status) => new((HttpStatusCode)status);

            switch (method, segments)
            {
                case ("GET", ["resources"]):
                    return Json(200, Page(Resources));

                case ("GET", ["resources", _, "scopes"]):
                    return Json(200, new JsonArray());

                case ("POST", ["resources"]):
                {
                    Guid id = Guid.NewGuid();
                    JsonNode? metadata = body!["metadata"];
                    var created = new JsonObject
                    {
                        ["id"] = GuidNode(id),
                        ["tenant_id"] = GuidNode(TenantId),
                        ["name"] = body["name"]!.DeepClone(),
                        ["resource_type"] = body["resource_type"]!.DeepClone(),
                        ["parent_id"] = body["parent_id"]?.DeepClone(),
                        // The server stores {} for a resource created without any.
                        ["metadata"] = metadata is null ? new JsonObject() : metadata.DeepClone(),
                        ["created_at"] = Str(Now),
                        ["updated_at"] = Str(Now),
                    };
                    Resources.Add(created);
                    return Json(201, created.DeepClone());
                }

                case ("PUT", ["resources", var rid]):
                {
                    JsonObject r = Resources.First(x => x["id"]!.GetValue<string>() == rid);
                    if (body is JsonObject rbo)
                    {
                        foreach (string field in new[] { "metadata", "resource_type" })
                        {
                            if (rbo.ContainsKey(field))
                            {
                                r[field] = rbo[field]?.DeepClone();
                            }
                        }
                    }

                    return Json(200, r.DeepClone());
                }

                case ("GET", ["permissions"]):
                    return Json(200, Page(Array.Empty<JsonObject>()));

                case ("GET", ["roles"]):
                    return Json(200, Page(Roles));

                case ("POST", ["roles"]):
                {
                    Guid id = Guid.NewGuid();
                    var created = new JsonObject
                    {
                        ["id"] = GuidNode(id),
                        ["tenant_id"] = GuidNode(TenantId),
                        ["name"] = body!["name"]!.DeepClone(),
                        ["description"] = body["description"]!.DeepClone(),
                        ["is_global"] = body["is_global"] is { } g ? g.DeepClone() : Bool(false),
                        ["created_at"] = Str(Now),
                        ["updated_at"] = Str(Now),
                    };
                    Roles.Add(created);
                    return Json(201, created.DeepClone());
                }

                case ("GET", ["roles", _, "permissions"]):
                    return Json(200, new JsonArray());

                case ("GET", [var kindSubj, var subjId, "roles"])
                    when kindSubj is "users" or "groups" or "service-accounts":
                {
                    Guid subject = Guid.Parse(subjId);
                    var rows = new JsonArray();
                    foreach (Assignment a in Assignments.Where(a => a.Subject == subject && a.Kind == kindSubj))
                    {
                        JsonObject role = Roles.First(r => r["id"]!.GetValue<string>() == a.Role.ToString());
                        var row = new JsonObject
                        {
                            ["role"] = role.DeepClone(),
                            ["resource_id"] = GuidOrNull(a.ResourceId),
                            ["inherit"] = Bool(a.Inherit),
                        };
                        if (a.TenantScope is { Count: > 0 } ts)
                        {
                            row["tenant_scope"] = new JsonArray(ts.Select(t => (JsonNode)GuidNode(t)).ToArray());
                        }

                        rows.Add(row);
                    }

                    return Json(200, rows);
                }

                case ("POST", ["roles", var roleIdStr, var kindAssign])
                    when kindAssign is "users" or "groups" or "service-accounts":
                {
                    Guid roleId = Guid.Parse(roleIdStr);
                    string subjectField = kindAssign switch
                    {
                        "users" => "user_id",
                        "groups" => "group_id",
                        _ => "service_account_id",
                    };
                    Guid subject = Guid.Parse(body![subjectField]!.GetValue<string>());
                    Guid? resourceId = NodeGuid(body["resource_id"]);
                    if (resourceId is not null && resourceId == RefuseAssignAt)
                    {
                        return Text(400, "resource refuses this assignment");
                    }

                    // has_role is UNIQUE(in, out): one assignment per subject and role.
                    if (Assignments.Any(a => a.Role == roleId && a.Subject == subject))
                    {
                        return Text(409, "already assigned");
                    }

                    bool inherit = body["inherit"] is { } iv && iv.GetValueKind() != JsonValueKind.Null
                        ? iv.GetValue<bool>()
                        : true;
                    IReadOnlyList<Guid>? tenantScope = body["tenant_scope"] is JsonArray ta
                        ? ta.Select(t => Guid.Parse(t!.GetValue<string>())).ToList()
                        : null;
                    Assignments.Add(new Assignment(kindAssign, roleId, subject, resourceId, inherit, tenantScope));
                    return Empty(204);
                }

                case ("DELETE", ["roles", var roleIdStr2, var kindUnassign, var subjectIdStr])
                    when kindUnassign is "users" or "groups" or "service-accounts":
                {
                    Guid roleId = Guid.Parse(roleIdStr2);
                    Guid subject = Guid.Parse(subjectIdStr);
                    Guid? resourceId = ParseQueryGuid(query, "resource_id");
                    int before = Assignments.Count;
                    Assignments.RemoveAll(a => a.Role == roleId && a.Subject == subject && a.ResourceId == resourceId);
                    return Assignments.Count == before ? Empty(404) : Empty(204);
                }

                case ("GET", ["groups"]):
                    return Json(200, Page(Groups));

                case ("GET", ["groups", _, "members"]):
                    return Json(200, Page(Array.Empty<JsonObject>()));

                case ("POST", ["groups"]):
                {
                    Guid id = Guid.NewGuid();
                    var created = new JsonObject
                    {
                        ["id"] = GuidNode(id),
                        ["tenant_id"] = GuidNode(TenantId),
                        ["name"] = body!["name"]!.DeepClone(),
                        ["description"] = body["description"]!.DeepClone(),
                        ["metadata"] = new JsonObject(),
                        ["created_at"] = Str(Now),
                        ["updated_at"] = Str(Now),
                    };
                    Groups.Add(created);
                    return Json(201, created.DeepClone());
                }

                case ("GET", ["users"]):
                    return Json(200, Page(Users));

                case ("POST", ["users"]):
                {
                    JsonObject created = UserJson(Guid.NewGuid(), body!["username"]!.GetValue<string>());
                    Users.Add(created);
                    return Json(201, created.DeepClone());
                }

                case ("GET", ["service-accounts"]):
                    return Json(200, Page(ServiceAccounts));

                case ("POST", ["service-accounts"]):
                {
                    Guid id = Guid.NewGuid();
                    string? description = body!["description"]?.GetValue<string>();
                    JsonObject created = SaJson(id, body["name"]!.GetValue<string>(), description);
                    ServiceAccounts.Add(created);
                    var withSecret = (JsonObject)created.DeepClone();
                    // Returned here, and by nothing else.
                    withSecret["client_secret"] = Str($"secret-of-{id}");
                    return Json(201, withSecret);
                }

                case ("PUT", ["service-accounts", var saId]):
                {
                    JsonObject a = ServiceAccounts.First(x => x["id"]!.GetValue<string>() == saId);
                    if (body is JsonObject sbo && sbo.ContainsKey("description"))
                    {
                        a["description"] = sbo["description"]?.DeepClone();
                    }

                    return Json(200, a.DeepClone());
                }

                default:
                    return Text(599, $"fake: unhandled {method} {path}");
            }
        }
    }
}
