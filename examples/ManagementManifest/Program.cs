using Axiam.Sdk;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Options;

// The CONTRACT.md §27.6 declarative layer: describe the tenant you want, see what would
// change, then apply it.
//
// A manifest states what should exist. It is not a diff and not a migration: running it
// against a tenant that already matches writes nothing, and running it twice is the same
// as running it once. What it never does is delete — something the manifest does not
// mention is something the manifest has no opinion about, not something it wants gone
// (§27.6 rule 4).
//
// Run: AXIAM_BASE_URL=... AXIAM_TENANT=... AXIAM_ADMIN=... AXIAM_ADMIN_PASSWORD=...
//      dotnet run --project examples/ManagementManifest -- --apply

bool apply = args.Length > 0 && args[0] == "--apply";
string baseUrl = Env("AXIAM_BASE_URL", "https://localhost:8443");
string tenant = Env("AXIAM_TENANT", "acme");
string admin = Env("AXIAM_ADMIN", "admin@example.com");
string password = Env("AXIAM_ADMIN_PASSWORD", "changeme");

// The builder checks back-references as they are made: a grant naming a role no Role(...)
// call has declared is refused at Build(), before any request. Ordering between KINDS is
// derived (resources before scopes, permissions before grants), so this reads top-down
// but need not.
ManagementManifest manifest = ManagementManifest.Builder()
    .Resource("docs", "documents", "collection")
    .Scope("docs", "draft", "draft", "Unpublished work")
    .ChildResource("archive", "archive", "collection", "docs")
    .Permission("read", "document:read", "Read a document")
    .Permission("purge", "document:purge", "Permanently delete a document")
    .Role("editor", "Editor", "Edits documents")
    // A grant narrowed to a scope applies only within it.
    .Grant("editor", "read", null, "draft")
    // AXIAM's RBAC is DENY-OVERRIDE: this refusal beats every allow that reaches the
    // same principal, at any depth of the resource hierarchy. It is not "the more
    // specific rule wins".
    .Grant("editor", "purge", "deny")
    .Group("staff", "Staff", "Everyone in the company", "editor")
    .User("alice", "alice", "alice@example.test", Sensitive<string>.Wrap("correct-horse-battery"))
    .AssignRole("alice", "editor")
    .AddToGroup("alice", "staff")
    .Build();

using var client = new AxiamClient(
    new Uri(baseUrl),
    tenant,
    new AxiamClientOptions { BaseUrl = new Uri(baseUrl), TenantId = tenant, OrgSlug = tenant });

await client.LoginAsync(admin, password);

// PlanAsync issues reads and nothing else — it cannot change the tenant, so it is safe
// to run against production to find out what an apply would do.
ManagementPlan plan = await client.Management.Manifest.PlanAsync(manifest);
Console.WriteLine(plan.IsConverged
    ? "tenant already matches the manifest; nothing to do"
    : $"{plan.Changes.Count} change(s) pending:");
foreach (PlannedAction action in plan.Changes)
{
    Console.WriteLine($"  {action.Change} {action.Target}  {action.Summary}");
}

if (!apply)
{
    Console.WriteLine("(re-run with --apply to execute)");
    return;
}

// ApplyAsync stops at the FIRST failure and does not roll back (§27.6 rule 7).
// Everything before the failure stands; everything after it is reported as never
// attempted. That is deliberate: an automatic rollback would be a second unreviewed
// batch of writes issued at exactly the moment the tenant is in an unknown state.
ApplyReport report = await client.Management.Manifest.ApplyAsync(manifest);
foreach (AppliedStep step in report.Steps)
{
    Console.WriteLine($"  {step.Outcome.Status,-13} {step.Action.Summary}");
}

if (report.Failure is { } failed)
{
    Console.WriteLine($"stopped at: {failed.Action.Summary} -- {failed.Outcome.Message}");
}

Console.WriteLine(report.IsComplete
    ? $"applied {report.ChangedCount} change(s)"
    : "INCOMPLETE: fix the failure above and re-run; what succeeded stands");

static string Env(string name, string fallback) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : fallback;
