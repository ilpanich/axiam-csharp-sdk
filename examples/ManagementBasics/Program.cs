using Axiam.Sdk;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Options;

// Walks the CONTRACT.md §27 management surface: namespace handles, paging, sparse
// updates, one-time secrets, and the three error classifications.
//
// Every call goes through `client.Management`, which is a view over the same session
// the rest of the SDK uses — there is no second client to build, no second login, and
// no second set of TLS settings to get wrong.
//
// Run: AXIAM_BASE_URL=... AXIAM_TENANT=... AXIAM_ADMIN=... AXIAM_ADMIN_PASSWORD=...
//      dotnet run --project examples/ManagementBasics

string baseUrl = Env("AXIAM_BASE_URL", "https://localhost:8443");
string tenant = Env("AXIAM_TENANT", "acme");
string admin = Env("AXIAM_ADMIN", "admin@example.com");
string password = Env("AXIAM_ADMIN_PASSWORD", "changeme");

using var client = new AxiamClient(
    new Uri(baseUrl),
    tenant,
    new AxiamClientOptions { BaseUrl = new Uri(baseUrl), TenantId = tenant, OrgSlug = tenant });

await client.LoginAsync(admin, password);

// §27.2: a handle is a view, not a connection. Reaching for one is free and performs
// no I/O, so holding onto it buys nothing.
Console.WriteLine($"org    : {client.ResolvedOrgId}");
Console.WriteLine($"tenant : {client.ResolvedTenantId}");

// ------------------------------------------------------------------
// §27.4 rule 4 — paging
// ------------------------------------------------------------------

// Total is the size of the WHOLE set, not of this page. Treating Items.Count as the
// total is the bug this type exists to stop.
Page<UserResponse> firstPage = await client.Management.Users.ListAsync(PageRequest.Of(25));
Console.WriteLine($"users  : {firstPage.Items.Count} of {firstPage.Total}");

// ListAllAsync walks to exhaustion. It stops on an empty page even if the server's
// total disagrees, so a miscounting server costs one wasted request rather than an
// unbounded loop.
IReadOnlyList<Role> roles = await client.Management.Roles.ListAllAsync();
Console.WriteLine($"roles  : {roles.Count}");

// ------------------------------------------------------------------
// §27.4 rule 5 — sparse update vs replacement
// ------------------------------------------------------------------

if (firstPage.Items.Count > 0)
{
    // A sparse body sends ONLY the properties you name. Everything you leave out is
    // absent from the JSON entirely — not sent as null, which the server would read as
    // "clear this field". C# object initializers already are the builder.
    await client.Management.Users.UpdateAsync(
        firstPage.Items[0].Id,
        new UpdateUserRequest { Email = "renamed@example.test" });
}

// A replacement body's properties are `required`: forgetting one is a compile error
// rather than a silent overwrite with null.
Role created = await client.Management.Roles.CreateAsync(
    new CreateRoleRequest { Description = "Edits documents", IsGlobal = false, Name = "Editor" });
Console.WriteLine($"created: {created.Id}");

// ------------------------------------------------------------------
// §27.4 rule 7 — the three classifications
// ------------------------------------------------------------------

// Each inherits the parent §2 already gave its status, so code that already catches
// AuthzError or NetworkError keeps working, and code that wants the distinction can
// ask for it.
try
{
    await client.Management.Users.GetAsync(Guid.NewGuid());
}
catch (NotFoundError e)
{
    Console.WriteLine($"404 -> NotFoundError (an AuthzError): {e.Message}");
}

try
{
    await client.Management.Roles.CreateAsync(
        new CreateRoleRequest { Description = "Edits documents", IsGlobal = false, Name = "Editor" });
}
catch (ConflictError e)
{
    // Also an AuthzError: §2 already mapped 409 there, and the sub-type keeps that
    // mapping rather than moving the status.
    Console.WriteLine($"409 -> ConflictError: {e.Message}");
}

try
{
    await client.Management.Users.CreateAsync(new CreateUserRequest
    {
        Email = "not-an-email",
        Password = Sensitive<string>.Wrap("correct-horse-battery"),
        Username = "someone",
    });
}
catch (ValidationError e)
{
    // A ValidationError carries the server's per-field detail when it sent any, so the
    // caller can point at the offending input.
    Console.WriteLine($"400 -> ValidationError on: [{string.Join(", ", e.Fields.Select(f => f.Field))}]");
}

// §27.4 rule 8: only GETs are retried. A create that times out is reported, never
// repeated — one retried POST is two roles.

static string Env(string name, string fallback) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : fallback;
