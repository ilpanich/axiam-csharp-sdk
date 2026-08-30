using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Opaque;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Contract 1.34 &#167;5.2.2 and contract 1.35 &#167;5.2.3 — the acting tenant vs the
/// principal tenant, and tenant-scoped role assignments.
/// </summary>
/// <remarks>
/// <para>
/// Two of these rules are the kind an SDK breaks silently rather than loudly, which is why
/// they are pinned here rather than left to the generated surface test:
/// </para>
/// <para>
/// <b>&#167;5.2.2 rule 2.</b> A registration record for the caller's <i>own</i> password is
/// sealed against the tenant the account lives in, not the one the client is pointed at. Get
/// it wrong and the server answers "the OPAQUE session was issued for a different tenant" —
/// but only for an organization-level principal that has switched tenant, so it passes every
/// test written against an ordinary account.
/// </para>
/// <para>
/// <b>&#167;5.2.3 rule 1.</b> <c>tenant_scope: []</c> is refused with <c>400</c>. A null check
/// alone does not prevent it: an empty array is the natural thing to build for "no tenants
/// named", and it is not null.
/// </para>
/// </remarks>
[Trait("Category", "Fast")]
[Collection("Opaque")]
public sealed class Contract135Tests : IDisposable
{
    private static readonly Uri BaseUrl = new("https://axiam-135.test");
    private const string ActingTenant = "33333333-3333-4333-8333-333333333333";
    private const string PrincipalTenant = "55555555-5555-4555-8555-555555555555";
    private const string OrgId = "11111111-1111-4111-8111-111111111111";
    private const string ReachableTenant = "66666666-6666-4666-8666-666666666666";

    /// <summary>
    /// The acting tenant as a <b>slug</b>, for the two &#167;23 tests.
    /// </summary>
    /// <remarks>
    /// A slug rather than the GUID on purpose: <c>ApplyTenantAndOrgFields</c> writes
    /// <c>tenant_slug</c> for one and <c>tenant_id</c> for the other, and &#167;5.2.2 rule 2's
    /// override has to <i>remove</i> the slug it finds. Pointed at a GUID tenant there is no
    /// slug to remove, so the assertion that it is gone would pass against an implementation
    /// that never removed anything.
    /// </remarks>
    private const string ActingTenantSlug = "acme";

    private const string LoginPath = "/api/v1/auth/login";
    private const string RegisterStartPath = "/api/v1/auth/opaque/register/start";

    /// <summary>The hex RegistrationResponse the fake server answers with.</summary>
    private const string WireRegistrationResponse = "726573703a";

    /// <summary>
    /// Minted per run rather than written down: nothing here depends on the value — the login
    /// stub answers 200 regardless, so what is under test is which tenant the body names,
    /// never whether a credential matched — and a literal that reads like a credential is a
    /// finding for every secret scanner that looks at this repository.
    /// </summary>
    private static readonly string PasswordText =
        "fixture-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));

    private static char[] Password => PasswordText.ToCharArray();

    private readonly FakeOpaqueNative _lib = new();

    public Contract135Tests() => OpaqueLibrary.SetForTests(_lib);

    public void Dispose()
    {
        OpaqueLibrary.ResetForTests();
        _lib.Dispose();
    }

    private static AxiamClient Client(RoutingHandler handler) =>
        AxiamClient.CreateForTesting(
            BaseUrl,
            ActingTenant,
            new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = ActingTenant },
            handler);

    /// <summary>The same client, pointed at the acting tenant by slug. See <see cref="ActingTenantSlug"/>.</summary>
    private static AxiamClient SlugClient(RoutingHandler handler) =>
        AxiamClient.CreateForTesting(
            BaseUrl,
            ActingTenantSlug,
            new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = ActingTenantSlug },
            handler);

    /// <summary>A 200 <c>LoginSuccessResponse</c> whose <c>user</c> object is <paramref name="user"/>.</summary>
    private static HttpResponseMessage LoginSuccess(string user)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"user\":" + user
                + ",\"session_id\":\"22222222-2222-4222-8222-222222222222\",\"expires_in\":900}",
                Encoding.UTF8,
                "application/json"),
        };
        response.Headers.Add("Set-Cookie", "axiam_access=fake-token; Path=/");
        return response;
    }

    private static HttpResponseMessage RegisterStart() =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"opaque_session\":\"reg-handle\",\"registration_response\":\""
                + WireRegistrationResponse
                + "\",\"ksf\":\"argon2id\",\"memory_kib\":19456,\"iterations\":2,\"parallelism\":1}",
                Encoding.UTF8,
                "application/json"),
        };

    // -----------------------------------------------------------------
    // §5.2.2 — acting tenant vs principal tenant
    // -----------------------------------------------------------------

    /// <summary>
    /// Rule 1: absent means <i>equal</i>, not unknown. A server older than contract 1.34 omits
    /// <c>principal_tenant_id</c> and cannot switch the acting tenant either, so reading
    /// <c>tenant_id</c> there is not a guess — it is the only value the field could have had.
    /// </summary>
    [Fact]
    public async Task AbsentPrincipalTenantReadsAsTheActingTenant()
    {
        using var handler = new RoutingHandler();
        handler.Map(LoginPath, _ => LoginSuccess("{\"tenant_id\":\"" + ActingTenant + "\"}"));
        using AxiamClient client = Client(handler);

        LoginResult result = await client.LoginAsync(
            "alice@example.com", PasswordText, CancellationToken.None);

        Assert.NotNull(result.Scope);
        Assert.Equal(Guid.Parse(ActingTenant), result.Scope!.ActingTenantId);
        Assert.Equal(Guid.Parse(ActingTenant), result.Scope.PrincipalTenantId);
        Assert.Null(result.Scope.PrincipalTenantSlug);
    }

    /// <summary>
    /// The whole point of the field: for an organization-level principal that has selected
    /// another tenant, the two differ and the SDK must not collapse them.
    /// </summary>
    [Fact]
    public async Task DivergentPrincipalTenantIsReportedSeparately()
    {
        using var handler = new RoutingHandler();
        handler.Map(LoginPath, _ => LoginSuccess(
            "{\"tenant_id\":\"" + ActingTenant + "\","
            + "\"principal_tenant_id\":\"" + PrincipalTenant + "\","
            + "\"principal_tenant_slug\":\"organization\","
            + "\"org_id\":\"" + OrgId + "\","
            + "\"organization_level\":true}"));
        using AxiamClient client = Client(handler);

        LoginResult result = await client.LoginAsync(
            "alice@example.com", PasswordText, CancellationToken.None);

        Assert.True(result.OrganizationLevel);
        Assert.NotNull(result.Scope);
        Assert.Equal(Guid.Parse(ActingTenant), result.Scope!.ActingTenantId);
        Assert.Equal(Guid.Parse(PrincipalTenant), result.Scope.PrincipalTenantId);
        Assert.Equal("organization", result.Scope.PrincipalTenantSlug);

        // Rule 3: read the organization from the session rather than resolving a slug through
        // the super-admin-only GET /api/v1/organizations.
        Assert.Equal(Guid.Parse(OrgId), result.Scope.OrgId);
    }

    /// <summary>
    /// &#167;5.2.3 rule 3: a narrowed principal still reports <c>OrganizationLevel = true</c>,
    /// which is exactly why gating on that flag alone offers tenants the server refuses.
    /// </summary>
    [Fact]
    public async Task ReachableTenantIdsNarrowsAnOrganizationLevelPrincipal()
    {
        using var handler = new RoutingHandler();
        handler.Map(LoginPath, _ => LoginSuccess(
            "{\"tenant_id\":\"" + ActingTenant + "\",\"organization_level\":true,"
            + "\"reachable_tenant_ids\":[\"" + ReachableTenant + "\"]}"));
        using AxiamClient client = Client(handler);

        LoginResult result = await client.LoginAsync(
            "alice@example.com", PasswordText, CancellationToken.None);

        Assert.True(result.OrganizationLevel);
        Assert.NotNull(result.Scope?.ReachableTenantIds);
        Assert.Equal(
            new[] { Guid.Parse(ReachableTenant) },
            result.Scope!.ReachableTenantIds!);
    }

    /// <summary>
    /// <c>null</c>, never an empty list: an empty list would read as "reaches nothing", the
    /// opposite of what an omitted field means here.
    /// </summary>
    [Fact]
    public async Task AbsentReachIsUnrestrictedNotEmpty()
    {
        using var handler = new RoutingHandler();
        handler.Map(LoginPath, _ => LoginSuccess("{\"tenant_id\":\"" + ActingTenant + "\"}"));
        using AxiamClient client = Client(handler);

        LoginResult result = await client.LoginAsync(
            "alice@example.com", PasswordText, CancellationToken.None);

        Assert.Null(result.Scope?.ReachableTenantIds);
    }

    /// <summary>
    /// A present-but-empty list is normalised to <c>null</c> for the same reason: whichever way
    /// the server spells "not narrowed", the caller must not read it as "reaches nothing".
    /// </summary>
    [Fact]
    public void AnEmptyReachIsNormalisedToNull()
    {
        var scope = new PrincipalScope(
            ActingTenantId: Guid.Parse(ActingTenant),
            ReachableTenantIds: Array.Empty<Guid>());

        Assert.Null(scope.ReachableTenantIds);
    }

    // -----------------------------------------------------------------
    // §5.2.2 rule 2 — which tenant a registration record is sealed against
    // -----------------------------------------------------------------

    /// <summary>
    /// The correctness fix itself. <c>OpaqueEnrollmentForSelfAsync</c> seals against the tenant
    /// the account lives in, and drops the slug naming the acting tenant — a slug left beside
    /// the id would out-vote it server-side, which is the exact confusion the override exists
    /// to avoid.
    /// </summary>
    [Fact]
    public async Task EnrollmentForSelfSealsAgainstThePrincipalTenant()
    {
        string? registerBody = null;
        using var handler = new RoutingHandler();
        handler.Map(LoginPath, _ => LoginSuccess(
            "{\"tenant_id\":\"" + ActingTenant + "\","
            + "\"principal_tenant_id\":\"" + PrincipalTenant + "\","
            + "\"organization_level\":true}"));
        handler.Map(RegisterStartPath, req =>
        {
            registerBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            return RegisterStart();
        });
        using AxiamClient client = SlugClient(handler);
        await client.LoginAsync("alice@example.com", PasswordText, CancellationToken.None);

        // Fully qualified: Axiam.Sdk.Management.Models has an OpaqueEnrollment of its own
        // (the §27 request-body shape), and both namespaces are in scope here.
        Axiam.Sdk.Opaque.OpaqueEnrollment enrollment =
            await client.OpaqueEnrollmentForSelfAsync(Password, CancellationToken.None);

        Assert.NotNull(registerBody);
        JsonElement body = JsonDocument.Parse(registerBody!).RootElement;
        Assert.Equal(PrincipalTenant, body.GetProperty("tenant_id").GetString());
        // A slug naming the acting tenant would out-vote the principal tenant id.
        Assert.False(body.TryGetProperty("tenant_slug", out _));
        Assert.Equal("reg-handle", enrollment.OpaqueSession);
    }

    /// <summary>
    /// The other call site, unchanged: creating a record for <i>another</i> account seals it
    /// against the tenant being acted on, which is what the client is already pointed at.
    /// </summary>
    [Fact]
    public async Task PlainEnrollmentStillSealsAgainstTheActingTenant()
    {
        string? registerBody = null;
        using var handler = new RoutingHandler();
        handler.Map(LoginPath, _ => LoginSuccess(
            "{\"tenant_id\":\"" + ActingTenant + "\","
            + "\"principal_tenant_id\":\"" + PrincipalTenant + "\","
            + "\"organization_level\":true}"));
        handler.Map(RegisterStartPath, req =>
        {
            registerBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            return RegisterStart();
        });
        using AxiamClient client = SlugClient(handler);
        await client.LoginAsync("alice@example.com", PasswordText, CancellationToken.None);

        await client.OpaqueEnrollmentAsync(Password, CancellationToken.None);

        Assert.NotNull(registerBody);
        JsonElement body = JsonDocument.Parse(registerBody!).RootElement;
        Assert.Equal(ActingTenantSlug, body.GetProperty("tenant_slug").GetString());
        Assert.False(body.TryGetProperty("tenant_id", out _));
    }

    /// <summary>
    /// Before a login there is no principal tenant to seal against, and falling back to the
    /// acting one is exactly the bug this method exists to prevent.
    /// </summary>
    [Fact]
    public async Task EnrollmentForSelfRefusesBeforeALogin()
    {
        using var handler = new RoutingHandler();
        using AxiamClient client = Client(handler);

        NetworkError error = await Assert.ThrowsAsync<NetworkError>(
            () => client.OpaqueEnrollmentForSelfAsync(Password, CancellationToken.None));

        Assert.Contains("principal tenant", error.Message, StringComparison.Ordinal);
        // The request that must NOT happen: no route is mapped, so a request would 404 —
        // but an empty request list proves it was never attempted at all.
        Assert.Empty(handler.Requests);
    }

    // -----------------------------------------------------------------
    // §5.2.3 rules 1 and 2 — tenant_scope on an assignment
    // -----------------------------------------------------------------

    /// <summary>
    /// Rule 1. <c>[]</c> is refused with <c>400</c>, and an empty list is what building the
    /// field from a filtered collection produces for "no tenants named", so both spellings of
    /// absent must travel the same way: by not appearing.
    /// </summary>
    [Fact]
    public void AnEmptyTenantScopeNeverReachesTheWire()
    {
        Guid userId = Guid.Parse("77777777-7777-4777-8777-777777777777");

        string omitted = JsonSerializer.Serialize(
            new AssignRoleToUserRequest { UserId = userId }, ManagementJson.Wire);
        string empty = JsonSerializer.Serialize(
            new AssignRoleToUserRequest { UserId = userId, TenantScope = Array.Empty<Guid>() },
            ManagementJson.Wire);

        Assert.DoesNotContain("tenant_scope", omitted, StringComparison.Ordinal);
        Assert.DoesNotContain("tenant_scope", empty, StringComparison.Ordinal);
    }

    /// <summary>
    /// Rule 2. Dropping a scope the caller <i>did</i> name would turn a refusal they need to
    /// see into a success that silently applied no restriction.
    /// </summary>
    [Fact]
    public void ANamedTenantScopeIsSent()
    {
        Guid scoped = Guid.Parse("88888888-8888-4888-8888-888888888888");
        Guid id = Guid.Parse("99999999-9999-4999-8999-999999999999");
        IReadOnlyList<Guid> scope = new[] { scoped };

        foreach (string body in new[]
        {
            JsonSerializer.Serialize(
                new AssignRoleToUserRequest { UserId = id, TenantScope = scope },
                ManagementJson.Wire),
            JsonSerializer.Serialize(
                new AssignRoleToGroupRequest { GroupId = id, TenantScope = scope },
                ManagementJson.Wire),
            JsonSerializer.Serialize(
                new AssignRoleToServiceAccountRequest { ServiceAccountId = id, TenantScope = scope },
                ManagementJson.Wire),
        })
        {
            JsonElement parsed = JsonDocument.Parse(body).RootElement;
            JsonElement sent = parsed.GetProperty("tenant_scope");
            Assert.Equal(1, sent.GetArrayLength());
            Assert.Equal(scoped, Guid.Parse(sent[0].GetString()!));
        }
    }

    /// <summary>
    /// The normalisation is one field wide on purpose: elsewhere an empty list is meaningful —
    /// a replacement body clearing a list — and dropping it would make "remove every entry"
    /// inexpressible.
    /// </summary>
    [Fact]
    public void OtherEmptyListsAreStillSent()
    {
        string body = JsonSerializer.Serialize(
            new UpdateWebhookRequest { Events = Array.Empty<string>() }, ManagementJson.Wire);

        Assert.Contains("\"events\":[]", body, StringComparison.Ordinal);
    }
}
