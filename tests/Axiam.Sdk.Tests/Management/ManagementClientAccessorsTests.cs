using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.Management;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// CONTRACT.md &#167;27.2/&#167;27.3 — the namespace handles sit on the client.
/// </summary>
/// <remarks>
/// <para>
/// &#167;27.3's C# row is <c>client.ServiceAccounts.RotateSecretAsync(id)</c>, and
/// &#167;27.2 rule 4 makes the single <c>Management</c> accessor the <em>additional</em>
/// one. Both forms therefore exist, and rule 4 requires that "where an SDK offers both,
/// the two MUST return equivalent handles".
/// </para>
/// <para>
/// Equivalent means the same <em>request</em>, not merely the same type — a direct
/// accessor that built a handle with a default scope instead of the client's would return
/// the right type and address the wrong organization. So the assertions below compare what
/// each form actually put on the wire.
/// </para>
/// </remarks>
[Trait("Category", "Fast")]
public sealed class ManagementClientAccessorsTests : ManagementTestBase
{
    /// <summary>Every namespace the aggregate exposes is also directly on the client.</summary>
    [Fact]
    public void EveryNamespaceIsReachableBothWays()
    {
        PropertyInfo[] onAggregate = typeof(ManagementApi)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.Name != "Manifest")
            .ToArray();

        Assert.NotEmpty(onAggregate);
        foreach (PropertyInfo property in onAggregate)
        {
            PropertyInfo? onClient = typeof(AxiamClient).GetProperty(property.Name);
            Assert.True(
                onClient is not null,
                $"§27.3 puts `{property.Name}` on the client, not only behind Management");
            Assert.Equal(property.PropertyType, onClient!.PropertyType);
        }

        // 24 namespaces. Pinned so a partial regeneration that dropped one fails here
        // rather than quietly shipping 23.
        Assert.Equal(24, onAggregate.Length);
    }

    /// <summary>Both forms reach the same route with the client's own scope.</summary>
    [Fact]
    public async Task TheTwoFormsIssueTheSameRequest()
    {
        Route route = Mount("GET", "/api/v1/roles", 200, PageOf(null));

        await Client.Roles.ListAsync();
        Assert.Equal(1, route.Calls);
        string directPath = route.Last.Path;
        string directMethod = route.Last.Method;

        await Client.Management.Roles.ListAsync();
        Assert.Equal(2, route.Calls);
        Assert.Equal(directPath, route.Last.Path);
        Assert.Equal(directMethod, route.Last.Method);
    }

    /// <summary>
    /// A direct accessor carries the client's implicit <c>{org_id}</c>, not a bare default.
    /// </summary>
    /// <remarks>
    /// This is the failure the equivalence rule exists to prevent: a forwarding accessor
    /// that constructed its own handle would compile, return the right type, and address
    /// the wrong organization.
    /// </remarks>
    [Fact]
    public async Task ADirectAccessorCarriesTheClientsOwnScope()
    {
        Route route = Mount(
            "GET", $"/api/v1/organizations/{OrgId}/ca-certificates", 200, PageOf(null));

        await Client.CaCertificates.ListAsync();

        Assert.Equal(1, route.Calls);
        Assert.Contains(OrgId.ToString(), route.Last.Path, System.StringComparison.Ordinal);
    }

    /// <summary>Re-scoping a directly-reached handle still returns a new one.</summary>
    [Fact]
    public async Task ADirectAccessorStillRescopes()
    {
        const string other = "44444444-4444-4444-8444-444444444444";
        Route mine = Mount(
            "GET", $"/api/v1/organizations/{OrgId}/ca-certificates", 200, PageOf(null));
        Route theirs = Mount(
            "GET", $"/api/v1/organizations/{other}/ca-certificates", 200, PageOf(null));

        CaCertificatesApi handle = Client.CaCertificates;
        await handle.InOrg(System.Guid.Parse(other)).ListAsync();
        await handle.ListAsync();

        Assert.Equal(1, theirs.Calls);
        Assert.Equal(1, mine.Calls);
    }

    /// <summary>Acquiring a handle either way performs no I/O (&#167;27.2 rule 1).</summary>
    [Fact]
    public void AcquiringAHandlePerformsNoIO()
    {
        _ = Client.Roles;
        _ = Client.ServiceAccounts;
        _ = Client.Management.Certificates;

        Assert.Equal(0, TotalCalls());
    }
}
