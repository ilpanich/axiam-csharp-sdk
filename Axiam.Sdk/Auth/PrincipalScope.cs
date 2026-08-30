#nullable enable

namespace Axiam.Sdk.Auth;

/// <summary>
/// Where the signed-in principal lives, and how far its roles reach —
/// CONTRACT.md &#167;5.2.2 and &#167;5.2.3.
/// </summary>
/// <remarks>
/// <para>
/// Grouped into one type rather than spread across <see cref="LoginResult"/>'s parameters
/// because they are read together and grow together: &#167;5.2.2 added three of these and
/// &#167;5.2.3 a fourth, and a record that gains a parameter per contract revision is one
/// whose shape churns every time.
/// </para>
/// <para>
/// Every property is nullable, and absent has a specific meaning in each case rather than
/// "unknown". A server older than contract 1.34 sends none of them, in which case the whole
/// scope is <c>null</c>.
/// </para>
/// </remarks>
/// <param name="ActingTenantId">
/// The tenant a request <b>acts on</b> — what the <c>X-Axiam-Tenant</c> header names.
/// <c>null</c> when the server does not report it.
/// </param>
/// <param name="PrincipalTenantId">
/// The tenant this principal's record <b>lives in</b>. The same value as
/// <paramref name="ActingTenantId"/> for every ordinary principal; the two diverge only once
/// an organization-level principal selects another tenant to act on. This is where the
/// account's own credentials belong, and what a &#167;23 registration record for <i>this</i>
/// account must be sealed against — see <c>OpaqueEnrollmentForSelfAsync</c>. Falls back to
/// <paramref name="ActingTenantId"/> when the server omits it, which is exactly right there:
/// a server that cannot switch the acting tenant cannot make the two differ.
/// </param>
/// <param name="PrincipalTenantSlug">
/// Slug of <paramref name="PrincipalTenantId"/> — <c>"organization"</c> for an
/// organization-level principal; <c>null</c> when the server omits it.
/// </param>
/// <param name="OrgId">
/// The caller's organization as a UUID (&#167;5.2.2 rule 3). Read this rather than resolving
/// a slug through <c>GET /api/v1/organizations</c>, which is <c>super-admin</c>-only and
/// returns only the caller's own organization.
/// </param>
/// <param name="ReachableTenantIds">
/// The tenants this caller's roles reach, when they are narrowed (&#167;5.2.3). <c>null</c>
/// means <b>unrestricted</b>, which is both the common case and the only thing a server older
/// than contract 1.35 can mean. A present list is a deliberately narrowed organization-level
/// account: confine any tenant switch to it, because naming anything outside is refused at the
/// header. Note the pairing with <see cref="LoginResult.OrganizationLevel"/> — a narrowed
/// account still reports <c>true</c> there, so gating on that flag alone offers tenants the
/// server will refuse.
/// </param>
public sealed record PrincipalScope(
    Guid? ActingTenantId = null,
    Guid? PrincipalTenantId = null,
    string? PrincipalTenantSlug = null,
    Guid? OrgId = null,
    IReadOnlyList<Guid>? ReachableTenantIds = null)
{
    /// <summary>
    /// The tenant this principal's record lives in, with &#167;5.2.2 rule 1's fallback
    /// applied: absent means <i>equal</i> to the acting tenant, not unknown.
    /// </summary>
    public Guid? PrincipalTenantId { get; init; } = PrincipalTenantId ?? ActingTenantId;

    /// <summary>
    /// The tenants this caller reaches, with an empty list normalised to <c>null</c> — an
    /// empty list would read as "reaches nothing", the opposite of what an omitted field
    /// means here.
    /// </summary>
    public IReadOnlyList<Guid>? ReachableTenantIds { get; init; } =
        ReachableTenantIds is { Count: 0 } ? null : ReachableTenantIds;
}
