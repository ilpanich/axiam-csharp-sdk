namespace Axiam.Sdk.Core;

/// <summary>
/// Immutable tenant-identity value object required at <c>AxiamClient</c> construction
/// time and propagated on every outgoing request (CONTRACT.md &#167;5: <c>X-Tenant-Id</c>
/// header on REST; <c>x-tenant-id</c> gRPC metadata in a later plan). There is no
/// default-constructible/blank instance — the constructor throws a runtime guard
/// backing the compile-time guarantee that <c>AxiamClient</c>'s own tenant-required
/// constructor provides (SC#1): AXIAM is multi-tenant and there is no default tenant.
/// </summary>
public sealed class TenantContext
{
    /// <summary>
    /// The tenant identifier as supplied by the caller — either a human-readable
    /// tenant slug or a tenant UUID rendered as a string (CONTRACT.md &#167;5 accepts
    /// either form). Never blank.
    /// </summary>
    public string TenantId { get; }

    /// <summary>
    /// Optional organization UUID. Mutually exclusive with <see cref="OrgSlug"/> —
    /// the real AXIAM login/refresh endpoints require an organization identifier
    /// beyond &#167;5's documented tenant-only minimum; supply exactly one of
    /// <see cref="OrgId"/>/<see cref="OrgSlug"/> via <c>AxiamClientOptions</c>.
    /// </summary>
    public Guid? OrgId { get; }

    /// <summary>Optional organization slug. Mutually exclusive with <see cref="OrgId"/>.</summary>
    public string? OrgSlug { get; }

    /// <summary>
    /// Constructs a <see cref="TenantContext"/>. Throws <see cref="ArgumentException"/>
    /// when <paramref name="tenantId"/> is null/blank — the runtime guard backing
    /// <c>AxiamClient</c>'s tenant-required constructor (CONTRACT.md &#167;5, SC#1).
    /// </summary>
    /// <param name="tenantId">The tenant slug or tenant UUID (as a string) — required, never blank.</param>
    /// <param name="orgId">Optional organization UUID. Mutually exclusive with <paramref name="orgSlug"/>.</param>
    /// <param name="orgSlug">Optional organization slug. Mutually exclusive with <paramref name="orgId"/>.</param>
    public TenantContext(string tenantId, Guid? orgId = null, string? orgSlug = null)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            throw new ArgumentException(
                "tenantId is required — AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5).",
                nameof(tenantId));
        }

        // §5.2.1 rule 2: an SDK MUST NOT send an empty-string slug. `tenantId`
        // was already covered; `orgSlug` was not, and a blank one reaches the
        // login body the same way. Nothing can carry an empty slug, so the
        // server resolves nothing — and on /auth/opaque/login/start a workspace
        // that does not resolve fails *before* the tenant's OPAQUE mode is
        // read, so the 404 that means "OPAQUE is not offered here" never
        // arrives and this SDK has no fallback to take. `null` stays fine: that
        // is what "not named" looks like, and it is the organization identifier
        // being optional rather than blank.
        if (orgSlug is not null && string.IsNullOrWhiteSpace(orgSlug))
        {
            throw new ArgumentException(
                "orgSlug must not be blank — omit it entirely, or name the organization (CONTRACT.md §5.1, §5.2.1).",
                nameof(orgSlug));
        }

        TenantId = tenantId;
        OrgId = orgId;
        OrgSlug = orgSlug;
    }
}
