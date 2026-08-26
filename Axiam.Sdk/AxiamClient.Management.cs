using System.Text.Json;
using Axiam.Sdk.Management;

namespace Axiam.Sdk;

/// <content>
/// The CONTRACT.md &#167;27 management API surface.
/// </content>
public sealed partial class AxiamClient
{
    private ManagementApi? _management;

    /// <summary>
    /// The CONTRACT.md &#167;27 management API, acting as this client's session.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A view over the client, not a connection: reaching for it performs no I/O
    /// (&#167;27.2 rule 1), so there is nothing to cache and nothing to close.
    /// Everything it issues goes through this client's own request path, so &#167;3 CSRF,
    /// the &#167;4 cookie jar, the &#167;5 tenant header, &#167;6 TLS, &#167;16 retry and
    /// &#167;19 telemetry all apply unchanged.
    /// </para>
    /// <para>
    /// The instance is memoized because it holds no per-call state — the per-call state
    /// is the <c>NamespaceScope</c> each handle carries, and a handle is a fresh object
    /// every time.
    /// </para>
    /// </remarks>
    public ManagementApi Management => _management ??= new ManagementApi(
        new ManagementTransport(
            _httpClient,
            _options,
            _telemetry,
            () => CurrentAccessToken,
            () => ResolvedOrgId,
            () => ResolvedTenantId,
            EnsureNotDisposed,
            Random.Shared.NextDouble));

    // ---- CONTRACT.md §27.2/§27.3: the namespace handles, on the client ----
    //
    // `client.ServiceAccounts.RotateSecretAsync(id)` -- the form §27.3's C# row
    // shows. `Management` above reaches the same handles behind one accessor, which
    // §27.2 rule 4 makes the ADDITIONAL one ("SHOULD additionally be reachable
    // behind one accessor"); shipping only that had the two the wrong way round,
    // with the optional form present and the one the naming map specifies absent.
    //
    // Each forwards to Management, so rule 4's "where an SDK offers both, the two
    // MUST return equivalent handles" holds structurally rather than by two code
    // paths agreeing to stay in step.

    /// <summary>
    /// The organizations operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Organizations</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public OrganizationsApi Organizations => Management.Organizations;

    /// <summary>
    /// The tenants operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Tenants</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public TenantsApi Tenants => Management.Tenants;

    /// <summary>
    /// The users operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Users</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public UsersApi Users => Management.Users;

    /// <summary>
    /// The groups operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Groups</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public GroupsApi Groups => Management.Groups;

    /// <summary>
    /// The roles operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Roles</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public RolesApi Roles => Management.Roles;

    /// <summary>
    /// The permissions operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Permissions</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public PermissionsApi Permissions => Management.Permissions;

    /// <summary>
    /// The resources operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Resources</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public ResourcesApi Resources => Management.Resources;

    /// <summary>
    /// The scopes operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Scopes</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public ScopesApi Scopes => Management.Scopes;

    /// <summary>
    /// The service_accounts operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.ServiceAccounts</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public ServiceAccountsApi ServiceAccounts => Management.ServiceAccounts;

    /// <summary>
    /// The certificates operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Certificates</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public CertificatesApi Certificates => Management.Certificates;

    /// <summary>
    /// The ca_certificates operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.CaCertificates</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public CaCertificatesApi CaCertificates => Management.CaCertificates;

    /// <summary>
    /// The pgp_keys operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.PgpKeys</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public PgpKeysApi PgpKeys => Management.PgpKeys;

    /// <summary>
    /// The webhooks operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Webhooks</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public WebhooksApi Webhooks => Management.Webhooks;

    /// <summary>
    /// The oauth2_clients operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Oauth2Clients</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public Oauth2ClientsApi Oauth2Clients => Management.Oauth2Clients;

    /// <summary>
    /// The federation operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Federation</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public FederationApi Federation => Management.Federation;

    /// <summary>
    /// The notification_rules operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.NotificationRules</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public NotificationRulesApi NotificationRules => Management.NotificationRules;

    /// <summary>
    /// The email_config operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.EmailConfig</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public EmailConfigApi EmailConfig => Management.EmailConfig;

    /// <summary>
    /// The settings operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Settings</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public SettingsApi Settings => Management.Settings;

    /// <summary>
    /// The scim_tokens operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.ScimTokens</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public ScimTokensApi ScimTokens => Management.ScimTokens;

    /// <summary>
    /// The reactors operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Reactors</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public ReactorsApi Reactors => Management.Reactors;

    /// <summary>
    /// The webauthn_policy operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.WebauthnPolicy</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public WebauthnPolicyApi WebauthnPolicy => Management.WebauthnPolicy;

    /// <summary>
    /// The audit operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Audit</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public AuditApi Audit => Management.Audit;

    /// <summary>
    /// The privacy operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Privacy</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public PrivacyApi Privacy => Management.Privacy;

    /// <summary>
    /// The platform operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Acquiring the handle performs no I/O (&#167;27.2 rule 1). The same handle
    /// as <c>Management.Platform</c> (&#167;27.2 rule 4).
    /// </para>
    /// </remarks>
    public PlatformApi Platform => Management.Platform;

    /// <summary>
    /// The organization UUID this client can address, if one has resolved.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The value CONTRACT.md &#167;27.4 rule 3 interpolates into every <c>{org_id}</c>
    /// path: the <c>OrgId</c> the client was constructed with, else the <c>org_id</c>
    /// claim of the live access token. <c>null</c> until one of those exists — notably,
    /// before <c>LoginAsync</c> on a client built with an organization <em>slug</em>,
    /// since resolving a slug would cost a wire call the caller did not ask for.
    /// </para>
    /// <para>
    /// Public because &#167;27 has routes where <c>{org_id}</c> names the organization
    /// being administered rather than the calling context, and those take it as an
    /// ordinary argument. Without this, a caller would have no way to pass the same
    /// organization the implicit routes are using.
    /// </para>
    /// </remarks>
    public Guid? ResolvedOrgId
    {
        get
        {
            if (_tenant.OrgId is { } configured)
            {
                return configured;
            }

            return ClaimGuid("org_id");
        }
    }

    /// <summary>
    /// The tenant UUID this client can address, if one has resolved.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Read from the live access token's <c>tenant_id</c> claim, so it is <c>null</c>
    /// until <c>LoginAsync</c> (or an OAuth2 flow) has established a session. Distinct
    /// from the tenant identifier the client was constructed with, which is a slug as
    /// often as a UUID (CONTRACT.md &#167;5).
    /// </para>
    /// <para>
    /// Public for the same reason as <see cref="ResolvedOrgId"/>: on <c>Tenants</c> and
    /// on the signing CAs under <c>CaCertificates</c>, <c>{tenant_id}</c> names the
    /// tenant being administered and is an argument rather than an implicit.
    /// </para>
    /// </remarks>
    public Guid? ResolvedTenantId => ClaimGuid("tenant_id");

    /// <summary>
    /// Reads one UUID claim out of the live access token, or <c>null</c>.
    /// </summary>
    /// <remarks>
    /// An unparseable claim reads as no claim: a malformed UUID cannot go into a path,
    /// and pretending otherwise turns a local refusal into a server-side 404 the caller
    /// has to interpret.
    /// </remarks>
    private Guid? ClaimGuid(string name)
    {
        if (CurrentAccessToken is not { } token)
        {
            return null;
        }

        JsonElement? claims = DecodeUnverifiedClaims(token);
        if (claims is not { } element ||
            !element.TryGetProperty(name, out JsonElement value) ||
            value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return Guid.TryParse(value.GetString(), out Guid parsed) ? parsed : null;
    }
}
