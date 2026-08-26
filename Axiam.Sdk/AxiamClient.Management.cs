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
