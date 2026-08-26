namespace Axiam.Sdk.Core;

/// <summary>
/// Authorization failure: the caller lacks permission for the requested operation
/// (CONTRACT.md &#167;2, D-12). Always constructed via <see cref="ErrorMapper"/> so REST
/// and gRPC transports cannot drift on the error taxonomy.
/// </summary>
/// <remarks>
/// Unsealed so CONTRACT.md &#167;27.4 rule 7 can classify a 404 as
/// <see cref="Management.NotFoundError"/> and a 409 as
/// <see cref="Management.ConflictError"/> <em>inside</em> this type rather than beside
/// it. <c>catch (AuthzError)</c> written before &#167;27 existed still catches both,
/// which is exactly the property the rule asks for. The &#167;2 taxonomy is still three
/// top-level types; these are sub-types of one of them, not a fourth peer.
/// </remarks>
public class AuthzError : Exception
{
    /// <summary>
    /// The denied action (e.g. <c>"users:get"</c>), when known. Populated from the
    /// server's structured 403 body's <c>action</c> field (CONTRACT.md &#167;2: AuthzError
    /// SHOULD carry the denied action/resource_id if available). Null when the transport
    /// has no body to parse (gRPC <c>PERMISSION_DENIED</c>) or the field was absent.
    /// </summary>
    public string? Action { get; }

    /// <summary>
    /// The resource UUID the denial was scoped to. Populated from the server's
    /// structured 403 body's <c>resource_id</c> field — present only for a
    /// resource-scoped denial. Null for a non-resource-scoped denial or when the
    /// transport has no body to parse (gRPC <c>PERMISSION_DENIED</c>).
    /// </summary>
    public string? ResourceId { get; }

    /// <summary>
    /// Constructs a message-only <see cref="AuthzError"/> — <see cref="Action"/> and
    /// <see cref="ResourceId"/> are left null. Used when no structured 403 body was
    /// available to parse (e.g. gRPC <c>PERMISSION_DENIED</c>, which carries no body).
    /// </summary>
    /// <param name="message">Describes the authorization failure (CONTRACT.md &#167;2 MUST).</param>
    public AuthzError(string message) : base(message)
    {
    }

    /// <summary>
    /// Constructs an <see cref="AuthzError"/> carrying the structured <c>action</c>/
    /// <c>resource_id</c> fields parsed from the server's 403 <c>authorization_denied</c>
    /// body by <see cref="ErrorMapper"/>. Either may be null — <c>action</c> when not
    /// known, <c>resourceId</c> when the denial was not resource-scoped.
    /// </summary>
    public AuthzError(string message, string? action, string? resourceId) : base(message)
    {
        Action = action;
        ResourceId = resourceId;
    }
}
