using System.Text.Json.Serialization;

namespace Axiam.Sdk.Mcp;

/// <summary>
/// The RFC 9728 &#167;2 protected-resource metadata document (CONTRACT.md &#167;28.2),
/// carrying <b>at most</b> the five members below, in this order, and no others.
/// </summary>
/// <remarks>
/// Member names are the wire names — this type serializes to the document byte for byte.
/// RFC 9728 defines further members; &#167;28.2 forbids emitting them in this contract
/// version, because a member one SDK emits and ten do not is a divergence the cross-SDK
/// review would have to reconcile.
/// <para>
/// <see cref="ScopesSupported"/> and <see cref="ResourceDocumentation"/> are
/// <b>omitted</b>, never emitted empty or <c>null</c>, when the caller supplied none.
/// </para>
/// </remarks>
public sealed record ProtectedResourceMetadataDocument
{
    /// <summary>The resource identifier this server publishes about itself — the string
    /// an RFC 8707 <c>resource</c> parameter carries and the <c>aud</c> the guard checks.</summary>
    [JsonPropertyName("resource")]
    public required string Resource { get; init; }

    /// <summary>The issuer identifiers of the authorization servers that guard this
    /// resource. At least one, each verbatim.</summary>
    [JsonPropertyName("authorization_servers")]
    public required IReadOnlyList<string> AuthorizationServers { get; init; }

    /// <summary>The scope tokens this resource server understands, in the caller's
    /// order. Omitted from the serialized document when the caller passed none.</summary>
    [JsonPropertyName("scopes_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? ScopesSupported { get; init; }

    /// <summary>Always exactly <c>["header"]</c> in this contract version &#8212;
    /// &#167;10's guard reads a bearer credential from the <c>Authorization</c> header
    /// alone.</summary>
    [JsonPropertyName("bearer_methods_supported")]
    public required IReadOnlyList<string> BearerMethodsSupported { get; init; }

    /// <summary>A human-readable documentation page. Omitted from the serialized
    /// document when the caller passed none; never emitted as <c>null</c>.</summary>
    [JsonPropertyName("resource_documentation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ResourceDocumentation { get; init; }
}

/// <summary>
/// Arguments to <see cref="AxiamMcp.ProtectedResourceMetadata"/> (CONTRACT.md
/// &#167;28.1), in the contract's canonical order.
/// </summary>
public sealed class ProtectedResourceMetadataOptions
{
    /// <summary>The resource identifier. Absolute, <c>https</c> (or <c>http</c> on a
    /// loopback host), with no query and no fragment. A trailing slash is significant.</summary>
    public required string Resource { get; init; }

    /// <summary>The issuer identifiers of the authorization servers guarding it &#8212;
    /// at least one, no duplicates, no query, no fragment.</summary>
    public required IReadOnlyList<string> AuthorizationServers { get; init; }

    /// <summary>The scope tokens this resource server understands. Order is preserved,
    /// duplicates are refused, and an empty list omits the document member.</summary>
    public required IReadOnlyList<string> ScopesSupported { get; init; }

    /// <summary>Defaults to <c>["header"]</c>, the only accepted value in this contract
    /// version.</summary>
    public IReadOnlyList<string> BearerMethodsSupported { get; init; } = AxiamMcp.DefaultBearerMethodsSupported;

    /// <summary>Optional documentation page for a human. May carry a query and a
    /// fragment; omitted from the document when absent.</summary>
    public string? ResourceDocumentation { get; init; }
}

/// <summary>
/// What <see cref="AxiamMcp.ProtectedResourceMetadata"/> returns: the document, the path
/// it is served at, and the URL that path resolves to (CONTRACT.md &#167;28.1).
/// </summary>
/// <remarks>
/// <see cref="MetadataUrl"/> exists so an integrator feeds the ASP.NET Core guard's
/// <c>ResourceMetadataUrl</c> option (&#167;28.5) from the value this operation derived
/// rather than by retyping the string &#8212; retyping is how the two come to disagree,
/// and a challenge pointing at a document that is not this resource server's is worse
/// than no challenge at all.
/// </remarks>
public sealed record ProtectedResourceMetadata
{
    /// <summary>The RFC 9728 &#167;2 document, ready to serialize.</summary>
    public required ProtectedResourceMetadataDocument Document { get; init; }

    /// <summary>The absolute path the document is served at, derived from the resource
    /// per &#167;28.3 &#8212; never chosen.</summary>
    public required string MetadataPath { get; init; }

    /// <summary><see cref="MetadataPath"/> resolved against the resource's scheme and
    /// authority. Feed this to the ASP.NET Core guard's <c>ResourceMetadataUrl</c>.</summary>
    public required string MetadataUrl { get; init; }
}
