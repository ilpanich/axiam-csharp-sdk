using System.Text.Json.Serialization;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Auth.Oidc;

// Public types for the OIDC / SSO relying-party helpers (CONTRACT.md §12).
//
// Casing split, deliberate (§12 T1 reference judgment call 3):
//   - Types that ARE a protocol document keep wire snake_case: OidcConfiguration (the
//     OIDC Discovery 1.0 metadata document).
//   - Types that are an SDK-shaped RESULT use ordinary C# PascalCase properties:
//     AuthorizationRequest, OidcTokenSet, IntrospectionResult, SsoStartResult,
//     SsoCompleteResult. These carry Sensitive<T>-wrapped fields and derived data the
//     wire body does not have.
//
// The five §12.5 secret fields — access_token, refresh_token, id_token, client_secret,
// code_verifier — are Sensitive<string> wherever they appear below. state and nonce are
// NOT secrets (§12.3 rule 2) and are plain strings.

/// <summary>
/// The OIDC Discovery 1.0 metadata document served by
/// <c>GET /.well-known/openid-configuration</c> (wire schema <c>OidcDiscoveryDocument</c>,
/// CONTRACT.md &#167;12.1). Every field is required by the server's schema, so this record
/// keeps the wire's exact snake_case property names — it IS a protocol document, not an
/// SDK-shaped result.
/// </summary>
/// <remarks>
/// <see cref="Issuer"/> is the AUTHORITATIVE issuer for ID-token validation (&#167;12.4
/// rule 3). It may legitimately differ from the client's base URL when AXIAM runs behind a
/// proxy, so this SDK never rejects a document on an issuer/base-URL mismatch (&#167;12.3
/// rule 6). Likewise <see cref="JwksUri"/> is read from here rather than hardcoded.
/// </remarks>
public sealed record OidcConfiguration(
    [property: JsonPropertyName("issuer")] string Issuer,
    [property: JsonPropertyName("authorization_endpoint")] string AuthorizationEndpoint,
    [property: JsonPropertyName("token_endpoint")] string TokenEndpoint,
    [property: JsonPropertyName("userinfo_endpoint")] string UserinfoEndpoint,
    [property: JsonPropertyName("jwks_uri")] string JwksUri,
    [property: JsonPropertyName("revocation_endpoint")] string RevocationEndpoint,
    [property: JsonPropertyName("introspection_endpoint")] string IntrospectionEndpoint,
    [property: JsonPropertyName("response_types_supported")] IReadOnlyList<string> ResponseTypesSupported,
    [property: JsonPropertyName("subject_types_supported")] IReadOnlyList<string> SubjectTypesSupported,
    [property: JsonPropertyName("id_token_signing_alg_values_supported")] IReadOnlyList<string> IdTokenSigningAlgValuesSupported,
    [property: JsonPropertyName("scopes_supported")] IReadOnlyList<string> ScopesSupported,
    [property: JsonPropertyName("token_endpoint_auth_methods_supported")] IReadOnlyList<string> TokenEndpointAuthMethodsSupported,
    [property: JsonPropertyName("claims_supported")] IReadOnlyList<string> ClaimsSupported,
    [property: JsonPropertyName("grant_types_supported")] IReadOnlyList<string> GrantTypesSupported);

/// <summary>
/// The result of <see cref="AxiamClient.OidcBegin"/> — everything the caller needs to start
/// an authorization-code + PKCE login (CONTRACT.md &#167;12.1).
/// </summary>
/// <remarks>
/// The caller owns this state (&#167;12.3 rule 1) — the SDK stores nothing. Persist
/// <see cref="State"/>, <see cref="Nonce"/> and <see cref="CodeVerifier"/> in your own HTTP
/// session (or via <see cref="IOidcStateStore"/>), redirect the browser to <see cref="Url"/>,
/// and pass <see cref="Nonce"/> and <see cref="CodeVerifier"/> back into
/// <see cref="AxiamClient.OidcExchangeAsync"/> when the authorization code arrives.
/// </remarks>
public sealed record AuthorizationRequest(
    string Url,
    string State,
    string Nonce,
    Sensitive<string> CodeVerifier);

/// <summary>
/// Arguments to <see cref="AxiamClient.OidcBegin"/> — a pure local computation, no network
/// I/O. <c>client_id</c> comes from the client's own configuration
/// (<see cref="Options.AxiamClientOptions.OidcClientId"/>), not a per-call argument (&#167;12
/// T1 reference judgment call 21).
/// </summary>
public sealed class OidcBeginParams
{
    /// <summary>The relying party's redirect URI, echoed back into
    /// <see cref="AxiamClient.OidcExchangeAsync"/> unchanged.</summary>
    public required string RedirectUri { get; init; }

    /// <summary>
    /// The requested scope, space-separated. <c>"openid"</c> is added automatically when
    /// absent (&#167;12.1 rule 4); <c>null</c>/empty requests exactly <c>"openid"</c>.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// Additional caller-supplied authorization-request query parameters (e.g.
    /// <c>prompt</c>, <c>login_hint</c>, <c>ui_locales</c>). &#167;12.1 rule 5 allows
    /// caller-supplied additions but forbids the SDK from adding any of its own beyond the
    /// mandated eight: attempting to override one of those eight is a PROGRAMMING ERROR,
    /// thrown as <see cref="ArgumentException"/> — deliberately NOT the
    /// AuthError/AuthzError/NetworkError taxonomy (&#167;12 port addendum item 9).
    /// </summary>
    public IReadOnlyDictionary<string, string>? ExtraParams { get; init; }
}

/// <summary>
/// A token set returned by the OAuth2 token endpoint (wire schema <c>TokenResponse</c>),
/// returned by <see cref="AxiamClient.OidcExchangeAsync"/>,
/// <see cref="AxiamClient.OidcRefreshAsync"/> and
/// <see cref="AxiamClient.LoginClientCredentialsAsync"/>.
/// </summary>
/// <remarks>
/// <see cref="AccessToken"/>, <see cref="RefreshToken"/> and <see cref="IdToken"/> are
/// <see cref="Sensitive{T}"/> (&#167;12.5): <c>ToString()</c>/JSON serialization redact them
/// to <c>"[SENSITIVE]"</c>; the raw value is reachable only through
/// <see cref="Sensitive{T}.Expose"/> (the documented &#167;7-vs-&#167;12 accessor — see its
/// doc comment). <see cref="IdClaims"/> is non-null exactly when <see cref="IdToken"/> is
/// non-null, and holds the ALREADY-VALIDATED claim set (&#167;12.4) — validation happens
/// before this record is ever constructed, so an <see cref="OidcTokenSet"/> in your hands is
/// never partially trusted (&#167;12.4 rule 7).
/// </remarks>
public sealed record OidcTokenSet(
    Sensitive<string> AccessToken,
    string TokenType,
    long ExpiresIn,
    string? Scope,
    Sensitive<string>? RefreshToken,
    Sensitive<string>? IdToken,
    IdTokenClaims? IdClaims);

/// <summary>Arguments to <see cref="AxiamClient.OidcExchangeAsync"/> (<c>grant_type=authorization_code</c>).</summary>
public sealed class OidcExchangeParams
{
    /// <summary>The authorization code the IdP redirected back with.</summary>
    public required string Code { get; init; }

    /// <summary>The verifier from the matching <see cref="AuthorizationRequest"/>.</summary>
    public required Sensitive<string> CodeVerifier { get; init; }

    /// <summary>The same <c>redirect_uri</c> that was sent on the authorization request.</summary>
    public required string RedirectUri { get; init; }

    /// <summary>
    /// The nonce from the matching <see cref="AuthorizationRequest"/>. MANDATORY — &#167;12.4
    /// rule 6 is not optional for this grant.
    /// </summary>
    public required string Nonce { get; init; }

    /// <summary>
    /// The tenant UUID for the token endpoint's required <c>tenant_id</c> query parameter.
    /// When <c>null</c>, resolved from the client's own configuration or a prior successful
    /// login (CONTRACT.md &#167;12.3 rule 4).
    /// </summary>
    public Guid? TenantId { get; init; }

    /// <summary>A pre-fetched discovery document, to avoid re-reading the (cached) one.
    /// Fetched via <see cref="AxiamClient.OidcDiscoverAsync"/> when <c>null</c>.</summary>
    public OidcConfiguration? Configuration { get; init; }
}

/// <summary>Arguments to <see cref="AxiamClient.OidcRefreshAsync"/> (<c>grant_type=refresh_token</c>).</summary>
public sealed class OidcRefreshParams
{
    /// <summary>The refresh token to redeem.</summary>
    public required Sensitive<string> RefreshToken { get; init; }

    /// <summary>An optional narrowed scope to request. Omitted from the form body when
    /// <c>null</c>/empty.</summary>
    public string? Scope { get; init; }

    /// <summary>The tenant UUID for the <c>tenant_id</c> query parameter (&#167;12.3 rule 4).</summary>
    public Guid? TenantId { get; init; }

    /// <summary>A pre-fetched discovery document. Fetched via
    /// <see cref="AxiamClient.OidcDiscoverAsync"/> when <c>null</c>.</summary>
    public OidcConfiguration? Configuration { get; init; }
}

/// <summary>Arguments to <see cref="AxiamClient.LoginClientCredentialsAsync"/> (<c>grant_type=client_credentials</c>).</summary>
public sealed class LoginClientCredentialsParams
{
    /// <summary>An optional scope to request. This grant requests no <c>"openid"</c> scope
    /// and the response carries no <c>id_token</c> (&#167;12.1).</summary>
    public string? Scope { get; init; }

    /// <summary>The tenant UUID for the <c>tenant_id</c> query parameter (&#167;12.3 rule 4).</summary>
    public Guid? TenantId { get; init; }

    /// <summary>A pre-fetched discovery document. Fetched via
    /// <see cref="AxiamClient.OidcDiscoverAsync"/> when <c>null</c>.</summary>
    public OidcConfiguration? Configuration { get; init; }

    /// <summary>
    /// Requests adopting the returned <c>access_token</c> as this client's bearer credential
    /// (CONTRACT.md &#167;12.1, a MAY). NOT IMPLEMENTED by this port (&#167;12 port addendum
    /// item 13 explicitly permits skipping it) — setting this to <c>true</c> throws
    /// <see cref="NotSupportedException"/>; see the CHANGELOG for the deviation note.
    /// </summary>
    public bool AdoptAsCredential { get; init; }
}

/// <summary>Arguments to <see cref="AxiamClient.IntrospectAsync"/> (RFC 7662). Requires
/// confidential-client credentials (&#167;12.1 note 4).</summary>
public sealed class IntrospectParams
{
    /// <summary>The token to introspect.</summary>
    public required Sensitive<string> Token { get; init; }

    /// <summary>An optional RFC 7662 <c>token_type_hint</c> (<c>access_token</c> /
    /// <c>refresh_token</c>).</summary>
    public string? TokenTypeHint { get; init; }

    /// <summary>The tenant UUID for the <c>tenant_id</c> query parameter (&#167;12.3 rule 4).</summary>
    public Guid? TenantId { get; init; }

    /// <summary>A pre-fetched discovery document. Fetched via
    /// <see cref="AxiamClient.OidcDiscoverAsync"/> when <c>null</c>.</summary>
    public OidcConfiguration? Configuration { get; init; }
}

/// <summary>Arguments to <see cref="AxiamClient.RevokeAsync"/> (RFC 7009). Requires
/// confidential-client credentials (&#167;12.1 note 4).</summary>
public sealed class RevokeParams
{
    /// <summary>The token to revoke.</summary>
    public required Sensitive<string> Token { get; init; }

    /// <summary>An optional RFC 7009 <c>token_type_hint</c>.</summary>
    public string? TokenTypeHint { get; init; }

    /// <summary>The tenant UUID for the <c>tenant_id</c> query parameter (&#167;12.3 rule 4).</summary>
    public Guid? TenantId { get; init; }

    /// <summary>A pre-fetched discovery document. Fetched via
    /// <see cref="AxiamClient.OidcDiscoverAsync"/> when <c>null</c>.</summary>
    public OidcConfiguration? Configuration { get; init; }
}

/// <summary>
/// The RFC 7662 introspection result (wire schema <c>IntrospectionResponse</c>). Only
/// <see cref="Active"/> is guaranteed; the server omits the metadata fields for an inactive
/// token (all <c>null</c>).
/// </summary>
public sealed record IntrospectionResult(
    bool Active,
    string? Sub,
    string? ClientId,
    string? Scope,
    string? TokenType,
    long? Exp,
    long? Iat);

/// <summary>
/// Arguments to <see cref="AxiamClient.SsoStartAsync"/>
/// (<c>POST /api/v1/auth/federation/oidc/start</c>). One tenant form
/// (<see cref="TenantId"/> or <see cref="TenantSlug"/>) and one org form
/// (<see cref="OrgId"/> or <see cref="OrgSlug"/>) must be resolvable, from these properties
/// or from the client's own construction options (CONTRACT.md &#167;5.1).
/// </summary>
public sealed class SsoStartParams
{
    /// <summary>The UUID of the server-side federation configuration identifying the
    /// upstream IdP.</summary>
    public required string FederationConfigId { get; init; }

    /// <summary>The post-login destination, stored server-side and echoed back by
    /// <see cref="AxiamClient.SsoCompleteAsync"/>.</summary>
    public required string RedirectUri { get; init; }

    /// <summary>The tenant UUID. Defaults to the client's own tenant when <c>null</c> and
    /// <see cref="TenantSlug"/> is also <c>null</c>.</summary>
    public Guid? TenantId { get; init; }

    /// <summary>The tenant slug. Defaults to the client's own tenant when both this and
    /// <see cref="TenantId"/> are <c>null</c>.</summary>
    public string? TenantSlug { get; init; }

    /// <summary>The organization UUID. Defaults to the client's configured organization
    /// when <c>null</c>.</summary>
    public Guid? OrgId { get; init; }

    /// <summary>The organization slug. Defaults to the client's configured organization
    /// when <c>null</c>.</summary>
    public string? OrgSlug { get; init; }
}

/// <summary>
/// The result of <see cref="AxiamClient.SsoStartAsync"/> (wire schema
/// <c>OidcStartResponse</c>). There is deliberately no nonce: on the federation path the
/// nonce never leaves the server (&#167;12.1 note 7). Round-trip <see cref="State"/> into
/// <see cref="AxiamClient.SsoCompleteAsync"/> unmodified — the server stores it single-use
/// with a 10-minute TTL and recovers the whole login context from it.
/// </summary>
public sealed record SsoStartResult(string AuthorizeUrl, string State, long ExpiresInSecs);

/// <summary>Arguments to <see cref="AxiamClient.SsoCompleteAsync"/>
/// (<c>POST /api/v1/auth/federation/oidc/callback</c>).</summary>
public sealed class SsoCompleteParams
{
    /// <summary>The <c>state</c> value the IdP redirected back with — must be the one
    /// <see cref="AxiamClient.SsoStartAsync"/> returned.</summary>
    public required string State { get; init; }

    /// <summary>The authorization code the IdP redirected back with.</summary>
    public required string Code { get; init; }
}

/// <summary>
/// The result of <see cref="AxiamClient.SsoCompleteAsync"/> (wire schema
/// <c>SsoLoginSuccessResponse</c>). Carries NO token material — the session arrives as
/// <c>Set-Cookie</c>, so the &#167;4 cookie jar (already owned by every
/// <see cref="AxiamClient"/>) is what actually captures it (&#167;12.1 note 6).
/// </summary>
public sealed record SsoCompleteResult(string UserId, string SessionId, long ExpiresIn, string RedirectUri);
