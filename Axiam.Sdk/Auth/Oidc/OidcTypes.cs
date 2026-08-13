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
    [property: JsonPropertyName("grant_types_supported")] IReadOnlyList<string> GrantTypesSupported,
    [property: JsonPropertyName("device_authorization_endpoint")] string? DeviceAuthorizationEndpoint = null,
    [property: JsonPropertyName("end_session_endpoint")] string? EndSessionEndpoint = null,
    [property: JsonPropertyName("backchannel_logout_supported")] bool BackchannelLogoutSupported = false,
    [property: JsonPropertyName("backchannel_logout_session_supported")] bool BackchannelLogoutSessionSupported = false);

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


// ---------------------------------------------------------------------------
// §14 Device Authorization Grant (RFC 8628)
// ---------------------------------------------------------------------------

/// <summary>Arguments to <see cref="AxiamClient.DeviceAuthorizeAsync"/> (CONTRACT.md &#167;14.1).</summary>
/// <param name="Scope">Space-separated scope to request; omitted when <see langword="null"/>.</param>
/// <param name="TenantId">Tenant UUID for the mandatory <c>tenant_id</c> query parameter.</param>
/// <param name="Configuration">A pre-fetched discovery document, or <see langword="null"/> to fetch one.</param>
public sealed record DeviceAuthorizeParams(
    string? Scope = null,
    Guid? TenantId = null,
    OidcConfiguration? Configuration = null);

/// <summary>
/// The <c>DeviceAuthorizationResponse</c> — what the device shows its user, plus the
/// <c>device_code</c> it polls with (CONTRACT.md &#167;14.1).
/// </summary>
/// <remarks>
/// <see cref="DeviceCode"/> is <see cref="Sensitive{T}"/> (&#167;14.5): a bearer credential for the
/// lifetime of the grant. <see cref="UserCode"/> deliberately is <b>not</b> — it exists to be read
/// aloud and typed by a human, and wrapping it would defeat the one thing it is for. Neither may be
/// logged; displaying the user code is the caller's job.
/// </remarks>
/// <param name="DeviceCode">The device's polling credential (&#167;14.5 secret).</param>
/// <param name="UserCode">The short code the human types into the verification page.</param>
/// <param name="VerificationUri">Where the human goes to enter <paramref name="UserCode"/>.</param>
/// <param name="VerificationUriComplete">
/// The verification URI with the user code already embedded, when the server sent one — prefer it
/// when the device can render a QR code. Never synthesised by concatenation when absent
/// (&#167;14.3): its format is the server's to choose.
/// </param>
/// <param name="ExpiresIn">Seconds until the grant expires. Polling stops here (&#167;14.2 rule 4).</param>
/// <param name="Interval">
/// Seconds between polls, from the response, defaulted to 5 when the server omitted it
/// (&#167;14.2 rule 2).
/// </param>
public sealed record DeviceAuthorization(
    Sensitive<string> DeviceCode,
    string UserCode,
    string VerificationUri,
    string? VerificationUriComplete,
    int ExpiresIn,
    int Interval);

/// <summary>Arguments to <see cref="AxiamClient.DevicePollAsync"/> (CONTRACT.md &#167;14.1).</summary>
/// <param name="DeviceCode">The <c>DeviceCode</c> from <see cref="DeviceAuthorization"/>.</param>
/// <param name="TenantId">Tenant UUID for the <c>tenant_id</c> query parameter.</param>
/// <param name="Configuration">A pre-fetched discovery document, or <see langword="null"/>.</param>
public sealed record DevicePollParams(
    Sensitive<string> DeviceCode,
    Guid? TenantId = null,
    OidcConfiguration? Configuration = null);

/// <summary>Arguments to <see cref="AxiamClient.DeviceLoginAsync"/> (CONTRACT.md &#167;14.3).</summary>
/// <param name="OnUserCode">
/// Invoked with the <see cref="DeviceAuthorization"/> <b>before the first poll</b> (&#167;14.3
/// rule 2), so the caller can display the code. A <see cref="Func{T, TResult}"/> returning a
/// <see cref="Task"/>, so a device that must await a paint or a redraw can — polling does not begin
/// until it completes. The SDK never prints the code.
/// </param>
/// <param name="Scope">Space-separated scope to request.</param>
/// <param name="TenantId">Tenant UUID for the <c>tenant_id</c> query parameter.</param>
/// <param name="Configuration">A pre-fetched discovery document, or <see langword="null"/>.</param>
/// <param name="AdoptAsCredential">
/// Mirrors <see cref="LoginClientCredentialsParams.AdoptAsCredential"/>: this port does not
/// implement adoption and throws <see cref="NotSupportedException"/> when it is set.
/// &#167;14.3 rule 4 (contract 1.7) defers to the &#167;12.1 adoption MAY, so this SDK takes the
/// same posture here rather than inventing a second one.
/// </param>
public sealed record DeviceLoginParams(
    Func<DeviceAuthorization, Task> OnUserCode,
    string? Scope = null,
    Guid? TenantId = null,
    OidcConfiguration? Configuration = null,
    bool AdoptAsCredential = false);

// ---------------------------------------------------------------------------
// §15 Token Exchange (RFC 8693)
// ---------------------------------------------------------------------------

/// <summary>Arguments to <see cref="AxiamClient.TokenExchangeAsync"/> (CONTRACT.md &#167;15.1).</summary>
/// <remarks>
/// A parameter object rather than positional arguments, because four optional strings in positional
/// order is a bug waiting to be written (&#167;15.1).
/// </remarks>
/// <param name="SubjectToken">The token being exchanged (&#167;15.5 secret).</param>
/// <param name="SubjectTokenType">
/// What kind of token <paramref name="SubjectToken"/> is. <b>Required</b> (&#167;15.1), with no
/// default: a default would be this SDK choosing which kind of credential you hold, which is
/// exactly what &#167;15.7 forbids. Pass <see cref="AxiamClient.AccessTokenType"/> for the
/// same-domain exchange, or <see cref="AxiamClient.JwtTokenType"/> for a trusted external
/// issuer's JWT (&#167;15.7). The SDK never reads <paramref name="SubjectToken"/> to decide it:
/// which kind of token you hold is something only you know, AXIAM refuses refresh and ID token
/// types by name, and the SDK will not retry a refusal as a different type.
/// </param>
/// <param name="ActorToken">
/// The acting party, when this is a <b>delegation</b> (&#167;15.2 rule 1). Its absence selects
/// <b>impersonation</b> — a different operation with different risk. The SDK never fills this in.
/// </param>
/// <param name="Scopes">Scopes to request; omitted from the body when <see langword="null"/> or empty.</param>
/// <param name="Audience">The service the issued token is for.</param>
/// <param name="Resource">RFC 8707 synonym of <paramref name="Audience"/>; the server refuses the pair when they disagree.</param>
/// <param name="TenantId">Tenant UUID for the <c>tenant_id</c> query parameter.</param>
/// <param name="Configuration">A pre-fetched discovery document, or <see langword="null"/>.</param>
public sealed record TokenExchangeParams(
    Sensitive<string> SubjectToken,
    string SubjectTokenType,
    Sensitive<string>? ActorToken = null,
    IReadOnlyList<string>? Scopes = null,
    string? Audience = null,
    string? Resource = null,
    Guid? TenantId = null,
    OidcConfiguration? Configuration = null);

/// <summary>
/// The result of an RFC 8693 exchange (wire schema <c>TokenExchangeResponse</c>, &#167;15.1).
/// </summary>
/// <remarks>
/// <b>There is no <c>RefreshToken</c> property, and that is deliberate</b> (&#167;15.2 rule 4).
/// RFC 8693 issues none, so this type cannot represent one: an application that wants a fresh
/// exchanged token re-runs the exchange. This result also never enters the &#167;9 single-flight
/// refresh guard — there is nothing to refresh.
/// </remarks>
/// <param name="AccessToken">The issued token (&#167;15.5 secret).</param>
/// <param name="IssuedTokenType">
/// What the server actually issued. Mandatory in RFC 8693 &#167;2.2.1 and surfaced rather than
/// dropped (&#167;15.2 rule 6), so a client that asked for one type and got another can tell.
/// </param>
/// <param name="TokenType">The token type (<c>Bearer</c>).</param>
/// <param name="ExpiresIn">Lifetime in seconds — never longer than the subject token's remaining life.</param>
/// <param name="Scope">
/// <b>The granted scope, which may be narrower than requested</b> even on success (&#167;15.2
/// rule 7); read it rather than assuming the request was honoured verbatim.
/// </param>
public sealed record ExchangedToken(
    Sensitive<string> AccessToken,
    string IssuedTokenType,
    string TokenType,
    long ExpiresIn,
    string? Scope);

// ---------------------------------------------------------------------------
// §12.7 Logout helpers
// ---------------------------------------------------------------------------

/// <summary>Arguments to <see cref="AxiamClient.LogoutUrlAsync"/> (CONTRACT.md &#167;12.7.2).</summary>
/// <param name="IdToken">
/// A previously-issued ID token, placed in <c>id_token_hint</c> — the only <i>authenticated</i>
/// statement of which session is being ended.
/// </param>
/// <param name="PostLogoutRedirectUri">
/// Where the OP should send the browser afterwards. Honoured only on exact match against the
/// client's registered allow-list — a server-side check the SDK deliberately does not duplicate
/// (&#167;12.7.2 rule 3).
/// </param>
/// <param name="State">
/// An opaque value echoed back on the redirect. Generated and checked by the caller (&#167;12.7.2
/// rule 2), never by the SDK.
/// </param>
/// <param name="Configuration">A pre-fetched discovery document, or <see langword="null"/>.</param>
public sealed record LogoutUrlParams(
    Sensitive<string> IdToken,
    string? PostLogoutRedirectUri = null,
    string? State = null,
    OidcConfiguration? Configuration = null);

/// <summary>What a verified back-channel logout token names (CONTRACT.md &#167;12.7.3).</summary>
/// <remarks>
/// Deliberately <b>not</b> a bare <see cref="bool"/>: the RP has to know <i>which</i> session to
/// end, and a verifier that only says "valid" would force the caller to re-parse the token
/// themselves, with none of the checks this type is proof of.
/// </remarks>
/// <param name="Sid">
/// The session that ended. <b>When non-<see langword="null"/>, end only this session</b> — falling
/// back to "every session for <paramref name="Sub"/>" is over-reach the AXIAM server itself refuses
/// to make.
/// </param>
/// <param name="Sub">The subject whose session ended.</param>
/// <param name="Jti">
/// Replay identifier. <b>The RP dedups on this, not the SDK.</b> Back-channel delivery is
/// at-least-once with retry, so a valid token legitimately arrives twice; the SDK has no durable
/// store and an in-memory guard would silently drop a real second logout after a restart. Surfaced,
/// never consumed.
/// </param>
public sealed record VerifiedLogoutToken(
    string? Sid,
    string? Sub,
    string Jti);

// ---------------------------------------------------------------------------
// §20 UMA 2.0 — Protection API and ticket grant
// ---------------------------------------------------------------------------

/// <summary>
/// A UMA resource set — an AXIAM resource seen through the Protection API
/// (CONTRACT.md &#167;20.1).
/// </summary>
/// <remarks>
/// <para><paramref name="Id"/> is <b>the AXIAM resource id</b>, not a parallel
/// identifier: the same GUID is directly usable as the
/// <see cref="RequestedPermission.ResourceId"/> of a later ticket request, and
/// as the resource id anywhere else in this SDK.</para>
/// </remarks>
/// <param name="Name">Human-readable name, shown in the admin UI.</param>
/// <param name="Id">Assigned by the server on registration; <c>null</c> on the way in.</param>
/// <param name="Type">
/// Free-form resource type. Defaults server-side to <c>uma_resource</c> when
/// <c>null</c>, so a resource server that omits it does not produce a row that
/// sorts oddly next to hand-made ones.
/// </param>
/// <param name="ResourceScopes">
/// The scope names a resource server may ask for on this resource.
/// <b>Replaced wholesale by an update, never merged</b> (&#167;20.2 rule 8) —
/// this SDK does not read the current scopes and fold them into an update
/// payload as a convenience, because that would make removing a scope
/// impossible through it.
/// </param>
public sealed record ResourceSet(
    string Name,
    Guid? Id = null,
    string? Type = null,
    IReadOnlyList<string>? ResourceScopes = null);

/// <summary>One <c>(resource, scopes)</c> pair a resource server requires (&#167;20.1).</summary>
/// <param name="ResourceId">
/// The AXIAM resource id — the same GUID the Protection API returned as <c>_id</c>.
/// </param>
/// <param name="ResourceScopes">
/// Scope names, each of which the resource must already declare. Matched
/// exactly: no prefix or wildcard semantics in either direction.
/// </param>
public sealed record RequestedPermission(Guid ResourceId, IReadOnlyList<string> ResourceScopes);

/// <summary>One entry of an RPT's <c>permissions</c> claim (&#167;20.1).</summary>
/// <remarks>
/// <b>A record of a decision already made, not a live authorization answer</b>
/// (&#167;20.2 rule 7). These are the pairs the engine allowed when the RPT was
/// minted; a grant revoked afterwards does not empty a live RPT. Do not cache
/// them beyond the token's own expiry — which is why that expiry is short.
/// </remarks>
/// <param name="ResourceId">The resource the engine allowed.</param>
/// <param name="ResourceScopes">The scopes it allowed on that resource.</param>
/// <param name="Exp">Absolute expiry, seconds since the epoch.</param>
public sealed record RptPermission(Guid ResourceId, IReadOnlyList<string> ResourceScopes, long Exp);

/// <summary>The result of the UMA ticket grant (&#167;20.1).</summary>
/// <remarks>
/// <b>There is no <c>RefreshToken</c> component, and that is deliberate</b>
/// (&#167;20.2 rule 5). The grant issues none, so an RPT cannot outlive the
/// ticket that authorised it; an application that wants a fresh one re-runs the
/// grant. This result never enters the &#167;9 single-flight refresh guard —
/// there is nothing to refresh.
/// </remarks>
/// <param name="AccessToken">The RPT itself (&#167;20.6 secret).</param>
/// <param name="TokenType">Always <c>Bearer</c>.</param>
/// <param name="ExpiresIn"><c>min(claimToken remaining, server ceiling, 300 s)</c>.</param>
public sealed record RequestingPartyToken(
    Sensitive<string> AccessToken,
    string TokenType,
    long ExpiresIn);

/// <summary>Arguments to <see cref="AxiamClient.UmaExchangeTicketAsync"/> (&#167;20.1).</summary>
/// <param name="Ticket">The permission ticket.</param>
/// <param name="ClaimToken">
/// The requesting party's access token. <b>Required</b>, though UMA 2.0
/// &#167;3.3.1 marks it optional: v1 implements neither incremental
/// authorization nor claims-gathering, so this is the only channel that names a
/// requesting party (&#167;20.2 rule 2).
/// </param>
/// <param name="TenantId">Tenant GUID for the <c>tenant_id</c> query parameter.</param>
/// <param name="Configuration">A pre-fetched discovery document.</param>
public sealed record UmaExchangeTicketParams(
    Sensitive<string> Ticket,
    Sensitive<string> ClaimToken,
    Guid? TenantId = null,
    OidcConfiguration? Configuration = null);

/// <summary>A parsed <c>WWW-Authenticate: UMA</c> challenge (UMA 2.0 &#167;3.2, &#167;20.3).</summary>
/// <param name="Realm">The protection realm the resource server named.</param>
/// <param name="AsUri">
/// The authorization server the resource server nominates. <b>Not automatically
/// trusted</b> — see <see cref="UmaChallenge.Parse"/>.
/// </param>
/// <param name="Ticket">
/// The ticket to exchange — a bearer credential for its 60-second life.
/// </param>
public sealed record UmaChallenge(string? Realm, string? AsUri, Sensitive<string>? Ticket)
{
    /// <summary>Parses a <c>WWW-Authenticate: UMA …</c> header value (&#167;20.3).</summary>
    /// <remarks>
    /// <para><b>This deliberately does not exchange the ticket.</b> Parsing a
    /// challenge and acting on it are separate decisions: the <c>as_uri</c>
    /// names an authorization server the caller has not necessarily chosen to
    /// trust, and auto-exchanging would send the requesting party's
    /// <c>claim_token</c> to whatever host answered the 403. The caller
    /// decides.</para>
    /// </remarks>
    /// <param name="header">The header value.</param>
    /// <returns>The parsed challenge, or <c>null</c> when it is not a UMA challenge.</returns>
    public static UmaChallenge? Parse(string header)
    {
        ArgumentNullException.ThrowIfNull(header);
        string trimmed = header.Trim();
        if (!trimmed.StartsWith("UMA", StringComparison.Ordinal))
        {
            return null;
        }
        string rest = trimmed[3..];
        // "UMA" alone is a valid, if useless, challenge; anything else must be
        // separated by whitespace so `UMAX realm="…"` is not read as UMA.
        if (rest.Length > 0 && !char.IsWhiteSpace(rest[0]))
        {
            return null;
        }

        string? realm = null;
        string? asUri = null;
        Sensitive<string>? ticket = null;
        foreach (string part in rest.Split(','))
        {
            int eq = part.IndexOf('=', StringComparison.Ordinal);
            if (eq < 0)
            {
                continue;
            }
            string key = part[..eq].Trim();
            string value = part[(eq + 1)..].Trim().Trim('"');
            switch (key)
            {
                case "realm":
                    realm = value;
                    break;
                case "as_uri":
                    asUri = value;
                    break;
                case "ticket":
                    ticket = Sensitive<string>.Wrap(value);
                    break;
                default:
                    // Unknown parameters are ignored rather than rejected: UMA 2.0
                    // permits a server to add its own, and refusing the whole
                    // challenge over one would lose the ticket with it.
                    break;
            }
        }
        return new UmaChallenge(realm, asUri, ticket);
    }

    /// <summary>Formats a <c>WWW-Authenticate: UMA</c> header value (&#167;20.3, emit half).</summary>
    /// <param name="realm">The protection realm.</param>
    /// <param name="asUri">The authorization server.</param>
    /// <param name="ticket">The permission ticket.</param>
    /// <returns>The header value.</returns>
    public static string Header(string realm, string asUri, Sensitive<string> ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        return $"UMA realm=\"{realm}\", as_uri=\"{asUri}\", ticket=\"{ticket.Reveal()}\"";
    }
}
