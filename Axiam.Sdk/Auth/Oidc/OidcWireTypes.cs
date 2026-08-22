using System.Text.Json.Serialization;

namespace Axiam.Sdk.Auth.Oidc;

// Internal wire DTOs mirroring the server's OpenAPI schemas verbatim (mirror only, no
// server dependency) — CONTRACT.md §12.1. Never part of the public API surface; AxiamClient
// converts these into the public SDK-shaped result types in OidcTypes.cs.

/// <summary>The <c>200</c> body of <c>POST /oauth2/token</c> (wire schema <c>TokenResponse</c>).
/// <c>token_type</c> is required (&#167;12 port addendum item 3).</summary>
internal sealed record TokenResponseWire(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] long ExpiresIn,
    [property: JsonPropertyName("scope")] string? Scope,
    [property: JsonPropertyName("refresh_token")] string? RefreshToken,
    [property: JsonPropertyName("id_token")] string? IdToken);

/// <summary>The <c>200</c> body of <c>POST /oauth2/introspect</c> (wire schema
/// <c>IntrospectionResponse</c>).</summary>
internal sealed record IntrospectionResponseWire(
    [property: JsonPropertyName("active")] bool Active,
    [property: JsonPropertyName("sub")] string? Sub,
    [property: JsonPropertyName("client_id")] string? ClientId,
    [property: JsonPropertyName("scope")] string? Scope,
    [property: JsonPropertyName("token_type")] string? TokenType,
    [property: JsonPropertyName("exp")] long? Exp,
    [property: JsonPropertyName("iat")] long? Iat);

/// <summary>The RFC 6749 error response body an <c>/oauth2/*</c> endpoint returns on the
/// endpoint-qualified error status (CONTRACT.md &#167;2, &#167;12.1).</summary>
internal sealed record OAuth2ErrorResponseWire(
    [property: JsonPropertyName("error")] string? Error,
    [property: JsonPropertyName("error_description")] string? ErrorDescription);

/// <summary>The <c>200</c> body of <c>POST /api/v1/auth/federation/oidc/start</c> (wire
/// schema <c>OidcStartResponse</c>).</summary>
internal sealed record OidcStartResponseWire(
    [property: JsonPropertyName("authorize_url")] string AuthorizeUrl,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("expires_in_secs")] long ExpiresInSecs);

/// <summary>The <c>200</c> body of <c>POST /api/v1/auth/federation/oidc/callback</c> (wire
/// schema <c>SsoLoginSuccessResponse</c>).</summary>
internal sealed record SsoLoginSuccessResponseWire(
    [property: JsonPropertyName("user_id")] string UserId,
    [property: JsonPropertyName("session_id")] string SessionId,
    [property: JsonPropertyName("expires_in")] long ExpiresIn,
    [property: JsonPropertyName("redirect_uri")] string RedirectUri);

/// <summary>200 body of <c>POST /oauth2/device_authorization</c> (CONTRACT.md &#167;14.1).</summary>
internal sealed record DeviceAuthorizationResponseWire(
    [property: JsonPropertyName("device_code")] string DeviceCode,
    [property: JsonPropertyName("user_code")] string UserCode,
    [property: JsonPropertyName("verification_uri")] string VerificationUri,
    [property: JsonPropertyName("expires_in")] int ExpiresIn,
    [property: JsonPropertyName("verification_uri_complete")] string? VerificationUriComplete = null,
    [property: JsonPropertyName("interval")] int? Interval = null);

/// <summary>200 body of a token-exchange <c>POST /oauth2/token</c> (CONTRACT.md &#167;15.1).</summary>
internal sealed record TokenExchangeResponseWire(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("issued_token_type")] string IssuedTokenType,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] long ExpiresIn,
    [property: JsonPropertyName("scope")] string? Scope = null);

/// <summary>The <c>201</c> body of <c>POST /oauth2/par</c> (RFC 9126 &#167;2.2 — Created,
/// not OK).</summary>
internal sealed record PushedAuthorizationResponseWire(
    [property: JsonPropertyName("request_uri")] string RequestUri,
    [property: JsonPropertyName("expires_in")] long ExpiresIn);
