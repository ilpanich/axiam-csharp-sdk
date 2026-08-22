using System.Text.Json;
using System.Text.Json.Serialization;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Webauthn;

/// <summary>
/// A started ceremony: the server's options plus the token binding a response to them
/// (CONTRACT.md &#167;24.1).
/// </summary>
/// <param name="Challenge">
/// The server's options, exactly as they arrived — a <c>{"publicKey": {…}}</c> object
/// carrying base64url buffers. Hand it to the authenticator <b>unchanged</b>
/// (&#167;24.0), or use <see cref="RequestJson"/> for the string a platform API takes.
/// </param>
/// <param name="StateToken">
/// Binds the authenticator's answer to this challenge. A bearer credential for the length
/// of the ceremony — one that leaks inside that window is a ceremony an attacker can try
/// to complete — so it is <see cref="Sensitive{T}"/> (&#167;24.5). It is <b>opaque</b>:
/// this SDK never decodes it, and neither should a caller.
/// </param>
public sealed record WebauthnChallenge(JsonElement Challenge, Sensitive<string> StateToken)
{
    /// <summary>
    /// The challenge in the JSON form every platform authenticator API takes
    /// (&#167;24.6a rule 1).
    /// </summary>
    /// <remarks>
    /// This is the string a browser passes to
    /// <c>PublicKeyCredential.parseCreationOptionsFromJSON()</c>, and the value a MAUI or
    /// Uno app hands to the platform's WebAuthn bridge. It is the inner options object:
    /// the <c>publicKey</c> wrapper belongs to the DOM's <c>CredentialCreationOptions</c>,
    /// and the platform JSON APIs do not want it.
    /// <para>
    /// Pure local computation, no I/O, hence a property rather than an <c>Async</c>
    /// method. Nothing is defaulted, dropped or reordered on the way through (&#167;24.0).
    /// </para>
    /// </remarks>
    public string RequestJson =>
        Challenge.ValueKind == JsonValueKind.Object &&
        Challenge.TryGetProperty("publicKey", out JsonElement options)
            ? options.GetRawText()
            : Challenge.GetRawText();
}

/// <summary>
/// A credential the user just enrolled — the <c>201</c> body of <c>register/finish</c>
/// (CONTRACT.md &#167;24.1).
/// </summary>
/// <param name="Id">This credential's AXIAM id, for a later delete.</param>
/// <param name="CredentialId">The authenticator's own base64url credential id.</param>
/// <param name="Name">The label it was stored under.</param>
/// <param name="CredentialType"><c>passkey</c> or <c>security_key</c>, as the server classified it.</param>
/// <param name="CreatedAt">RFC 3339 timestamp.</param>
/// <param name="LastUsedAt">RFC 3339 timestamp, or <c>null</c> for a credential never used.</param>
public sealed record WebauthnCredential(
    [property: JsonPropertyName("id")] Guid Id,
    [property: JsonPropertyName("credential_id")] string CredentialId,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("credential_type")] string CredentialType,
    [property: JsonPropertyName("created_at")] string CreatedAt,
    [property: JsonPropertyName("last_used_at")] string? LastUsedAt = null);

/// <summary>
/// A completed authentication ceremony (CONTRACT.md &#167;24.3).
/// </summary>
/// <remarks>
/// The tokens are also adopted by the client that produced this value — the server sets
/// the <c>axiam_access</c> / <c>axiam_refresh</c> / <c>axiam_csrf</c> cookie triple
/// alongside them — so a caller who only wants to be signed in can ignore every property
/// here.
/// </remarks>
/// <param name="AccessToken">The new access token (&#167;24.5).</param>
/// <param name="RefreshToken">The new refresh token (&#167;24.5).</param>
/// <param name="SessionId">The session this ceremony established.</param>
/// <param name="ExpiresIn">The access token's lifetime in seconds.</param>
public sealed record WebauthnLoginResult(
    Sensitive<string> AccessToken,
    Sensitive<string> RefreshToken,
    Guid SessionId,
    long ExpiresIn);

/// <summary>
/// The workspace a usernameless ceremony runs in (CONTRACT.md &#167;24.1).
/// </summary>
/// <remarks>
/// <c>discoverable/start</c> is the one WebAuthn endpoint that carries the workspace
/// explicitly, because a usernameless ceremony has no prior step to have minted a token
/// that names it. Unlike the five <c>/oauth2</c> operations of &#167;12.1 rule 2 it
/// <b>accepts slugs</b>, so a slug-only client can run it.
/// <para>
/// Pass <c>null</c> to <c>WebauthnDiscoverableStartAsync</c> to have it filled from the
/// client's own configured identity, which is what almost every caller wants.
/// </para>
/// </remarks>
public sealed class WebauthnWorkspace
{
    /// <summary>An organization override, in UUID form.</summary>
    public Guid? OrgId { get; init; }

    /// <summary>An organization override, in slug form.</summary>
    public string? OrgSlug { get; init; }

    /// <summary>A tenant override, in UUID form.</summary>
    public Guid? TenantId { get; init; }

    /// <summary>A tenant override, in slug form.</summary>
    public string? TenantSlug { get; init; }
}

/// <summary>
/// A ceremony failure a caller can say something useful about (CONTRACT.md &#167;24.6b
/// rule 5).
/// </summary>
/// <remarks>
/// This SDK ships no linked-API helper — a server or CLI runtime has no authenticator and
/// &#167;24.6b rule 2 forbids emulating one — but the classification is still required of
/// it: a Blazor or MAUI front end relaying a <c>DOMException</c> name has the same five
/// outcomes and the same reason to want one vocabulary for them.
/// </remarks>
public enum WebauthnFailure
{
    /// <summary>
    /// Covers <b>both</b> an explicit refusal and a silent timeout.
    /// </summary>
    /// <remarks>
    /// The WebAuthn spec deliberately refuses to distinguish them, because telling a
    /// website which one happened leaks whether an authenticator was present. It must not
    /// be recovered by timing the call.
    /// </remarks>
    Cancelled,

    /// <summary>
    /// The authenticator already holds a credential for this account and refused to
    /// silently mint a second — the exclusion list working, not a failure. The only
    /// classification whose remedy is "use a different device".
    /// </summary>
    AlreadyRegistered,

    /// <summary>An explicitly aborted ceremony.</summary>
    Timeout,

    /// <summary>This device or browser cannot run the ceremony.</summary>
    Unsupported,

    /// <summary>Everything else.</summary>
    Unknown,
}

/// <summary>Classification and user-facing copy for <see cref="WebauthnFailure"/>.</summary>
public static class WebauthnFailures
{
    private static readonly IReadOnlyDictionary<string, WebauthnFailure> ByName =
        new Dictionary<string, WebauthnFailure>(StringComparer.OrdinalIgnoreCase)
        {
            ["notallowederror"] = WebauthnFailure.Cancelled,
            ["canceled"] = WebauthnFailure.Cancelled,
            ["cancelled"] = WebauthnFailure.Cancelled,
            ["invalidstateerror"] = WebauthnFailure.AlreadyRegistered,
            ["aborterror"] = WebauthnFailure.Timeout,
            ["timeout"] = WebauthnFailure.Timeout,
            ["notsupportederror"] = WebauthnFailure.Unsupported,
            ["securityerror"] = WebauthnFailure.Unsupported,
        };

    /// <summary>
    /// Maps a platform ceremony error name to its canonical classification.
    /// </summary>
    /// <remarks>
    /// Every platform reports a ceremony failure as one opaque type whose only
    /// machine-readable part is a name, so a browser front end can relay just that name
    /// and a .NET service turns it into the same five outcomes. Anything unrecognized is
    /// <see cref="WebauthnFailure.Unknown"/> rather than a throw — a classifier that can
    /// fail is one more thing for an error handler to handle.
    /// </remarks>
    public static WebauthnFailure Classify(string? name) =>
        name is not null && ByName.TryGetValue(name.Trim(), out WebauthnFailure failure)
            ? failure
            : WebauthnFailure.Unknown;

    /// <summary>
    /// Copy for a failure, safe to show a user.
    /// </summary>
    /// <remarks>
    /// The <see cref="WebauthnFailure.Cancelled"/> string deliberately does not accuse
    /// anyone of cancelling: the same classification covers a silent timeout, and the spec
    /// will not say which happened.
    /// </remarks>
    public static string Message(this WebauthnFailure failure) => failure switch
    {
        WebauthnFailure.Cancelled => "The request was cancelled or timed out. You can try again.",
        WebauthnFailure.AlreadyRegistered =>
            "This device is already registered on your account. Try a different device, " +
            "or remove the existing one first.",
        WebauthnFailure.Timeout => "The request timed out before it completed. Please try again.",
        WebauthnFailure.Unsupported =>
            "This browser or device cannot be used for passkeys. Try a different browser, " +
            "or use another sign-in method.",
        _ => "Something went wrong. Please try again.",
    };
}
