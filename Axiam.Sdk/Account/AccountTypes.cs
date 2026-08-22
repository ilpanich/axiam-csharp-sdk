using System.Text.Json;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Account;

/// <summary>
/// A TOTP factor offered but not yet active (CONTRACT.md &#167;25.1).
/// </summary>
/// <remarks>
/// <b>Both halves are <see cref="Sensitive{T}"/>, and the second one is why.</b> The
/// <c>otpauth://</c> URI <i>contains</i> the secret: wrapping the bare secret and then
/// logging the URI leaks exactly the same bytes (&#167;25.3).
/// </remarks>
/// <param name="SecretBase32">
/// The shared TOTP secret. Anyone holding it can generate valid codes for this account
/// indefinitely.
/// </param>
/// <param name="TotpUri">
/// <c>otpauth://totp/…?secret=&lt;SecretBase32&gt;</c> — the string an authenticator app
/// scans out of a QR code.
/// </param>
public sealed record MfaEnrollment(Sensitive<string> SecretBase32, Sensitive<string> TotpUri);

/// <summary>
/// The OPAQUE policy for the account a reset token belongs to (CONTRACT.md &#167;25.1).
/// </summary>
/// <param name="Opaque">
/// The tenant's &#167;23 parameters when it has OPAQUE enabled, and <c>null</c> when it
/// does not — in which case the plaintext path is allowed. The block is forwarded to the
/// &#167;23 helpers untouched: this SDK does not model, validate or re-encode it.
/// </param>
public sealed record PasswordResetContext(JsonElement? Opaque);

/// <summary>
/// Arguments to <c>RequestPasswordResetAsync</c> (CONTRACT.md &#167;25.1).
/// </summary>
/// <remarks>
/// The workspace properties are all optional: unset, they are filled from the client's own
/// configured identity, which is what almost every caller wants.
/// </remarks>
public sealed class PasswordResetRequest
{
    /// <summary>The address to send the reset mail to.</summary>
    public required string Email { get; init; }

    /// <summary>An organization override, in slug form.</summary>
    public string? OrgSlug { get; init; }

    /// <summary>A tenant override, in UUID form.</summary>
    public Guid? TenantId { get; init; }

    /// <summary>A tenant override, in slug form.</summary>
    public string? TenantSlug { get; init; }
}

/// <summary>
/// Arguments to <c>ConfirmPasswordResetAsync</c> (CONTRACT.md &#167;25.1).
/// </summary>
public sealed class PasswordResetConfirmation
{
    /// <summary>
    /// The single-use token from the reset mail. Build it with
    /// <see cref="Sensitive{T}.Wrap"/> — a caller holding it as a bare string is the
    /// expected case, and wrapping a value can never leak it.
    /// </summary>
    public required Sensitive<string> Token { get; init; }

    /// <summary>The replacement password, wrapped the same way.</summary>
    public required Sensitive<string> NewPassword { get; init; }

    /// <summary>
    /// The tenant the account belongs to. A <b>body</b> field: this is not an
    /// <c>/oauth2</c> endpoint, so &#167;12.1 rule 2's query-parameter convention does not
    /// reach it.
    /// </summary>
    public required Guid TenantId { get; init; }

    /// <summary>
    /// The &#167;23 registration record, for a tenant whose
    /// <c>PasswordResetContextAsync</c> reported an OPAQUE policy. <c>null</c> on the
    /// plaintext path.
    /// </summary>
    public JsonElement? Opaque { get; init; }
}
