namespace Axiam.Sdk.Opaque;

using System;
using System.Text.Json;

/// <summary>
/// The tenant's <c>opaque_mode</c>, as carried by the optional <c>mode</c> field of a
/// <c>POST /api/v1/auth/opaque/login/start</c> response (CONTRACT.md &#167;23.5).
/// </summary>
/// <remarks>
/// <para>
/// &#167;23.4 rule 7 is the only thing an SDK does with this field: when <c>KE2</c> fails to
/// open, <c>mode</c> — and nothing else — decides whether the exchange is over or whether the
/// SDK owes the caller one more attempt over <c>POST /api/v1/auth/login</c>.
/// </para>
/// <para>
/// It is <b>not</b> downgrade protection and must not be presented as such. A hostile server
/// that wanted the plaintext would answer <c>404</c> and get the fallback whatever it puts
/// here; what closes that is the server refusing <c>/auth/login</c> under <c>required</c>,
/// before it examines any credential. The field is a property of the <i>tenant</i>, identical
/// for a real and a decoy exchange, so it also leaks nothing about whether an identity exists
/// or is enrolled.
/// </para>
/// </remarks>
internal static class OpaqueMode
{
    /// <summary>Both login paths work; records accumulate as passwords are set.</summary>
    internal const string Optional = "optional";

    /// <summary><c>/auth/login</c> answers <c>403 opaque_required</c> for every principal.</summary>
    internal const string Required = "required";

    /// <summary>
    /// Reads the optional <c>mode</c> field, preserving absence.
    /// </summary>
    /// <param name="wire">The parsed <c>login/start</c> response body.</param>
    /// <returns>
    /// The mode the server named, or <c>null</c> when the field is absent, null or not a
    /// string — a server older than contract 1.29 simply does not send it.
    /// </returns>
    internal static string? FromWire(JsonElement wire) =>
        wire.TryGetProperty("mode", out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>
    /// Whether a failed <c>KE2</c> under <paramref name="mode"/> must be retried over
    /// <c>POST /api/v1/auth/login</c> (&#167;23.4 rule 7).
    /// </summary>
    /// <remarks>
    /// Only the exact string <c>optional</c> qualifies, so an absent field (a server older than
    /// the field) and an unrecognised value both fail closed — the failure is final and no
    /// plaintext password goes on the wire. <c>optional</c> is the mid-migration state where an
    /// account with no registration record is the ordinary case rather than an error: every
    /// account has none the moment an operator enables OPAQUE, and acquires one only as it next
    /// sets a password. Treating the failed exchange as final there locks out every user of the
    /// tenant.
    /// </remarks>
    /// <param name="mode">The value <see cref="FromWire"/> returned.</param>
    /// <returns><c>true</c> only for <c>optional</c>.</returns>
    internal static bool AllowsPasswordFallback(string? mode) =>
        string.Equals(mode, Optional, StringComparison.Ordinal);
}
