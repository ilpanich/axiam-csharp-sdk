namespace Axiam.Sdk.Opaque;

/// <summary>
/// The <c>opaque</c> object CONTRACT.md &#167;23 defines: a registration record and the
/// server-issued session handle that identifies the exchange it came from.
/// </summary>
/// <remarks>
/// <para>
/// The server cannot build this — it never sees the plaintext — so any request that
/// <b>sets</b> a password has to carry it: <c>POST /api/v1/users</c>,
/// <c>/auth/password/change</c>, <c>/auth/reset/confirm</c> and <c>/admin/bootstrap</c>.
/// </para>
/// <para>
/// Note what is <i>not</i> here. The SRP enrolment this replaces carried a salt, a group and a
/// full set of KDF costs, and required the account's canonical username — passing an email
/// produced a verifier no login could ever satisfy, and renaming a user invalidated their
/// verifier outright. A record binds to a credential identifier the server chooses, and the
/// key-stretching parameters are the server's, so there is nothing here a caller can get wrong.
/// </para>
/// </remarks>
/// <param name="OpaqueSession">The handle <c>register/start</c> issued.</param>
/// <param name="RegistrationRecord">The hex <c>RegistrationRecord</c>.</param>
public sealed record OpaqueEnrollment(string OpaqueSession, string RegistrationRecord)
{
    /// <summary>
    /// This enrolment as the dictionary the password-setting endpoints accept as their
    /// <c>opaque</c> member.
    /// </summary>
    /// <returns>The JSON-ready body fragment.</returns>
    public Dictionary<string, object?> ToWire() => new()
    {
        ["opaque_session"] = OpaqueSession,
        ["registration_record"] = RegistrationRecord,
    };
}
