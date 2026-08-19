namespace Axiam.Sdk.Srp;

/// <summary>
/// The <c>srp</c> object CONTRACT.md &#167;23.5 defines: a verifier and the parameters it was
/// computed under.
/// </summary>
/// <remarks>
/// <para>
/// The server cannot compute this — it never sees the plaintext — so any request that
/// <b>sets</b> a password has to carry it: <c>POST /api/v1/users</c>,
/// <c>/auth/password/change</c>, <c>/auth/reset/confirm</c> and <c>/admin/bootstrap</c>
/// (&#167;23.3 rule 11).
/// </para>
/// <para>
/// Neither <see cref="Salt"/> nor <see cref="Verifier"/> may be logged (&#167;23.3 rule 12).
/// </para>
/// </remarks>
/// <param name="Group">The wire group name the verifier lives in.</param>
/// <param name="Kdf">The KDF used to derive <c>x</c>.</param>
/// <param name="MemoryKib">Argon2id's memory cost, or <c>0</c> for PBKDF2.</param>
/// <param name="Iterations">The KDF's iteration/time cost.</param>
/// <param name="Parallelism">Argon2id's lane count, or <c>0</c> for PBKDF2.</param>
/// <param name="Salt">The 32-byte enrolment salt, lowercase hex.</param>
/// <param name="Verifier"><c>v = g^x mod N</c>, lowercase hex.</param>
public sealed record SrpEnrollment(
    string Group,
    string Kdf,
    int MemoryKib,
    int Iterations,
    int Parallelism,
    string Salt,
    string Verifier)
{
    /// <summary>
    /// This enrolment as the dictionary the password-setting endpoints accept as their
    /// <c>srp</c> member.
    /// </summary>
    /// <remarks>
    /// Argon2id's two cost keys are omitted entirely for a PBKDF2 enrolment rather than sent
    /// as zeros, which is what &#167;23.5's shape specifies.
    /// </remarks>
    /// <returns>The JSON-ready body fragment.</returns>
    public Dictionary<string, object?> ToWire()
    {
        var wire = new Dictionary<string, object?>
        {
            ["group"] = Group,
            ["kdf"] = Kdf,
        };
        if (MemoryKib > 0)
        {
            wire["memory_kib"] = MemoryKib;
        }

        wire["iterations"] = Iterations;
        if (Parallelism > 0)
        {
            wire["parallelism"] = Parallelism;
        }

        wire["salt"] = Salt;
        wire["verifier"] = Verifier;
        return wire;
    }
}
