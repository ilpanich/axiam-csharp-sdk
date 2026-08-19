namespace Axiam.Sdk.Srp;

using System.Text.Json;

/// <summary>
/// The KDF and cost the server dictates for one SRP exchange (CONTRACT.md &#167;23.5).
/// </summary>
/// <remarks>
/// &#167;23.3 rule 4: these arrive per exchange and are honoured as given. They are
/// deliberately <b>not</b> cached across logins — a verifier enrolled under different costs
/// is still valid and has to keep working.
/// </remarks>
/// <param name="Kdf"><c>argon2id</c> or <c>pbkdf2_sha256</c>.</param>
/// <param name="Iterations">Argon2id's time cost, or PBKDF2's iteration count.</param>
/// <param name="MemoryKib">Argon2id's memory cost in KiB; ignored for PBKDF2.</param>
/// <param name="Parallelism">Argon2id's lane count; ignored for PBKDF2.</param>
public sealed record SrpKdfParams(string Kdf, int Iterations, int MemoryKib = 0, int Parallelism = 0)
{
    /// <summary>The wire name of the memory-hard KDF AXIAM asks for by default.</summary>
    public const string Argon2id = "argon2id";

    /// <summary>The wire name of the fallback for runtimes with no vetted Argon2.</summary>
    public const string Pbkdf2Sha256 = "pbkdf2_sha256";

    /// <summary>Reads the KDF fields of a challenge response.</summary>
    /// <remarks>
    /// <c>memory_kib</c> and <c>parallelism</c> are present only for <c>argon2id</c>, so
    /// their absence is normal rather than an error.
    /// </remarks>
    /// <param name="challenge">The parsed challenge response body.</param>
    /// <returns>The parameters that exchange must use.</returns>
    public static SrpKdfParams FromChallenge(JsonElement challenge) => new(
        challenge.TryGetProperty("kdf", out JsonElement kdf) ? kdf.GetString() ?? string.Empty : string.Empty,
        ReadInt(challenge, "iterations"),
        ReadInt(challenge, "memory_kib"),
        ReadInt(challenge, "parallelism"));

    /// <summary>
    /// This instance with any zero cost replaced by AXIAM's default for the chosen KDF.
    /// </summary>
    /// <remarks>
    /// Used on the enrolment path, where the caller may know only which KDF the tenant runs.
    /// It is never applied to a challenge response: a server that omits a cost it is required
    /// to send is a server this SDK should not be guessing on behalf of.
    /// </remarks>
    /// <returns>The same parameters with defaults filled in.</returns>
    public SrpKdfParams WithDefaults()
    {
        string kdf = string.IsNullOrEmpty(Kdf) ? Argon2id : Kdf;
        if (kdf == Pbkdf2Sha256)
        {
            return new SrpKdfParams(kdf, Iterations > 0 ? Iterations : 600_000);
        }

        return new SrpKdfParams(
            kdf,
            Iterations > 0 ? Iterations : 2,
            MemoryKib > 0 ? MemoryKib : 19456,
            Parallelism > 0 ? Parallelism : 1);
    }

    private static int ReadInt(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) && value.TryGetInt32(out int parsed) ? parsed : 0;
}
