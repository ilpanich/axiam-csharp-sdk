namespace Axiam.Sdk.Opaque;

using System.Text.Json;
using Axiam.Sdk.Core;

/// <summary>
/// The key-stretching function and cost a <c>/start</c> response names (CONTRACT.md
/// &#167;23.4).
/// </summary>
/// <remarks>
/// <para>
/// The cost properties are nullable on purpose: they arrive flat, and a field that does not
/// apply to the named function is <b>absent, not zero</b>. Reading a missing
/// <see cref="MemoryKib"/> as <c>0</c> would stretch at the wrong cost and fail against a
/// record that is perfectly good (&#167;23.4 rule 5).
/// </para>
/// <para>
/// These are never cached across exchanges and never defaulted locally. A credential enrolled
/// under one cost keeps working after a tenant raises its policy, so a client that guessed
/// would derive a different randomized password and report "invalid password" for one that is
/// entirely correct (&#167;23.4 rule 2).
/// </para>
/// </remarks>
/// <param name="Ksf">The wire name of the function: <c>argon2id</c> or <c>scrypt</c>.</param>
/// <param name="MemoryKib">Argon2id's memory cost in KiB.</param>
/// <param name="Iterations">Argon2id's time cost.</param>
/// <param name="Parallelism">Argon2id's lane count.</param>
/// <param name="LogN">scrypt's base-2 CPU/memory cost.</param>
/// <param name="R">scrypt's block size.</param>
/// <param name="P">scrypt's parallelisation parameter.</param>
public sealed record KsfParams(
    string Ksf,
    int? MemoryKib = null,
    int? Iterations = null,
    int? Parallelism = null,
    int? LogN = null,
    int? R = null,
    int? P = null)
{
    /// <summary>The wire name of the memory-hard function AXIAM asks for by default.</summary>
    public const string Argon2id = "argon2id";

    /// <summary>The wire name of the alternative AXIAM accepts.</summary>
    public const string Scrypt = "scrypt";

    /// <summary>
    /// Reads the flat key-stretching fields of a <c>/start</c> response, preserving absence.
    /// </summary>
    /// <param name="wire">The parsed response body.</param>
    /// <returns>The parameters that exchange must use.</returns>
    public static KsfParams FromWire(JsonElement wire) => new(
        wire.TryGetProperty("ksf", out JsonElement ksf) ? ksf.GetString() ?? string.Empty : string.Empty,
        Optional(wire, "memory_kib"),
        Optional(wire, "iterations"),
        Optional(wire, "parallelism"),
        Optional(wire, "log_n"),
        Optional(wire, "r"),
        Optional(wire, "p"));

    private static int? Optional(JsonElement wire, string field)
    {
        if (!wire.TryGetProperty(field, out JsonElement value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String
            ? int.TryParse(value.GetString(), out int parsed) ? parsed : null
            : value.TryGetInt32(out int number) ? number : null;
    }

    /// <summary>
    /// Builds the library's key-stretching handle from what the <i>server</i> named.
    /// </summary>
    /// <remarks>
    /// An unrecognised function is refused, never substituted: substituting produces a
    /// well-formed randomized password no AXIAM server agrees with, which surfaces to the user
    /// as a wrong password (&#167;23.4 rule 3). The returned handle must be released with
    /// <c>KsfFree</c>.
    /// </remarks>
    internal nint Build(IOpaqueNative lib)
    {
        nint handle = Ksf switch
        {
            Argon2id => lib.KsfArgon2id(
                (uint)Require("memory_kib", MemoryKib, 8192, 1_048_576),
                (uint)Require("iterations", Iterations, 1, 10),
                (uint)Require("parallelism", Parallelism, 1, 16)),
            Scrypt => lib.KsfScrypt(
                (byte)Require("log_n", LogN, 14, 20),
                (uint)Require("r", R, 1, 16),
                (uint)Require("p", P, 1, 16)),
            _ => throw NetworkError.FromMessage(
                "OPAQUE: this SDK cannot perform the key-stretching function the server " +
                $"named (`{Ksf}`)"),
        };

        return handle == nint.Zero
            ? throw NetworkError.FromMessage(
                "OPAQUE: " + OpaqueProtocol.LastError(lib, "invalid KSF parameters"))
            : handle;
    }

    /// <summary>
    /// One cost the named function needs: present, and inside the band this SDK will act on.
    /// </summary>
    /// <remarks>
    /// A server is trusted to name its own policy, not to name a cost that would wedge every
    /// device an account owns. The library range-checks too; doing it here as well means the
    /// refusal names the field.
    /// </remarks>
    private int Require(string field, int? value, int low, int high)
    {
        if (value is null)
        {
            throw NetworkError.FromMessage(
                $"OPAQUE: the server named ksf `{Ksf}` without `{field}`");
        }

        if (value < low || value > high)
        {
            throw NetworkError.FromMessage(
                $"OPAQUE: the server named {field}={value} for `{Ksf}`, outside the accepted " +
                $"{low}..{high}");
        }

        return value.Value;
    }
}
