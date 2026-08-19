namespace Axiam.Sdk.Srp;

using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Axiam.Sdk.Core;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

/// <summary>
/// SRP-6a protocol arithmetic (CONTRACT.md &#167;23).
/// </summary>
/// <remarks>
/// <para>
/// Everything here is pure: no I/O, no client state, no network. The two HTTP calls and the
/// policy around them live in <c>AxiamClient.LoginSrpAsync</c>.
/// </para>
/// <para>
/// <c>H</c> is <b>SHA-256</b> throughout. RFC 5054 specifies SHA-1; AXIAM does not use SHA-1
/// anywhere and does not start here.
/// </para>
/// </remarks>
public static class SrpMath
{
    /// <summary>
    /// <c>PAD(v)</c> — <paramref name="value"/> as exactly <paramref name="byteLength"/>
    /// big-endian bytes (&#167;23.3 rule 1).
    /// </summary>
    /// <remarks>
    /// Skipping this is the classic SRP interop bug: two implementations agree until a value
    /// happens to have a leading zero byte, and then roughly one login in 256 fails in a way
    /// that reads as a flaky network.
    /// </remarks>
    /// <param name="value">The value to render.</param>
    /// <param name="byteLength">The group's modulus width in bytes.</param>
    /// <returns>Exactly <paramref name="byteLength"/> bytes.</returns>
    public static byte[] Pad(BigInteger value, int byteLength)
    {
        // isUnsigned so a value whose top bit is set does not gain a sign byte; isBigEndian
        // because every SRP field is big-endian on the wire.
        byte[] raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length == byteLength)
        {
            return raw;
        }

        var padded = new byte[byteLength];
        // A value wider than the modulus is a caller error, not something to truncate:
        // silently dropping high bytes would produce a wrong hash that still looked fine.
        int copy = Math.Min(raw.Length, byteLength);
        Array.Copy(raw, raw.Length - copy, padded, byteLength - copy, copy);
        return padded;
    }

    /// <summary>SHA-256 over the concatenation of <paramref name="parts"/>.</summary>
    /// <param name="parts">The byte strings to hash, in order.</param>
    /// <returns>The 32-byte digest.</returns>
    public static byte[] Hash(params byte[][] parts)
    {
        ArgumentNullException.ThrowIfNull(parts);
        using var sha = SHA256.Create();
        var total = new List<byte>();
        foreach (byte[] part in parts)
        {
            total.AddRange(part);
        }

        return sha.ComputeHash(total.ToArray());
    }

    /// <summary><see cref="Hash"/> read back as a non-negative big-endian integer.</summary>
    /// <param name="parts">The byte strings to hash, in order.</param>
    /// <returns>The digest as an integer.</returns>
    public static BigInteger HashToInt(params byte[][] parts) =>
        new(Hash(parts), isUnsigned: true, isBigEndian: true);

    /// <summary><c>k = H(N | PAD(g))</c> — depends only on the group.</summary>
    /// <param name="group">The group.</param>
    /// <returns>The SRP-6a multiplier.</returns>
    public static BigInteger Multiplier(SrpGroup group)
    {
        ArgumentNullException.ThrowIfNull(group);
        return HashToInt(Pad(group.Modulus, group.ByteLength), Pad(group.Generator, group.ByteLength));
    }

    /// <summary>
    /// <c>x = KDF(identity ":" password, salt)</c>, as raw bytes (&#167;23.3 rule 3).
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 5054's bare-hash <c>x</c> would make a leaked verifier <i>cheaper</i> to attack
    /// offline than the Argon2id hashes AXIAM stores today, which would make adopting SRP a
    /// net regression at rest — so the KDF is memory-hard, and the server dictates which one
    /// per exchange.
    /// </para>
    /// <para>
    /// <paramref name="identity"/> is the one the server named in the challenge, never what
    /// the human typed (&#167;23.3 rule 2).
    /// </para>
    /// </remarks>
    /// <param name="identity">The server's canonical identity for the account.</param>
    /// <param name="password">The plaintext password.</param>
    /// <param name="salt">The account's SRP salt.</param>
    /// <param name="parameters">The KDF and cost the server dictated.</param>
    /// <returns>32 bytes of key material; the caller reduces mod <c>N</c>.</returns>
    /// <exception cref="NetworkError">The named KDF is not one this SDK implements.</exception>
    public static byte[] DeriveX(string identity, char[] password, byte[] salt, SrpKdfParams parameters)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(parameters);

        byte[] secret = EncodeSecret(identity, password);
        try
        {
            return parameters.Kdf switch
            {
                SrpKdfParams.Argon2id => Argon2Id(secret, salt, parameters),
                SrpKdfParams.Pbkdf2Sha256 => Rfc2898DeriveBytes.Pbkdf2(
                    secret, salt, Math.Max(1, parameters.Iterations), HashAlgorithmName.SHA256, 32),

                // Never substitute the other KDF: it derives a different x and surfaces as
                // "invalid password", the single most misleading failure this code could
                // produce.
                _ => throw NetworkError.FromMessage(
                    $"SRP: this SDK does not implement KDF '{parameters.Kdf}'; " +
                    "it implements argon2id and pbkdf2_sha256"),
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>
    /// <c>identity ":" password</c> as UTF-8, without ever materialising it as a
    /// <see cref="string"/>.
    /// </summary>
    /// <remarks>
    /// A <see cref="string"/> here would be immutable, interned-adjacent and impossible to
    /// clear, which is exactly what taking the password as a <c>char[]</c> exists to avoid.
    /// </remarks>
    private static byte[] EncodeSecret(string identity, char[] password)
    {
        char[] joined = new char[identity.Length + 1 + password.Length];
        try
        {
            identity.CopyTo(0, joined, 0, identity.Length);
            joined[identity.Length] = ':';
            Array.Copy(password, 0, joined, identity.Length + 1, password.Length);
            return Encoding.UTF8.GetBytes(joined);
        }
        finally
        {
            Array.Clear(joined);
        }
    }

    private static byte[] Argon2Id(byte[] secret, byte[] salt, SrpKdfParams parameters)
    {
        // BouncyCastle rather than a .NET built-in: the BCL ships PBKDF2 but no Argon2, and
        // §23.3 rule 4 makes both KDFs mandatory for login. BouncyCastle.Cryptography is
        // already a dependency of this SDK for the §8 AMQP path.
        var builder = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithIterations(Math.Max(1, parameters.Iterations))
            .WithMemoryAsKB(Math.Max(8, parameters.MemoryKib))
            .WithParallelism(Math.Max(1, parameters.Parallelism))
            .WithSalt(salt);

        var generator = new Argon2BytesGenerator();
        generator.Init(builder.Build());
        var output = new byte[32];
        generator.GenerateBytes(secret, output);
        return output;
    }

    /// <summary>
    /// <c>v = g^x mod N</c> — the verifier the server stores instead of a password hash.
    /// </summary>
    /// <param name="group">The group the verifier lives in.</param>
    /// <param name="x">The KDF output from <see cref="DeriveX"/>.</param>
    /// <returns>The verifier, lowercase hex, padded to the group width.</returns>
    public static string ComputeVerifier(SrpGroup group, byte[] x)
    {
        ArgumentNullException.ThrowIfNull(group);
        BigInteger reduced = ToPositive(x) % group.Modulus;
        return ToHex(Pad(BigInteger.ModPow(group.Generator, reduced, group.Modulus), group.ByteLength));
    }

    /// <summary>
    /// 32 fresh bytes from the platform CSPRNG, for an enrolment salt (&#167;23.3 rule 11).
    /// </summary>
    /// <remarks>
    /// A reused salt would make every verifier in a tenant equally attackable with one
    /// precomputation.
    /// </remarks>
    /// <returns>32 random bytes.</returns>
    public static byte[] GenerateSalt() => RandomNumberGenerator.GetBytes(32);

    /// <summary>
    /// Constant-time comparison of the server's <c>M2</c> against the expected one
    /// (&#167;23.3 rule 6).
    /// </summary>
    /// <param name="expected">The <c>M2</c> this client derived.</param>
    /// <param name="actual">The <c>server_proof</c> the server returned, possibly <c>null</c>.</param>
    /// <returns><c>true</c> only if they match.</returns>
    public static bool VerifyServerProof(string expected, string? actual)
    {
        ArgumentNullException.ThrowIfNull(expected);
        if (actual is null || actual.Length != expected.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected.ToLowerInvariant()),
            Encoding.ASCII.GetBytes(actual.ToLowerInvariant()));
    }

    /// <summary>Lowercase hex, the encoding every SRP field uses on the wire.</summary>
    /// <param name="bytes">The bytes to render.</param>
    /// <returns>The hex string.</returns>
    public static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    /// <summary>Parses a lowercase-hex wire field.</summary>
    /// <param name="hex">The field's value.</param>
    /// <param name="field">The field's name, for the error message.</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="NetworkError"><paramref name="hex"/> is not valid hex.</exception>
    public static byte[] FromHex(string hex, string field)
    {
        try
        {
            return Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            throw NetworkError.FromMessage($"SRP: the server's {field} is not valid hex");
        }
    }

    /// <summary>
    /// A big-endian byte string as a non-negative <see cref="BigInteger"/>.
    /// </summary>
    /// <remarks>
    /// Every SRP quantity is unsigned. Reading one with .NET's default little-endian, signed
    /// interpretation would produce a negative value whenever the top bit happened to be set,
    /// and every modular operation after that would be computed in the wrong ring.
    /// </remarks>
    /// <param name="bigEndian">The bytes to read.</param>
    /// <returns>The value.</returns>
    public static BigInteger ToPositive(byte[] bigEndian) =>
        new(bigEndian, isUnsigned: true, isBigEndian: true);
}
