namespace Axiam.Sdk.Srp;

using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Axiam.Sdk.Core;

/// <summary>
/// One SRP exchange's client half: the ephemeral secret <c>a</c> held between the challenge
/// request and the proof that answers it (CONTRACT.md &#167;23.2).
/// </summary>
/// <remarks>
/// A session is single-use. <c>a</c> is drawn fresh per exchange by <see cref="Begin"/> and
/// there is no way to supply one there, because reusing it across logins leaks the
/// relationship between two session secrets (&#167;23.3 rule 7).
/// </remarks>
public sealed class SrpClientSession
{
    private readonly BigInteger _ephemeral;

    private SrpClientSession(SrpGroup group, BigInteger ephemeral)
    {
        Group = group;
        _ephemeral = ephemeral;
        ClientPublic = SrpMath.ToHex(
            SrpMath.Pad(BigInteger.ModPow(group.Generator, ephemeral, group.Modulus), group.ByteLength));
    }

    /// <summary>The group this exchange runs in.</summary>
    public SrpGroup Group { get; }

    /// <summary><c>A = g^a mod N</c>, lowercase hex — sent with the challenge request.</summary>
    public string ClientPublic { get; }

    /// <summary>
    /// Starts an exchange in <paramref name="group"/>: draws a fresh <c>a</c> of at least
    /// 256 bits from the platform CSPRNG and computes <c>A</c>.
    /// </summary>
    /// <param name="group">The group to compute in.</param>
    /// <returns>The new session.</returns>
    public static SrpClientSession Begin(SrpGroup group)
    {
        ArgumentNullException.ThrowIfNull(group);
        byte[] raw = RandomNumberGenerator.GetBytes(32);
        // Set the top bit so a is unambiguously >= 2^255.
        raw[0] |= 0x80;
        return new SrpClientSession(group, SrpMath.ToPositive(raw));
    }

    /// <summary>Starts an exchange with <c>a</c> pinned to a supplied value.</summary>
    /// <remarks>
    /// For the &#167;23.7 cross-language vectors <b>only</b>: they fix <c>a</c> so every
    /// intermediate is reproducible. Never call this from application code — a predictable
    /// <c>a</c> defeats the protocol.
    /// </remarks>
    /// <param name="group">The group to compute in.</param>
    /// <param name="ephemeral">The pinned <c>a</c>.</param>
    /// <returns>The new session.</returns>
    public static SrpClientSession WithFixedEphemeral(SrpGroup group, BigInteger ephemeral)
    {
        ArgumentNullException.ThrowIfNull(group);
        return new SrpClientSession(group, ephemeral);
    }

    /// <summary>
    /// Completes the exchange: <c>S</c>, <c>K</c>, <c>M1</c> and the <c>M2</c> the server
    /// must return.
    /// </summary>
    /// <param name="identity">
    /// The identity from the challenge response, never what the user typed
    /// (&#167;23.3 rule 2).
    /// </param>
    /// <param name="saltHex">The <c>salt</c> field of the challenge response.</param>
    /// <param name="serverPublicHex">The <c>b_pub</c> field of the challenge response.</param>
    /// <param name="x">The KDF output from <see cref="SrpMath.DeriveX"/>.</param>
    /// <returns>The proof pair.</returns>
    /// <exception cref="NetworkError">
    /// <c>B mod N == 0</c>, <c>u</c> would be zero, or a hex field is malformed.
    /// </exception>
    public SrpProofs Finish(string identity, string saltHex, string serverPublicHex, byte[] x)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(x);

        byte[] salt = SrpMath.FromHex(saltHex, "salt");
        BigInteger modulus = Group.Modulus;
        BigInteger serverPublic = SrpMath.ToPositive(SrpMath.FromHex(serverPublicHex, "b_pub"));

        // §23.3 rule 5. B ≡ 0 is the classic SRP break: S becomes predictable and the exchange
        // would authenticate against a server that never knew the verifier. That is a broken
        // or hostile server, not a wrong password.
        if (serverPublic % modulus == BigInteger.Zero)
        {
            throw NetworkError.FromMessage("SRP: the server sent an invalid public value (B mod N == 0)");
        }

        byte[] paddedA = SrpMath.FromHex(ClientPublic, "client_public");
        byte[] paddedB = SrpMath.Pad(serverPublic, Group.ByteLength);

        // u = H(PAD(A) | PAD(B))
        BigInteger u = SrpMath.HashToInt(paddedA, paddedB);
        if (u == BigInteger.Zero)
        {
            throw NetworkError.FromMessage("SRP: the server's parameters produce u == 0");
        }

        BigInteger xInt = SrpMath.ToPositive(x) % modulus;
        BigInteger k = SrpMath.Multiplier(Group);

        // S = (B - k*g^x)^(a + u*x) mod N
        BigInteger kgx = k * BigInteger.ModPow(Group.Generator, xInt, modulus) % modulus;
        // .NET's % keeps the dividend's sign, and B - k*g^x is routinely negative; without
        // the explicit lift the exponentiation would run on a negative base.
        BigInteger difference = (serverPublic % modulus) - kgx;
        BigInteger baseValue = difference < BigInteger.Zero ? difference + modulus : difference;
        BigInteger sharedSecret = BigInteger.ModPow(baseValue, _ephemeral + (u * xInt), modulus);

        byte[] paddedS = SrpMath.Pad(sharedSecret, Group.ByteLength);
        byte[] sessionKey = SrpMath.Hash(paddedS);
        try
        {
            // M1 = H(H(N) XOR H(PAD(g)) | H(I) | s | PAD(A) | PAD(B) | K)
            byte[] hn = SrpMath.Hash(SrpMath.Pad(modulus, Group.ByteLength));
            byte[] hg = SrpMath.Hash(SrpMath.Pad(Group.Generator, Group.ByteLength));
            var hxor = new byte[hn.Length];
            for (int i = 0; i < hn.Length; i++)
            {
                hxor[i] = (byte)(hn[i] ^ hg[i]);
            }

            byte[] hi = SrpMath.Hash(Encoding.UTF8.GetBytes(identity));
            byte[] m1 = SrpMath.Hash(hxor, hi, salt, paddedA, paddedB, sessionKey);

            // M2 = H(PAD(A) | M1 | K)
            byte[] m2 = SrpMath.Hash(paddedA, m1, sessionKey);
            return new SrpProofs(SrpMath.ToHex(m1), SrpMath.ToHex(m2));
        }
        finally
        {
            // §23.3 rule 8: clear what can be cleared.
            CryptographicOperations.ZeroMemory(paddedS);
            CryptographicOperations.ZeroMemory(sessionKey);
        }
    }
}
