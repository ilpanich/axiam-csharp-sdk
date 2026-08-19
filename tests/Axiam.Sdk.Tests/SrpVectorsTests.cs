using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Core;
using Axiam.Sdk.Srp;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;23.7 conformance for the SRP-6a client.
/// </summary>
/// <remarks>
/// <para>
/// <c>srp-test-vectors.json</c> is generated from the AXIAM server implementation and vendored
/// into every SDK. Eleven independent SRP implementations do not interoperate by accident;
/// this is the file that says whether this one does.
/// </para>
/// <para>
/// &#167;23.7 rule 1 requires every intermediate to be reproduced, not only the final proof —
/// an SDK that gets <c>u</c> wrong should find out at <c>u</c> rather than at "login sometimes
/// fails".
/// </para>
/// </remarks>
[Trait("Category", "Fast")]
public class SrpVectorsTests
{
    /// <summary>One vector from the vendored fixture.</summary>
    public sealed record Vector(
        string Group,
        string Identity,
        string Salt,
        string X,
        string K,
        string Verifier,
        string APriv,
        string APub,
        string BPriv,
        string BPub,
        string U,
        string SessionSecret,
        string SessionKey,
        string ClientProof,
        string ServerProof);

    /// <summary>
    /// Walks up from the test assembly's directory to find the vendored fixture, so this does
    /// not encode how deep in the build output the tests happen to run.
    /// </summary>
    public static IReadOnlyList<Vector> Vectors { get; } = LoadVectors();

    private static IReadOnlyList<Vector> LoadVectors()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, "srp-test-vectors.json");
            if (File.Exists(candidate))
            {
                using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(candidate));
                var vectors = new List<Vector>();
                foreach (JsonElement v in doc.RootElement.GetProperty("vectors").EnumerateArray())
                {
                    vectors.Add(new Vector(
                        Str(v, "group"), Str(v, "identity"), Str(v, "salt"), Str(v, "x"), Str(v, "k"),
                        Str(v, "verifier"), Str(v, "a_priv"), Str(v, "a_pub"), Str(v, "b_priv"),
                        Str(v, "b_pub"), Str(v, "u"), Str(v, "session_secret"), Str(v, "session_key"),
                        Str(v, "client_proof"), Str(v, "server_proof")));
                }

                return vectors;
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException("srp-test-vectors.json not found in any parent directory");
    }

    private static string Str(JsonElement element, string name) => element.GetProperty(name).GetString()!;

    /// <summary>xUnit member data: one case per vector.</summary>
    public static TheoryData<Vector> AllVectors
    {
        get
        {
            var data = new TheoryData<Vector>();
            foreach (Vector v in Vectors)
            {
                data.Add(v);
            }

            return data;
        }
    }

    /// <summary>xUnit member data: one case per embedded group.</summary>
    public static TheoryData<string> AllGroups
    {
        get
        {
            var data = new TheoryData<string>();
            foreach (SrpGroup g in SrpGroup.All)
            {
                data.Add(g.WireName);
            }

            return data;
        }
    }

    private static BigInteger HexInt(string hex) =>
        BigInteger.Parse("0" + hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    // -----------------------------------------------------------------------
    // §23.7 rule 4 — group constants
    // -----------------------------------------------------------------------

    /// <summary>
    /// A transcription slip in a modulus is a silent, total break: client and server would
    /// still agree with each other while the discrete-log hardness the protocol rests on
    /// quietly vanished. A round-trip test cannot catch it, because both sides share the same
    /// wrong constant.
    /// </summary>
    [Theory]
    [MemberData(nameof(AllGroups))]
    public void EveryGroupIsASafePrimeOfTheAdvertisedWidth(string wireName)
    {
        SrpGroup group = SrpGroup.FromWire(wireName);
        BigInteger n = group.Modulus;

        Assert.True(n.Sign > 0, "the modulus parsed as negative — the sign-byte guard is missing");
        Assert.Equal(group.ByteLength * 8, (int)n.GetBitLength());
        Assert.True(IsProbablePrime(n), $"{wireName}: modulus is not prime");

        // A safe prime: N = 2q + 1 with q prime.
        BigInteger q = (n - BigInteger.One) >> 1;
        Assert.True(IsProbablePrime(q), $"{wireName}: (N-1)/2 is not prime — not a safe prime");

        // g generates the order-q subgroup iff g^q == N-1 for a safe prime.
        Assert.Equal(n - BigInteger.One, BigInteger.ModPow(group.Generator, q, n));
    }

    /// <summary>Miller-Rabin with fixed bases — deterministic, and strong at these sizes.</summary>
    private static bool IsProbablePrime(BigInteger n)
    {
        int[] bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
        if (n < 2)
        {
            return false;
        }

        foreach (int p in bases)
        {
            if (n == p)
            {
                return true;
            }

            if (n % p == 0)
            {
                return false;
            }
        }

        BigInteger d = n - 1;
        int r = 0;
        while (d.IsEven)
        {
            d >>= 1;
            r++;
        }

        foreach (int a in bases)
        {
            BigInteger x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1)
            {
                continue;
            }

            bool passed = false;
            for (int i = 1; i < r; i++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1)
                {
                    passed = true;
                    break;
                }
            }

            if (!passed)
            {
                return false;
            }
        }

        return true;
    }

    [Fact]
    public void AnUnrecognisedGroupIsRefusedRatherThanGuessed()
    {
        // Guessing would mean computing in a group whose safety this SDK has not verified —
        // potentially one whose discrete log the server knows. NetworkError, not AuthError: a
        // client capability gap reported as an auth failure would send a user to reset a
        // working password.
        NetworkError error = Assert.Throws<NetworkError>(() => SrpGroup.FromWire("rfc5054_1024"));
        Assert.Contains("rfc5054_1024", error.Message, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 1 — PAD()
    // -----------------------------------------------------------------------

    [Fact]
    public void PadLeftPadsToTheGroupWidth()
    {
        Assert.Equal("00000001", SrpMath.ToHex(SrpMath.Pad(BigInteger.One, 4)));
        Assert.Equal("0102", SrpMath.ToHex(SrpMath.Pad(new BigInteger(0x0102), 2)));
    }

    // -----------------------------------------------------------------------
    // §23.7 rules 1–3 — the vectors
    // -----------------------------------------------------------------------

    /// <summary>
    /// Guards the fixture itself: if these stop holding, everything below silently stops
    /// testing the two things it was built to test.
    /// </summary>
    [Fact]
    public void TheFixturesCoverTheCasesTheyExistFor()
    {
        Assert.NotEmpty(Vectors);
        Assert.Contains(Vectors, v => v.Salt.StartsWith("00", StringComparison.Ordinal));
        Assert.Contains(Vectors, v => v.X.StartsWith("00", StringComparison.Ordinal));
        Assert.Contains(Vectors, v => v.Identity.Any(c => c > 0x7f));
        foreach (SrpGroup g in SrpGroup.All)
        {
            Assert.Contains(Vectors, v => v.Group == g.WireName);
        }
    }

    [Theory]
    [MemberData(nameof(AllVectors))]
    public void EveryVectorReproducesEveryIntermediate(Vector v)
    {
        SrpGroup group = SrpGroup.FromWire(v.Group);
        BigInteger n = group.Modulus;
        BigInteger x = HexInt(v.X) % n;

        // k = H(N | PAD(g))
        Assert.Equal(v.K, SrpMath.ToHex(SrpMath.Pad(SrpMath.Multiplier(group), 32)));

        // v = g^x mod N
        Assert.Equal(v.Verifier, SrpMath.ComputeVerifier(group, Convert.FromHexString(v.X)));

        // A = g^a mod N
        BigInteger a = HexInt(v.APriv);
        BigInteger aPub = BigInteger.ModPow(group.Generator, a, n);
        Assert.Equal(v.APub, SrpMath.ToHex(SrpMath.Pad(aPub, group.ByteLength)));

        // B = (k*v + g^b) mod N
        BigInteger b = HexInt(v.BPriv);
        BigInteger verifier = BigInteger.ModPow(group.Generator, x, n);
        BigInteger bPub = ((SrpMath.Multiplier(group) * verifier) + BigInteger.ModPow(group.Generator, b, n)) % n;
        Assert.Equal(v.BPub, SrpMath.ToHex(SrpMath.Pad(bPub, group.ByteLength)));

        // u = H(PAD(A) | PAD(B))
        BigInteger u = SrpMath.HashToInt(SrpMath.Pad(aPub, group.ByteLength), SrpMath.Pad(bPub, group.ByteLength));
        Assert.Equal(v.U, SrpMath.ToHex(SrpMath.Pad(u, 32)));

        // S and K, from the client's derivation.
        BigInteger kgx = SrpMath.Multiplier(group) * BigInteger.ModPow(group.Generator, x, n) % n;
        BigInteger difference = bPub - kgx;
        BigInteger baseValue = difference < BigInteger.Zero ? difference + n : difference;
        BigInteger s = BigInteger.ModPow(baseValue, a + (u * x), n);
        Assert.Equal(v.SessionSecret, SrpMath.ToHex(SrpMath.Pad(s, group.ByteLength)));
        Assert.Equal(v.SessionKey, SrpMath.ToHex(SrpMath.Hash(SrpMath.Pad(s, group.ByteLength))));
    }

    /// <summary>
    /// Drives the real session rather than the helpers, with <c>a</c> pinned to the vector's
    /// value — otherwise this would only test the internals.
    /// </summary>
    [Theory]
    [MemberData(nameof(AllVectors))]
    public void EveryVectorProducesTheContractProofsThroughThePublicApi(Vector v)
    {
        SrpGroup group = SrpGroup.FromWire(v.Group);
        SrpClientSession session = SrpClientSession.WithFixedEphemeral(group, HexInt(v.APriv));
        Assert.Equal(v.APub, session.ClientPublic);

        SrpProofs proofs = session.Finish(v.Identity, v.Salt, v.BPub, Convert.FromHexString(v.X));
        Assert.Equal(v.ClientProof, proofs.ClientProof);
        Assert.Equal(v.ServerProof, proofs.ExpectedServerProof);
    }

    // -----------------------------------------------------------------------
    // §23.3 protocol refusals
    // -----------------------------------------------------------------------

    /// <summary>
    /// &#167;23.7 rule 6, with no network round trip. The classic SRP break: a client that
    /// accepts <c>B &#8801; 0</c> derives a predictable <c>S</c> and would authenticate
    /// against a server that never knew the verifier.
    /// </summary>
    [Fact]
    public void AServerPublicValueCongruentToZeroIsRefused()
    {
        SrpGroup group = SrpGroup.FromWire("rfc5054_2048");
        SrpClientSession session = SrpClientSession.Begin(group);

        NetworkError error = Assert.Throws<NetworkError>(() => session.Finish(
            "alice", new string('0', 64), new string('0', group.ByteLength * 2), new byte[32]));
        Assert.Contains("invalid public value", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryExchangeUsesAFreshClientEphemeral()
    {
        SrpGroup group = SrpGroup.FromWire("rfc5054_2048");
        Assert.NotEqual(SrpClientSession.Begin(group).ClientPublic, SrpClientSession.Begin(group).ClientPublic);
    }

    [Fact]
    public void AnUnknownKdfIsRefusedRatherThanSubstituted()
    {
        // Substituting the other KDF derives a different x and surfaces as "invalid password"
        // — the single most misleading failure available.
        NetworkError error = Assert.Throws<NetworkError>(() => SrpMath.DeriveX(
            "alice", "pw".ToCharArray(), new byte[32], new SrpKdfParams("scrypt", 1)));
        Assert.Contains("scrypt", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AMalformedHexFieldIsRefusedRatherThanSilentlyTruncated()
    {
        Assert.Throws<NetworkError>(() => SrpMath.FromHex("zz", "salt"));
        Assert.Throws<NetworkError>(() => SrpMath.FromHex("abc", "salt"));
    }

    // -----------------------------------------------------------------------
    // KDF
    // -----------------------------------------------------------------------

    /// <summary>
    /// Every one of these must change the output, or a verifier would be replayable against a
    /// different account or a different salt.
    /// </summary>
    [Fact]
    public void TheKdfBindsIdentityPasswordAndSalt()
    {
        var parameters = new SrpKdfParams(SrpKdfParams.Pbkdf2Sha256, 1000);
        byte[] salt = Enumerable.Repeat((byte)0x0a, 32).ToArray();
        string Base() => SrpMath.ToHex(SrpMath.DeriveX("alice", "pw".ToCharArray(), salt, parameters));

        Assert.Equal(32, SrpMath.DeriveX("alice", "pw".ToCharArray(), salt, parameters).Length);
        Assert.Equal(Base(), Base());
        Assert.NotEqual(Base(), SrpMath.ToHex(SrpMath.DeriveX("bob", "pw".ToCharArray(), salt, parameters)));
        Assert.NotEqual(Base(), SrpMath.ToHex(SrpMath.DeriveX("alice", "pw2".ToCharArray(), salt, parameters)));
        Assert.NotEqual(
            Base(),
            SrpMath.ToHex(SrpMath.DeriveX(
                "alice", "pw".ToCharArray(), Enumerable.Repeat((byte)0x0b, 32).ToArray(), parameters)));
    }

    /// <summary>
    /// Argon2id is the KDF the server asks for by default. Low memory so the test stays fast;
    /// the code path is identical to the 19 MiB production parameters.
    /// </summary>
    [Fact]
    public void Argon2idRunsAndIsTheDefaultKdf()
    {
        Assert.Equal(32, SrpMath.DeriveX(
            "alice", "pw".ToCharArray(), new byte[32], new SrpKdfParams(SrpKdfParams.Argon2id, 1, 8192, 1)).Length);

        SrpKdfParams defaults = new SrpKdfParams(string.Empty, 0).WithDefaults();
        Assert.Equal(SrpKdfParams.Argon2id, defaults.Kdf);
        Assert.Equal(2, defaults.Iterations);
        Assert.Equal(19456, defaults.MemoryKib);
        Assert.Equal(1, defaults.Parallelism);
        Assert.Equal(600_000, new SrpKdfParams(SrpKdfParams.Pbkdf2Sha256, 0).WithDefaults().Iterations);
    }

    /// <summary>
    /// &#167;23.7 rule 3 pins the UTF-8 encoding of the identity, which is why a non-ASCII
    /// vector exists. Both KDFs must agree, or they would disagree about the same account.
    /// </summary>
    [Fact]
    public void BothKdfsTreatAMangledNonAsciiIdentityAsADifferentAccount()
    {
        byte[] salt = new byte[32];
        foreach (SrpKdfParams parameters in new[]
                 {
                     new SrpKdfParams(SrpKdfParams.Pbkdf2Sha256, 1000),
                     new SrpKdfParams(SrpKdfParams.Argon2id, 1, 8192, 1),
                 })
        {
            Assert.NotEqual(
                SrpMath.ToHex(SrpMath.DeriveX("renée", "pw".ToCharArray(), salt, parameters)),
                SrpMath.ToHex(SrpMath.DeriveX("renÃ©e", "pw".ToCharArray(), salt, parameters)));
        }
    }

    /// <summary>
    /// The password is taken as a <c>char[]</c> precisely so the joined
    /// <c>identity ":" password</c> never becomes an immutable <see cref="string"/>. This
    /// pins that the encoding is nonetheless byte-identical to the obvious string form.
    /// </summary>
    [Fact]
    public void TheCharArrayPathEncodesIdenticallyToTheStringItAvoidsCreating()
    {
        var parameters = new SrpKdfParams(SrpKdfParams.Pbkdf2Sha256, 1000);
        byte[] salt = new byte[32];
        byte[] viaSdk = SrpMath.DeriveX("renée", "pw".ToCharArray(), salt, parameters);
        byte[] viaString = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes("renée:pw"),
            salt,
            1000,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            32);
        Assert.Equal(SrpMath.ToHex(viaString), SrpMath.ToHex(viaSdk));
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 6 — server proof comparison
    // -----------------------------------------------------------------------

    [Fact]
    public void TheServerProofComparisonAcceptsAMatchAndRejectsEverythingElse()
    {
        string proof = Vectors[0].ServerProof;
        Assert.True(SrpMath.VerifyServerProof(proof, proof));
        Assert.False(SrpMath.VerifyServerProof(proof, proof[..^1] + "0"));
        Assert.False(SrpMath.VerifyServerProof(proof, proof[..32]));
        Assert.False(SrpMath.VerifyServerProof(proof, string.Empty));
        Assert.False(SrpMath.VerifyServerProof(proof, null));
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 11 — enrolment salts
    // -----------------------------------------------------------------------

    [Fact]
    public void EnrolmentSaltsAre32FreshBytes()
    {
        // A reused salt would make every verifier in a tenant equally attackable with one
        // precomputation.
        byte[] first = SrpMath.GenerateSalt();
        Assert.Equal(32, first.Length);
        Assert.NotEqual(SrpMath.ToHex(first), SrpMath.ToHex(SrpMath.GenerateSalt()));
    }
}
