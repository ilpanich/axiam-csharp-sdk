using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;21.7.2 — DPoP proof verification, all ten checks.
/// </summary>
/// <remarks>
/// Each check gets a negative test, because &#167;21.7.2's whole premise is that a verifier
/// missing one of them still reports success. A suite that only proved a good proof passes
/// would not distinguish this class from returning the thumbprint unconditionally.
/// </remarks>
public class DpopProofTests
{
    private const string Method = "POST";
    private const string Uri = "https://rs.example.com/v1/things";
    private const string Token = "eyJhbGciOiJFZERTQSJ9.e30.sig";

    private static int _jtiSeq;

    private readonly DpopVerifier.InMemoryJtiStore _store = new();
    private readonly Ed25519PrivateKeyParameters _priv;
    private readonly Dictionary<string, object> _jwk;

    /// <summary>Fresh keypair and replay store per test.</summary>
    public DpopProofTests()
    {
        (_priv, _jwk) = NewKey();
    }

    private static (Ed25519PrivateKeyParameters, Dictionary<string, object>) NewKey()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair pair = gen.GenerateKeyPair();
        var priv = (Ed25519PrivateKeyParameters)pair.Private;
        var pub = (Ed25519PublicKeyParameters)pair.Public;

        return (priv, new Dictionary<string, object>
        {
            ["kty"] = "OKP",
            ["crv"] = "Ed25519",
            ["x"] = B64U(pub.GetEncoded()),
        });
    }

    private static string B64U(byte[] raw) =>
        Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static Dictionary<string, object> Claims(Dictionary<string, object?>? overrides = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["htm"] = Method,
            ["htu"] = Uri,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["jti"] = $"jti-{Interlocked.Increment(ref _jtiSeq)}",
            ["ath"] = DpopVerifier.AccessTokenHash(Token),
        };

        if (overrides is not null)
        {
            foreach (KeyValuePair<string, object?> kv in overrides)
            {
                if (kv.Value is null)
                {
                    claims.Remove(kv.Key);
                }
                else
                {
                    claims[kv.Key] = kv.Value;
                }
            }
        }

        return claims;
    }

    private Dictionary<string, object> Header(Dictionary<string, object?>? overrides = null)
    {
        var header = new Dictionary<string, object>
        {
            ["typ"] = "dpop+jwt",
            ["alg"] = "EdDSA",
            ["jwk"] = _jwk,
        };

        if (overrides is not null)
        {
            foreach (KeyValuePair<string, object?> kv in overrides)
            {
                if (kv.Value is null)
                {
                    header.Remove(kv.Key);
                }
                else
                {
                    header[kv.Key] = kv.Value;
                }
            }
        }

        return header;
    }

    /// <summary>
    /// Sign a proof by hand, so a test can put anything at all in the header — including
    /// the private material and bogus <c>alg</c> values a cooperative library would refuse
    /// to emit.
    /// </summary>
    private static string Sign(
        Ed25519PrivateKeyParameters key,
        Dictionary<string, object> header,
        Dictionary<string, object> claims)
    {
        string input = B64U(JsonSerializer.SerializeToUtf8Bytes(header))
            + "." + B64U(JsonSerializer.SerializeToUtf8Bytes(claims));
        byte[] msg = Encoding.ASCII.GetBytes(input);

        var signer = new Ed25519Signer();
        signer.Init(true, key);
        signer.BlockUpdate(msg, 0, msg.Length);

        return input + "." + B64U(signer.GenerateSignature());
    }

    private string GoodProof() => Sign(_priv, Header(), Claims());

    private static DpopVerifier.DpopRequest Request() => new(Method, Uri, Token);

    private static JsonElement Json(object value) =>
        JsonDocument.Parse(JsonSerializer.Serialize(value)).RootElement.Clone();

    // -----------------------------------------------------------------------
    // The happy path
    // -----------------------------------------------------------------------

    /// <summary>A well-formed proof verifies and hands back its thumbprint.</summary>
    [Fact]
    public void WellFormedProofVerifiesAndReturnsThumbprint()
    {
        string jkt = DpopVerifier.VerifyProof(GoodProof(), Request(), _store);

        // Returning the thumbprint rather than true is what lets a guard pass a value
        // onward that could only have come from a verified proof.
        Assert.Equal(DpopVerifier.ThumbprintS256(Json(_jwk)), jkt);
        Assert.Equal(43, jkt.Length);
    }

    /// <summary>Query and fragment come off both sides of the <c>htu</c> comparison.</summary>
    [Fact]
    public void QueryAndFragmentAreStrippedFromBothSides()
    {
        var request = new DpopVerifier.DpopRequest(Method, Uri + "?page=2#frag", Token);

        Assert.Equal(43, DpopVerifier.VerifyProof(GoodProof(), request, _store).Length);
    }

    /// <summary>All three permitted algorithms verify through their own key types.</summary>
    [Fact]
    public void AllThreePermittedAlgorithmsVerify()
    {
        // ES256, from a P-256 key.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters ecParams = ecdsa.ExportParameters(false);
        var ecJwk = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = B64U(ecParams.Q.X!),
            ["y"] = B64U(ecParams.Q.Y!),
        };
        string ecInput = B64U(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["typ"] = "dpop+jwt",
            ["alg"] = "ES256",
            ["jwk"] = ecJwk,
        })) + "." + B64U(JsonSerializer.SerializeToUtf8Bytes(Claims()));
        string ecProof = ecInput + "." + B64U(ecdsa.SignData(
            Encoding.ASCII.GetBytes(ecInput),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        Assert.Equal(
            DpopVerifier.ThumbprintS256(Json(ecJwk)),
            DpopVerifier.VerifyProof(ecProof, Request(), _store));

        // PS256, from an RSA key. RSASSA-PSS, not PKCS#1 v1.5.
        using var rsa = RSA.Create(2048);
        RSAParameters rsaParams = rsa.ExportParameters(false);
        var rsaJwk = new Dictionary<string, object>
        {
            ["kty"] = "RSA",
            ["n"] = B64U(rsaParams.Modulus!),
            ["e"] = B64U(rsaParams.Exponent!),
        };
        string rsaInput = B64U(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["typ"] = "dpop+jwt",
            ["alg"] = "PS256",
            ["jwk"] = rsaJwk,
        })) + "." + B64U(JsonSerializer.SerializeToUtf8Bytes(Claims()));
        string rsaProof = rsaInput + "." + B64U(rsa.SignData(
            Encoding.ASCII.GetBytes(rsaInput),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss));

        Assert.Equal(
            DpopVerifier.ThumbprintS256(Json(rsaJwk)),
            DpopVerifier.VerifyProof(rsaProof, Request(), _store));
    }

    // -----------------------------------------------------------------------
    // One negative test per check
    // -----------------------------------------------------------------------

    /// <summary>
    /// Check 1 — without pinning <c>typ</c>, any other JWT signed by the same key (an
    /// access token, an ID token) is replayable as a proof.
    /// </summary>
    [Fact]
    public void Check1ProofWithoutDpopTypIsRefused()
    {
        string proof = Sign(_priv, Header(new() { ["typ"] = "JWT" }), Claims());

        AuthError e = Assert.Throws<AuthError>(
            () => DpopVerifier.VerifyProof(proof, Request(), _store));
        Assert.Contains("typ", e.Message, StringComparison.Ordinal);
    }

    /// <summary>Check 1 — the <c>typ</c> comparison is case-insensitive.</summary>
    [Fact]
    public void Check1TypComparisonIsCaseInsensitive()
    {
        string proof = Sign(_priv, Header(new() { ["typ"] = "DPoP+JWT" }), Claims());

        Assert.Equal(43, DpopVerifier.VerifyProof(proof, Request(), _store).Length);
    }

    /// <summary>
    /// Check 2 — the public-key-as-HMAC-secret forgery, run for real.
    /// </summary>
    /// <remarks>
    /// The attacker holds no private key. They take the <i>public</i> key out of a proof
    /// they observed, use its raw bytes as an HMAC secret, sign a proof of their own with
    /// HS256, and embed the same public jwk. A verifier that reads <c>alg</c> from the
    /// header computes HMAC with that public key, gets a match, and reports success — the
    /// signature is valid, just not proof of anything. This class has no HMAC branch at
    /// all, so the forgery has nothing to verify against.
    /// </remarks>
    [Fact]
    public void Check2PublicKeyAsHmacSecretForgeryIsRefused()
    {
        byte[] publicBytes = ((Ed25519PublicKeyParameters)_priv.GeneratePublicKey()).GetEncoded();
        string input = B64U(JsonSerializer.SerializeToUtf8Bytes(Header(new() { ["alg"] = "HS256" })))
            + "." + B64U(JsonSerializer.SerializeToUtf8Bytes(Claims()));

        using var hmac = new HMACSHA256(publicBytes);
        string forged = input + "." + B64U(hmac.ComputeHash(Encoding.ASCII.GetBytes(input)));

        Assert.Throws<AuthError>(() => DpopVerifier.VerifyProof(forged, Request(), _store));
    }

    /// <summary>Check 2 — a key type outside the three permitted algorithms is refused.</summary>
    [Fact]
    public void Check2UnpermittedKeyTypeIsRefused()
    {
        var bogus = new Dictionary<string, object>
        {
            ["kty"] = "EC",
            ["crv"] = "P-521",
            ["x"] = "AA",
            ["y"] = "AA",
        };
        string proof = Sign(_priv, Header(new() { ["jwk"] = bogus }), Claims());

        AuthError e = Assert.Throws<AuthError>(
            () => DpopVerifier.VerifyProof(proof, Request(), _store));
        Assert.Contains("not permitted", e.Message, StringComparison.Ordinal);
    }

    /// <summary>Check 3 — a proof with no embedded <c>jwk</c> is refused.</summary>
    [Fact]
    public void Check3ProofWithNoJwkIsRefused()
    {
        string proof = Sign(_priv, Header(new() { ["jwk"] = null }), Claims());

        AuthError e = Assert.Throws<AuthError>(
            () => DpopVerifier.VerifyProof(proof, Request(), _store));
        Assert.Contains("jwk", e.Message, StringComparison.Ordinal);
    }

    /// <summary>Check 3 — a proof signed by a different key than the one it embeds.</summary>
    [Fact]
    public void Check3ForeignSignatureIsRefused()
    {
        (Ed25519PrivateKeyParameters other, _) = NewKey();
        string forged = Sign(other, Header(), Claims());

        AuthError e = Assert.Throws<AuthError>(
            () => DpopVerifier.VerifyProof(forged, Request(), _store));
        Assert.Contains("signature", e.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Check 4 — RFC 9449 &#167;4.3 private key material, tested against the RAW header
    /// JSON because many JWK libraries silently drop these members when parsing into a
    /// public-key type; the check would then pass because the library hid the evidence.
    /// </summary>
    [Fact]
    public void Check4PrivateKeyMaterialIsRefused()
    {
        foreach (string member in new[] { "d", "p", "q", "dp", "dq", "qi", "oth", "k" })
        {
            var leaky = new Dictionary<string, object>(_jwk) { [member] = "c2VjcmV0" };
            string proof = Sign(_priv, Header(new() { ["jwk"] = leaky }), Claims());

            AuthError e = Assert.Throws<AuthError>(
                () => DpopVerifier.VerifyProof(proof, Request(), _store));
            Assert.Contains("private key material", e.Message, StringComparison.Ordinal);
        }
    }

    /// <summary>Check 5 — a proof minted for another HTTP method is refused.</summary>
    [Fact]
    public void Check5ProofForAnotherMethodIsRefused()
    {
        string proof = Sign(_priv, Header(), Claims(new() { ["htm"] = "GET" }));

        AuthError e = Assert.Throws<AuthError>(
            () => DpopVerifier.VerifyProof(proof, Request(), _store));
        Assert.Contains("htm", e.Message, StringComparison.Ordinal);
    }

    /// <summary>Check 6 — a proof minted for another URI is refused.</summary>
    [Fact]
    public void Check6ProofForAnotherUriIsRefused()
    {
        string proof = Sign(
            _priv, Header(), Claims(new() { ["htu"] = "https://rs.example.com/v1/other" }));

        AuthError e = Assert.Throws<AuthError>(
            () => DpopVerifier.VerifyProof(proof, Request(), _store));
        Assert.Contains("htu", e.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Check 6 — <c>htu</c> is compared without normalisation. A normalising comparison is
    /// where two unequal URIs become equal; only query and fragment come off, and case,
    /// default ports and trailing slashes are left exactly as they are.
    /// </summary>
    [Fact]
    public void Check6HtuIsComparedWithoutNormalisation()
    {
        Assert.Equal("https://a.example/p", DpopVerifier.CanonicalHtu("https://a.example/p?q=1#f"));
        Assert.NotEqual(
            DpopVerifier.CanonicalHtu("https://A.example/P"),
            DpopVerifier.CanonicalHtu("https://a.example/p"));
        Assert.NotEqual(
            DpopVerifier.CanonicalHtu("https://a.example:443/p"),
            DpopVerifier.CanonicalHtu("https://a.example/p"));
        Assert.NotEqual(
            DpopVerifier.CanonicalHtu("https://a.example/p/"),
            DpopVerifier.CanonicalHtu("https://a.example/p"));
    }

    /// <summary>
    /// Check 7 — both directions. A proof from the future is as suspect as a stale one: it
    /// is how a one-sided skew allowance becomes a long-lived proof.
    /// </summary>
    [Fact]
    public void Check7StaleOrFutureProofIsRefused()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        foreach (int offset in new[] { -65, 65 })
        {
            string proof = Sign(
                _priv, Header(), Claims(new() { ["iat"] = now.ToUnixTimeSeconds() + offset }));
            var request = new DpopVerifier.DpopRequest(
                Method, Uri, Token, null, DpopVerifier.IatLeeway, now);

            AuthError e = Assert.Throws<AuthError>(
                () => DpopVerifier.VerifyProof(proof, request, _store));
            Assert.Contains("freshness window", e.Message, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Check 8 — freshness bounds the window; the <c>jti</c> guard is what makes the window
    /// unusable. Without this the same proof works repeatedly for a full minute.
    /// </summary>
    [Fact]
    public void Check8ReplayedProofIsRefused()
    {
        string proof = GoodProof();
        DpopVerifier.VerifyProof(proof, Request(), _store);

        AuthError e = Assert.Throws<AuthError>(
            () => DpopVerifier.VerifyProof(proof, Request(), _store));
        Assert.Contains("replay", e.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Check 8 — the <c>jti</c> claim is a mutation, so it runs last. Claiming it earlier
    /// would let an attacker burn arbitrary <c>jti</c> values out of the store using proofs
    /// that were never going to verify, turning the replay guard into a denial-of-service
    /// surface against legitimate proofs.
    /// </summary>
    [Fact]
    public void Check8JtiIsClaimedOnlyAfterEveryOtherCheckPasses()
    {
        string doomed = Sign(
            _priv, Header(), Claims(new() { ["htm"] = "GET", ["jti"] = "precious" }));

        Assert.Throws<AuthError>(() => DpopVerifier.VerifyProof(doomed, Request(), _store));

        Assert.True(
            _store.Claim("precious", DateTimeOffset.UtcNow.AddMinutes(1)),
            "a failed proof must not burn its jti");
    }

    /// <summary>
    /// Check 9 — without <c>ath</c>, a proof captured on one request can be re-aimed at a
    /// different token held by the same key.
    /// </summary>
    [Fact]
    public void Check9ProofAimedAtAnotherTokenIsRefused()
    {
        string proof = Sign(
            _priv,
            Header(),
            Claims(new() { ["ath"] = DpopVerifier.AccessTokenHash("some.other.token") }));

        AuthError e = Assert.Throws<AuthError>(
            () => DpopVerifier.VerifyProof(proof, Request(), _store));
        Assert.Contains("ath", e.Message, StringComparison.Ordinal);
    }

    /// <summary>Check 9 — a proof carrying no <c>ath</c> at all is refused.</summary>
    [Fact]
    public void Check9ProofWithNoAthIsRefused()
    {
        string proof = Sign(_priv, Header(), Claims(new() { ["ath"] = null }));

        AuthError e = Assert.Throws<AuthError>(
            () => DpopVerifier.VerifyProof(proof, Request(), _store));
        Assert.Contains("ath", e.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Check 10 — the step that ties the proof to the token; the other nine are what make
    /// the proof mean anything.
    /// </summary>
    [Fact]
    public void Check10ProofByTheWrongKeyIsRefused()
    {
        (_, Dictionary<string, object> otherJwk) = NewKey();
        var request = new DpopVerifier.DpopRequest(
            Method, Uri, Token, DpopVerifier.ThumbprintS256(Json(otherJwk)));

        AuthError e = Assert.Throws<AuthError>(
            () => DpopVerifier.VerifyProof(GoodProof(), request, _store));
        Assert.Contains("cnf.jkt", e.Message, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // Thumbprint and framing
    // -----------------------------------------------------------------------

    /// <summary>
    /// The RFC 7638 appendix A worked example. A thumbprint implementation that is
    /// self-consistent but wrong agrees with itself on every round trip, so the only useful
    /// test is against a published vector.
    /// </summary>
    [Fact]
    public void ThumbprintMatchesRfc7638AppendixA()
    {
        JsonElement rsa = JsonDocument.Parse("""
            {"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}
            """).RootElement;

        Assert.Equal("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", DpopVerifier.ThumbprintS256(rsa));
    }

    /// <summary>The RFC 8037 appendix A.3 Ed25519 thumbprint vector.</summary>
    [Fact]
    public void ThumbprintMatchesRfc8037Ed25519Vector()
    {
        JsonElement okp = JsonDocument.Parse("""
            {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
            """).RootElement;

        Assert.Equal("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", DpopVerifier.ThumbprintS256(okp));
    }

    /// <summary>
    /// <c>kid</c>/<c>use</c>/<c>alg</c>/<c>x5c</c> are excluded by RFC 7638 — which is
    /// exactly what makes the thumbprint stable across two encodings of the same key.
    /// </summary>
    [Fact]
    public void ThumbprintIgnoresMembersOutsideTheRfc7638Set()
    {
        var decorated = new Dictionary<string, object>(_jwk)
        {
            ["kid"] = "abc",
            ["use"] = "sig",
            ["alg"] = "EdDSA",
        };

        Assert.Equal(
            DpopVerifier.ThumbprintS256(Json(_jwk)),
            DpopVerifier.ThumbprintS256(Json(decorated)));
    }

    /// <summary>
    /// RFC 9449 &#167;4.2 makes exactly one proof the rule. Rejecting beats picking the
    /// first, which is how a verifier and a downstream parser end up reading different
    /// proofs.
    /// </summary>
    [Fact]
    public void HeaderCarryingTwoProofsIsRefused()
    {
        string proof = GoodProof();

        AuthError e = Assert.Throws<AuthError>(
            () => DpopVerifier.VerifyProof($"{proof},{proof}", Request(), _store));
        Assert.Contains("exactly one proof", e.Message, StringComparison.Ordinal);
    }

    /// <summary>Malformed input fails closed as an AuthError rather than some other type.</summary>
    [Fact]
    public void MalformedProofsAreRefused()
    {
        foreach (string junk in new[] { "", "not-a-jwt", "a.b", "a.b.c.d", "!!!.###.$$$" })
        {
            Assert.Throws<AuthError>(() => DpopVerifier.VerifyProof(junk, Request(), _store));
        }
    }
}
