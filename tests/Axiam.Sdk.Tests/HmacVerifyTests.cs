using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Axiam.Sdk.Amqp;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Proves <see cref="Hmac.Verify"/> reproduces the server's byte-for-byte
/// wire-order canonical JSON HMAC-SHA256 (<c>sdks/CONTRACT.md</c> §8) against
/// the real, Rust-signed <c>Fixtures/amqp_hmac_vectors.json</c> vectors
/// (committed in 21-01, byte-identical to the Java sibling SDK's fixture).
/// </summary>
[Trait("Category", "Fast")]
public class HmacVerifyTests
{
    private static readonly string FixturePath =
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "amqp_hmac_vectors.json");

    private sealed record Vector(string Name, string SigningKeyHex, JsonObject Message, bool ExpectedValid);

    private static List<Vector> LoadVectors()
    {
        string json = File.ReadAllText(FixturePath);
        JsonObject root = JsonNode.Parse(json)!.AsObject();
        JsonArray vectors = root["vectors"]!.AsArray();

        var result = new List<Vector>();
        foreach (JsonNode? v in vectors)
        {
            JsonObject obj = v!.AsObject();
            result.Add(new Vector(
                obj["name"]!.GetValue<string>(),
                obj["signing_key_hex"]!.GetValue<string>(),
                obj["message"]!.AsObject().DeepClone().AsObject(),
                obj["expected_valid"]!.GetValue<bool>()));
        }

        return result;
    }

    /// <summary>
    /// Reconstructs the exact bytes that would arrive over the wire for a
    /// fixture vector's "message" object: compact (non-indented) JSON
    /// preserving the field order the fixture file recorded (Rust struct
    /// declaration order) — the same canonical form <see cref="Hmac.Verify"/>
    /// itself produces internally after removing <c>hmac_signature</c>.
    /// </summary>
    private static byte[] CanonicalBody(JsonObject message) => Encoding.UTF8.GetBytes(message.ToJsonString());

    private static Vector Find(List<Vector> vectors, string name) => vectors.Single(v => v.Name == name);

    [Fact]
    public void AllFixtureVectors_VerifyMatchesExpectedValidity()
    {
        foreach (Vector vector in LoadVectors())
        {
            byte[] key = Convert.FromHexString(vector.SigningKeyHex);
            byte[] body = CanonicalBody(vector.Message);

            bool actual = Hmac.Verify(key, body);

            Assert.True(
                actual == vector.ExpectedValid,
                $"vector '{vector.Name}' expected {vector.ExpectedValid} but Hmac.Verify returned {actual}");
        }
    }

    [Fact]
    public void TamperedSignature_FailsVerification_NonVacuous()
    {
        List<Vector> vectors = LoadVectors();
        Vector valid = Find(vectors, "authz_request_valid");
        Vector tampered = Find(vectors, "authz_request_tampered_action");

        byte[] key = Convert.FromHexString(valid.SigningKeyHex);

        // Confirm the baseline verifies true first — otherwise the tampered
        // assertion below would be vacuously true for the wrong reason.
        Assert.True(Hmac.Verify(key, CanonicalBody(valid.Message)), "baseline vector must verify true");
        Assert.False(Hmac.Verify(key, CanonicalBody(tampered.Message)), "tampered-action vector must verify false");
    }

    [Fact]
    public void WrongKey_FailsVerification_NonVacuous()
    {
        List<Vector> vectors = LoadVectors();
        Vector valid = Find(vectors, "audit_event_valid");
        Vector wrongKey = Find(vectors, "audit_event_wrong_key");

        byte[] correctKey = Convert.FromHexString(valid.SigningKeyHex);
        byte[] incorrectKey = Convert.FromHexString(wrongKey.SigningKeyHex);
        byte[] body = CanonicalBody(valid.Message);

        Assert.True(Hmac.Verify(correctKey, body), "baseline vector must verify true with its own key");
        Assert.False(Hmac.Verify(incorrectKey, body), "same body/signature must verify false under a different key");
    }

    [Fact]
    public void MissingHmacSignature_FailsClosed()
    {
        Vector vector = Find(LoadVectors(), "missing_hmac_signature");
        byte[] key = Convert.FromHexString(vector.SigningKeyHex);

        Assert.False(Hmac.Verify(key, CanonicalBody(vector.Message)));
    }

    [Fact]
    public void NonHexSignature_FailsClosed_WithoutThrowing()
    {
        Vector vector = Find(LoadVectors(), "non_hex_signature");
        byte[] key = Convert.FromHexString(vector.SigningKeyHex);

        Assert.False(Hmac.Verify(key, CanonicalBody(vector.Message)));
    }

    [Fact]
    public void WrongLengthSignature_FailsClosed_WithoutThrowing()
    {
        Vector vector = Find(LoadVectors(), "wrong_length_signature");
        byte[] key = Convert.FromHexString(vector.SigningKeyHex);

        Assert.False(Hmac.Verify(key, CanonicalBody(vector.Message)));
    }

    [Fact]
    public void MalformedInput_NeverThrows_ReturnsFalse()
    {
        byte[] key = { 1, 2, 3, 4 };

        Assert.False(Hmac.Verify(key, Encoding.UTF8.GetBytes("not json at all")));
        Assert.False(Hmac.Verify(key, Array.Empty<byte>()));
        Assert.False(Hmac.Verify(key, Encoding.UTF8.GetBytes("[1,2,3]"))); // valid JSON, not an object
    }

    // ---- #882 (D-5): verify over the RECEIVED bytes, never over a re-serialization -----------------------

    private static readonly byte[] BytesKey = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();

    private static string HexMac(byte[] key, string signedText) =>
        Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(signedText))).ToLowerInvariant();

    /// <summary>The wire form the server writes: the signed bytes with the signature appended as the LAST member.</summary>
    private static byte[] Wire(string signedText, string signatureHex) =>
        Encoding.UTF8.GetBytes(signedText[..^1] + ",\"hmac_signature\":\"" + signatureHex + "\"}");

    /// <summary>
    /// What serde_json writes for a message whose action holds <c>&amp; &lt; &gt; ' +</c>, a non-ASCII character
    /// written raw, a lowercase <c>\u001f</c> escape (serde_json's form for a control character) and a literal
    /// backslash-u sequence. Every one is a place where System.Text.Json's re-serialization differs from the server's.
    /// </summary>
    internal const string SpecialCharsSigned =
        """{"correlation_id":"c1","action":"docs:a&b</\"c\">/'+ \u00e9 \u001f \\u0041 é€","key_version":2,"nonce":"n1","issued_at":"2026-07-10T12:00:00Z"}""";

    [Fact]
    public void AGenuineMessageWithCharactersTheEncodersDisagreeOn_Verifies()
    {
        byte[] body = Wire(SpecialCharsSigned, HexMac(BytesKey, SpecialCharsSigned));

        Assert.True(Hmac.Verify(BytesKey, body));
    }

    [Fact]
    public void ADuplicateKey_IsRefused_EvenWhenTheSignatureWasComputedOverOneOfTheReadings()
    {
        // The wire has `action` twice. A verifier that re-serializes sees one reading (last wins); a handler that parses
        // the same bytes may see the other (first wins). The signature below is over the last-wins reading, so a
        // verifier that parses then re-serializes would accept this body while the handler could read "read".
        const string wireText = """{"correlation_id":"c1","action":"read","action":"delete","key_version":2,"nonce":"n1","issued_at":"2026-07-10T12:00:00Z"}""";
        const string lastWins = """{"correlation_id":"c1","action":"delete","key_version":2,"nonce":"n1","issued_at":"2026-07-10T12:00:00Z"}""";
        byte[] body = Wire(wireText, HexMac(BytesKey, lastWins));

        Assert.False(Hmac.Verify(BytesKey, body));
    }

    [Fact]
    public void ACaseVariantKey_IsRefused_EvenWhenSignedOverTheReceivedBytes()
    {
        const string signed = """{"correlation_id":"c1","action":"read","ACTION":"delete","key_version":2,"nonce":"n1","issued_at":"2026-07-10T12:00:00Z"}""";
        byte[] body = Wire(signed, HexMac(BytesKey, signed));

        Assert.False(Hmac.Verify(BytesKey, body));
    }

    [Fact]
    public void TrailingContentAfterTheObject_IsRefused()
    {
        const string plain = """{"correlation_id":"c1","action":"read","key_version":2,"nonce":"n1","issued_at":"2026-07-10T12:00:00Z"}""";
        byte[] genuine = Wire(plain, HexMac(BytesKey, plain));

        Assert.True(Hmac.Verify(BytesKey, genuine));
        Assert.False(Hmac.Verify(BytesKey, genuine.Concat(Encoding.UTF8.GetBytes("\n")).ToArray()));
        Assert.False(Hmac.Verify(BytesKey, genuine.Concat(Encoding.UTF8.GetBytes(" {}")).ToArray()));
        Assert.False(Hmac.Verify(BytesKey, genuine.Concat(genuine).ToArray()));
    }

    [Fact]
    public void ASignatureThatIsNotTheTrailingMember_IsRefused()
    {
        // The server always writes `hmac_signature` last. A body that carries it elsewhere was not written by the
        // server (or was re-encoded on the way); it is refused rather than repaired by moving the member.
        const string signed = """{"correlation_id":"c1","action":"read","key_version":2,"nonce":"n1","issued_at":"2026-07-10T12:00:00Z"}""";
        string sig = HexMac(BytesKey, signed);
        byte[] body = Encoding.UTF8.GetBytes("{\"hmac_signature\":\"" + sig + "\"," + signed[1..]);

        Assert.False(Hmac.Verify(BytesKey, body));
    }
}
