using System;
using System.Security.Cryptography;
using System.Text;

namespace Axiam.Sdk.Amqp;

/// <summary>
/// HMAC-SHA256 verify-before-handler primitive for inbound AMQP messages
/// (<c>sdks/CONTRACT.md</c> §8, D-11).
///
/// <para>
/// <b>The signature is checked over the received bytes, never over a re-serialization.</b> The canonical Rust
/// signer (<c>crates/axiam-amqp/src/messages.rs</c>, <c>split_trailing_signature</c> on the verifying side) signs the
/// <c>serde_json</c> compact serialization of the message with <c>hmac_signature</c> absent and then appends
/// <c>,"hmac_signature":"&lt;hex&gt;"</c> as the LAST member. This class cuts that trailing member out of the
/// delivery body and HMACs the remaining bytes exactly as they arrived, so the result does not depend on how any
/// JSON library in this process would print what it parsed (<c>System.Text.Json</c> escapes <c>&amp; &lt; &gt; '</c>
/// and non-ASCII text, and writes <c>\u001F</c> where serde_json writes <c>\u001f</c>: a genuine message whose
/// fields hold them failed verification when the body was re-serialized).
/// </para>
///
/// <para>
/// <b>What is verified is what the handler reads (audit C2).</b> The consumer hands its handler the very bytes
/// that were verified. To make that equivalence hold, a body is refused unless it is one JSON object with
/// unambiguous keys (no key twice at any depth, no two top-level keys differing only by case, nothing after the
/// closing brace) and ends in the trailing signature member: the one reading of the signed bytes is then the only
/// reading any parser can take.
/// </para>
/// </summary>
public static class Hmac
{
    private static readonly byte[] SignatureMember = Encoding.ASCII.GetBytes(",\"hmac_signature\":\"");

    /// <summary>
    /// Returns <c>true</c> iff <paramref name="body"/> ends in a <c>hmac_signature</c> member whose value is
    /// HMAC-SHA256(<paramref name="signingKey"/>, the body with that trailing member removed), computed via a
    /// constant-time comparison over the bytes as received.
    ///
    /// <para>
    /// Never throws: malformed JSON, a body that is not one object with unambiguous keys, a missing, null, non-hex or
    /// not-trailing signature, or a wrong-length signature all verify as <c>false</c> — matching §8.3's strict-mode
    /// default that rejects (rather than silently accepts) an unparseable or absent signature.
    /// </para>
    /// </summary>
    /// <param name="signingKey">The per-tenant AMQP HMAC signing secret (§8.1).</param>
    /// <param name="body">The raw AMQP delivery body bytes.</param>
    /// <returns><c>true</c> if the signature is valid, <c>false</c> otherwise.</returns>
    public static bool Verify(byte[] signingKey, byte[] body)
    {
        try
        {
            if (AxiamAuthzRequester.HasAmbiguousKeys(body))
            {
                return false; // not one object with unambiguous keys, or content after it
            }

            if (!TrySplitTrailingSignature(body, out byte[]? canonical, out string? signatureHex))
            {
                return false; // §8.3 strict mode: missing, malformed or non-trailing signature = reject
            }

            byte[] expected = Convert.FromHexString(signatureHex!);
            byte[] computed = HMACSHA256.HashData(signingKey, canonical!);

            return computed.Length == expected.Length
                && CryptographicOperations.FixedTimeEquals(computed, expected);
        }
        catch
        {
            // Bad hex / bad key -> reject, never throw. Attacker-controlled input must never crash the consumer.
            return false;
        }
    }

    /// <summary>
    /// Splits <paramref name="body"/> into the bytes its HMAC covers and the signature: the body with its trailing
    /// <c>,"hmac_signature":"&lt;hex&gt;"</c> member removed (closed with <c>}</c>), and the hex. <c>false</c> when the
    /// body does not end in exactly that member with a non-empty hex value.
    /// </summary>
    private static bool TrySplitTrailingSignature(byte[] body, out byte[]? canonical, out string? signatureHex)
    {
        canonical = null;
        signatureHex = null;

        ReadOnlySpan<byte> raw = body;
        int start = raw.LastIndexOf(SignatureMember);
        if (start < 0)
        {
            return false;
        }

        ReadOnlySpan<byte> rest = raw[(start + SignatureMember.Length)..];
        int end = rest.IndexOf((byte)'"');
        if (end <= 0 || !rest[end..].SequenceEqual("\"}"u8))
        {
            return false; // empty value, or something other than `"}` follows it
        }

        ReadOnlySpan<byte> hex = rest[..end];
        foreach (byte b in hex)
        {
            bool isHex = b is >= (byte)'0' and <= (byte)'9' or >= (byte)'a' and <= (byte)'f' or >= (byte)'A' and <= (byte)'F';
            if (!isHex)
            {
                return false;
            }
        }

        signatureHex = Encoding.ASCII.GetString(hex);
        canonical = new byte[start + 1];
        raw[..start].CopyTo(canonical);
        canonical[start] = (byte)'}';
        return true;
    }
}
