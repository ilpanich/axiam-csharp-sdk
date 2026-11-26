using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace Axiam.Sdk.Amqp;

/// <summary>
/// Structural reads of a signed AMQP message AS RECEIVED (CONTRACT.md &#167;8): the shared basis of
/// <see cref="Hmac.Verify"/>, the consumer's layout check and the requester's response check. Nothing here
/// re-serializes.
/// </summary>
internal static class SignedJson
{
    private static readonly byte[] SignatureMember = Encoding.ASCII.GetBytes(",\"hmac_signature\":\"");

    /// <summary>The members of the signed <c>AuthzRequest</c>, in the server's declaration order (&#167;8 v2); <c>true</c> = optional.</summary>
    private static readonly (string Name, bool Optional)[] AuthzRequestLayout =
    {
        ("correlation_id", false), ("tenant_id", false), ("subject_id", false), ("action", false), ("resource_id", false),
        ("scope", true), ("key_version", false), ("nonce", false), ("issued_at", false),
    };

    /// <summary>The members of the signed <c>AuditEventMessage</c>, in the server's declaration order (&#167;8 v2).</summary>
    private static readonly (string Name, bool Optional)[] AuditEventLayout =
    {
        ("tenant_id", false), ("actor_id", false), ("actor_type", false), ("action", false), ("resource_id", true),
        ("outcome", false), ("ip_address", true), ("metadata", true), ("key_version", false), ("nonce", false), ("issued_at", false),
    };

    /// <summary>
    /// Removes the final <c>,"hmac_signature":"&lt;hex&gt;"</c> member from <paramref name="body"/>, returning the
    /// canonical bytes (the rest, closed with <c>}</c>) and the signature hex. <paramref name="hexLength"/> is the
    /// exact number of hex digits required, or <c>null</c> for any non-empty hex value (the caller's HMAC comparison
    /// then rejects a wrong length). <c>false</c> when the body does not end in exactly that member.
    /// </summary>
    internal static bool TryCutTrailingSignature(byte[] body, int? hexLength, out byte[]? canonical, out string? signatureHex)
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
        if (end <= 0 || !rest[end..].SequenceEqual("\"}"u8) || (hexLength is { } n && end != n))
        {
            return false; // empty or wrong-length value, or something other than `"}` follows it
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

    /// <summary>
    /// Whether the top-level members of <paramref name="canonical"/> (the verified bytes, signature cut out) are, in
    /// order, exactly the <c>AuthzRequest</c> layout or the <c>AuditEventMessage</c> layout (optional members may be
    /// absent). A message of any other signed shape (a cache-invalidation message, say), however validly signed under
    /// the tenant subkey, is not an event this consumer accepts. Names are compared exactly.
    /// </summary>
    internal static bool MatchesSignedLayout(byte[] canonical)
    {
        List<string>? keys = TopLevelKeys(canonical);
        return keys is not null && (Matches(keys, AuthzRequestLayout) || Matches(keys, AuditEventLayout));
    }

    private static bool Matches(List<string> keys, (string Name, bool Optional)[] layout)
    {
        int i = 0;
        foreach ((string name, bool optional) in layout)
        {
            if (i < keys.Count && keys[i] == name)
            {
                i++;
                continue;
            }
            if (!optional)
            {
                return false;
            }
        }
        return i == keys.Count;
    }

    private static List<string>? TopLevelKeys(byte[] json)
    {
        try
        {
            var reader = new Utf8JsonReader(json, new JsonReaderOptions { MaxDepth = 64 });
            var keys = new List<string>();
            int depth = 0;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                    case JsonTokenType.StartArray:
                        depth++;
                        break;
                    case JsonTokenType.EndObject:
                    case JsonTokenType.EndArray:
                        depth--;
                        break;
                    case JsonTokenType.PropertyName when depth == 1:
                        keys.Add(reader.GetString()!);
                        break;
                }
            }
            return keys;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether <paramref name="body"/> is not a JSON object with unambiguous keys: the same key twice at any
    /// depth, or two top-level keys that differ only by case (one decoder reads them as one member and another as
    /// two). Also <c>true</c> for anything that cannot be tokenized, so malformed input is refused here rather than
    /// reaching a lenient decoder.
    /// </summary>
    internal static bool HasAmbiguousKeys(ReadOnlySpan<byte> body)
    {
        try
        {
            var reader = new Utf8JsonReader(body, new JsonReaderOptions { MaxDepth = 64 });
            // One set per open object, null for an open array.
            var stack = new Stack<HashSet<string>?>();
            var topLevelFolded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool sawRoot = false;

            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        sawRoot = true;
                        stack.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;
                    case JsonTokenType.StartArray:
                        if (!sawRoot)
                        {
                            return true; // the root must be an object
                        }
                        stack.Push(null);
                        break;
                    case JsonTokenType.EndObject:
                    case JsonTokenType.EndArray:
                        stack.Pop();
                        break;
                    case JsonTokenType.PropertyName:
                        string name = reader.GetString()!;
                        if (!stack.Peek()!.Add(name))
                        {
                            return true;
                        }
                        if (stack.Count == 1 && !topLevelFolded.Add(name))
                        {
                            return true;
                        }
                        break;
                    default:
                        if (!sawRoot)
                        {
                            return true; // a bare scalar at the root
                        }
                        break;
                }
            }
            return !sawRoot;
        }
        catch (Exception)
        {
            return true;
        }
    }
}
