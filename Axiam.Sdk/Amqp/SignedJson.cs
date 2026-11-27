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

    /// <summary>Whether the first byte of <paramref name="body"/> is <c>{</c> (CONTRACT.md &#167;8 step 2a). A UTF-8 byte-order
    /// mark, whitespace, or any other prefix is not, and an empty body is not: such a body is refused as malformed and
    /// never stripped or repaired.</summary>
    internal static bool StartsWithObject(ReadOnlySpan<byte> body) => !body.IsEmpty && body[0] == (byte)'{';

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
    /// Whether the top-level members of <paramref name="canonical"/> (the signature cut out) are, in order, exactly the
    /// layout of <paramref name="type"/> (optional members may be absent) and no other member (&#167;8 step 2c). There is
    /// no "matches some signed layout": a message of any other signed shape, however validly signed under the tenant
    /// subkey, is not an event this consumer accepts. Names are compared exactly.
    /// </summary>
    internal static bool MatchesLayout(byte[] canonical, AmqpEventType type)
    {
        List<string>? keys = TopLevelKeys(canonical);
        return keys is not null && Matches(keys, type == AmqpEventType.AuthzRequest ? AuthzRequestLayout : AuditEventLayout);
    }

    /// <summary>
    /// Whether <paramref name="body"/> is exactly one JSON object and nothing else: it tokenizes to the end without an
    /// error (so no trailing content, no invalid UTF-8, no unbounded nesting) and its root is an object. This is
    /// reason position (1) of &#167;8 rule 4 once the first byte has been checked.
    /// </summary>
    internal static bool IsOneJsonObject(ReadOnlySpan<byte> body)
    {
        try
        {
            var reader = new Utf8JsonReader(body, new JsonReaderOptions { MaxDepth = 64 });
            bool first = true;
            while (reader.Read())
            {
                if (first && reader.TokenType != JsonTokenType.StartObject)
                {
                    return false;
                }
                first = false;
            }
            return !first;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Whether the root object of <paramref name="body"/> has a top-level member named
    /// <c>hmac_signature</c>, in any letter case (so a case-variant is a signature member that fails step 2b, never
    /// "unsigned"). Only meaningful for a body that passed <see cref="IsOneJsonObject"/>.</summary>
    internal static bool HasSignatureMember(byte[] body)
    {
        List<string>? keys = TopLevelKeys(body);
        return keys is not null && keys.Exists(k => string.Equals(k, "hmac_signature", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Step 2f's decode of the verified canonical bytes into <paramref name="type"/> (&#167;8 rule 4 position (5)): every
    /// present member has its JSON type (UUIDs and the <c>action</c>/<c>actor_type</c>/<c>outcome</c> strings are
    /// strings, <c>key_version</c> an integer 0&#8211;255, <c>issued_at</c> an RFC 3339 timestamp, <c>nonce</c> a UUID). The
    /// layout has already been checked, so no member is missing or foreign. Never throws.
    /// </summary>
    internal static bool DecodesAs(byte[] canonical, AmqpEventType type)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(canonical, new JsonDocumentOptions { MaxDepth = 64 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            foreach (JsonProperty member in root.EnumerateObject())
            {
                JsonElement v = member.Value;
                bool ok = member.Name switch
                {
                    "correlation_id" or "tenant_id" or "subject_id" or "resource_id" or "actor_id" or "nonce" =>
                        v.ValueKind == JsonValueKind.String && Guid.TryParse(v.GetString(), out _),
                    "action" or "scope" or "actor_type" or "outcome" or "ip_address" => v.ValueKind == JsonValueKind.String,
                    "key_version" => v.ValueKind == JsonValueKind.Number && v.TryGetByte(out _),
                    "issued_at" => v.ValueKind == JsonValueKind.String && IsRfc3339(v.GetString()),
                    "metadata" => true,
                    _ => false,
                };
                if (!ok)
                {
                    return false;
                }
            }
            return type is AmqpEventType.AuthzRequest or AmqpEventType.AuditEvent;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static readonly string[] Rfc3339Formats =
    {
        "yyyy-MM-dd'T'HH:mm:ssK", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFFFK",
    };

    private static bool IsRfc3339(string? text) =>
        text is not null &&
        System.DateTimeOffset.TryParseExact(text, Rfc3339Formats, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.None, out _);

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
