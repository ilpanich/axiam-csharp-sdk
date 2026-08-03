using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Webhooks;

/// <summary>
/// Verifies the <c>X-Axiam-Signature</c> HMAC-SHA256 header AXIAM attaches to every webhook
/// delivery (CONTRACT.md &#167;13, T-145). Mirrors the server's signer
/// (<c>crates/axiam-api-rest/src/webhook.rs</c>'s <c>compute_signature_v2</c>): the MAC covers
/// the ASCII string <c>&lt;t&gt;.&lt;raw_body&gt;</c>, keyed with the webhook secret's raw
/// UTF-8 bytes.
/// </summary>
public static class AxiamWebhooks
{
    /// <summary>
    /// The default freshness window (CONTRACT.md &#167;13.2): a signature whose <c>t=</c> is
    /// more than this far in the past OR the future (relative to <paramref
    /// name="timeProvider"/>'s clock — see <see cref="Verify"/>) is rejected.
    /// </summary>
    public static readonly TimeSpan DefaultTolerance = TimeSpan.FromSeconds(300);

    /// <summary>
    /// Verifies a webhook delivery's <c>X-Axiam-Signature</c> header against
    /// <paramref name="body"/> and returns the parsed <see cref="WebhookEvent"/> on success.
    /// </summary>
    /// <param name="secret">
    /// The webhook's plaintext signing secret (CONTRACT.md &#167;7 <see cref="Sensitive{T}"/>).
    /// Its raw UTF-8 bytes are the HMAC key. Wrap a bare string with
    /// <see cref="Sensitive{T}.Wrap"/>.
    /// </param>
    /// <param name="signatureHeader">
    /// The raw, unparsed <c>X-Axiam-Signature</c> header value — <c>t=&lt;unix_seconds&gt;,v1=&lt;hex&gt;</c>,
    /// optionally with multiple <c>v1</c> entries during secret rotation.
    /// </param>
    /// <param name="body">
    /// The <b>exact raw bytes</b> received off the wire, before any JSON parsing. Re-serializing
    /// a parsed body (different key order/whitespace) changes these bytes and breaks the MAC —
    /// callers MUST buffer and pass the untouched request body. In ASP.NET Core this means
    /// enabling <c>HttpRequest.EnableBuffering()</c> (or reading the body stream directly)
    /// before any model binder has had a chance to parse and re-serialize it.
    /// </param>
    /// <param name="tolerance">
    /// The freshness window; <c>null</c> or a non-positive value falls back to
    /// <see cref="DefaultTolerance"/> (300 seconds). Rejects a <c>t=</c> more than this far in
    /// the past OR the future — a two-sided check, so a future-dated timestamp is rejected just
    /// like a stale one (clock-skew abuse).
    /// </param>
    /// <param name="timeProvider">
    /// Test/injection seam for "now"; defaults to <see cref="TimeProvider.System"/>. Pass a
    /// fake <see cref="TimeProvider"/> to deterministically exercise the freshness check.
    /// </param>
    /// <returns>The verified, parsed <see cref="WebhookEvent"/>.</returns>
    /// <exception cref="WebhookVerificationException">
    /// The header is malformed (no <c>v1</c>, more than one <c>t</c>, non-numeric <c>t</c>, or
    /// empty), no supplied <c>v1</c> matches the recomputed MAC, or <c>t</c> falls outside the
    /// freshness tolerance. The exception message is always a fixed, generic reason string —
    /// never the expected signature or the secret (CONTRACT.md &#167;13.3 rule 6).
    /// </exception>
    public static WebhookEvent Verify(
        Sensitive<string> secret,
        string signatureHeader,
        ReadOnlySpan<byte> body,
        TimeSpan? tolerance = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(signatureHeader);

        TimeSpan effectiveTolerance = tolerance is { } t && t > TimeSpan.Zero ? t : DefaultTolerance;
        TimeProvider clock = timeProvider ?? TimeProvider.System;

        // 1-2. Parse the header: exactly one `t`, at least one `v1` (a header with no `v1` is
        // always a failure — never treated as "nothing to check"), `t` must be numeric.
        if (!TryParseHeader(signatureHeader, out string timestampRaw, out List<string> v1Values))
        {
            throw new WebhookVerificationException("Malformed X-Axiam-Signature header.");
        }

        if (!long.TryParse(timestampRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out long timestamp))
        {
            throw new WebhookVerificationException("Malformed X-Axiam-Signature header: non-numeric timestamp.");
        }

        // 3. Recompute HMAC-SHA256(secret, "<t>.<body>") — `<t>` is the EXACT raw text that
        // appeared in the `t=` field (not a reformatted/reparsed integer), matching the bytes
        // the server actually signed.
        byte[] computed = ComputeMac(secret, timestampRaw, body);

        // 4. Constant-time compare against each supplied `v1`, on the DECODED bytes. A failed
        // hex decode fails closed for that candidate (never throws, never short-circuits the
        // remaining candidates). Never `==` on hex strings.
        bool matched = false;
        foreach (string v1 in v1Values)
        {
            byte[] expected;
            try
            {
                expected = Convert.FromHexString(v1);
            }
            catch (FormatException)
            {
                continue; // not valid hex -> this candidate can never match; fail closed for it
            }

            if (computed.Length == expected.Length && CryptographicOperations.FixedTimeEquals(computed, expected))
            {
                matched = true;
                break;
            }
        }

        if (!matched)
        {
            throw new WebhookVerificationException("Webhook signature verification failed.");
        }

        // 5. Freshness — two-sided: reject stale AND future-dated timestamps.
        long nowUnix = clock.GetUtcNow().ToUnixTimeSeconds();
        long ageSeconds = nowUnix - timestamp;
        double toleranceSeconds = effectiveTolerance.TotalSeconds;
        if (ageSeconds > toleranceSeconds || ageSeconds < -toleranceSeconds)
        {
            throw new WebhookVerificationException("Webhook timestamp outside the freshness tolerance window.");
        }

        // 6. Success — return the parsed event. `body` is copied here (not before) since it is
        // only retained once verification has actually succeeded.
        byte[] bodyCopy = body.ToArray();
        (string? eventType, string? deliveryId) = TryParseEnvelope(bodyCopy);
        return new WebhookEvent(timestamp, bodyCopy, eventType, deliveryId);
    }

    /// <summary>
    /// Computes HMAC-SHA256(<paramref name="secret"/>'s raw UTF-8 bytes, ASCII
    /// <c>"&lt;timestampRaw&gt;.&lt;body&gt;"</c>) — the exact construction
    /// <c>crates/axiam-api-rest/src/webhook.rs</c>'s <c>compute_signature_v2</c> uses.
    /// </summary>
    private static byte[] ComputeMac(Sensitive<string> secret, string timestampRaw, ReadOnlySpan<byte> body)
    {
        byte[] secretBytes = Encoding.UTF8.GetBytes(secret.Reveal());
        byte[] timestampBytes = Encoding.ASCII.GetBytes(timestampRaw);

        byte[] signedMessage = new byte[timestampBytes.Length + 1 + body.Length];
        timestampBytes.CopyTo(signedMessage.AsSpan());
        signedMessage[timestampBytes.Length] = (byte)'.';
        body.CopyTo(signedMessage.AsSpan(timestampBytes.Length + 1));

        return HMACSHA256.HashData(secretBytes, signedMessage);
    }

    /// <summary>
    /// Parses the comma-separated <c>key=value</c> pairs of an <c>X-Axiam-Signature</c> header.
    /// Returns <c>false</c> (caller must reject) unless exactly one <c>t</c> and at least one
    /// non-empty <c>v1</c> were found. Unknown keys are ignored for forward compatibility.
    /// </summary>
    private static bool TryParseHeader(string header, out string timestampRaw, out List<string> v1Values)
    {
        timestampRaw = string.Empty;
        v1Values = new List<string>();
        bool hasTimestamp = false;

        foreach (string rawPart in header.Split(','))
        {
            string part = rawPart.Trim();
            if (part.Length == 0)
            {
                continue;
            }

            int eq = part.IndexOf('=');
            if (eq <= 0 || eq == part.Length - 1)
            {
                continue; // not a well-formed key=value pair -> ignore (forward-compat)
            }

            string key = part[..eq].Trim();
            string value = part[(eq + 1)..].Trim();

            if (key.Equals("t", StringComparison.Ordinal))
            {
                if (hasTimestamp || value.Length == 0)
                {
                    return false; // exactly one non-empty `t` is required
                }

                hasTimestamp = true;
                timestampRaw = value;
            }
            else if (key.Equals("v1", StringComparison.Ordinal))
            {
                if (value.Length > 0)
                {
                    v1Values.Add(value);
                }
            }
            // else: unknown/future scheme key -> ignored, forward compat.
        }

        // A header with no `v1` is ALWAYS a failure — never "nothing to check" == success.
        return hasTimestamp && v1Values.Count > 0;
    }

    /// <summary>
    /// Best-effort parse of the verified body's <c>"event"</c>/<c>"id"</c> JSON fields. Never
    /// throws and never affects the verification result — a non-JSON or differently-shaped
    /// body still verifies successfully (only the raw bytes are covered by the MAC), it simply
    /// yields <c>(null, null)</c> here.
    /// </summary>
    private static (string? EventType, string? DeliveryId) TryParseEnvelope(byte[] body)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(body);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return (null, null);
            }

            string? eventType = root.TryGetProperty("event", out JsonElement eventElement)
                                 && eventElement.ValueKind == JsonValueKind.String
                ? eventElement.GetString()
                : null;

            string? deliveryId = root.TryGetProperty("id", out JsonElement idElement)
                                  && idElement.ValueKind == JsonValueKind.String
                ? idElement.GetString()
                : null;

            return (eventType, deliveryId);
        }
        catch (JsonException)
        {
            return (null, null);
        }
    }
}
