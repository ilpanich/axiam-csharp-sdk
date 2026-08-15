using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Axiam.Sdk.Reactor;

/// <summary>
/// The reactor wire protocol (<c>sdks/CONTRACT.md</c> &#167;22.1–&#167;22.4): topology
/// names, key derivation, canonicalization, signing and verification.
///
/// <para>
/// <see cref="ReactorServer"/> is built on this class, and this class is public so an
/// integrator on a transport this SDK does not wrap (a different AMQP client, a test
/// harness, a bridge) can satisfy &#167;22 without reimplementing the one rule that is easy
/// to get wrong.
/// </para>
///
/// <para>
/// <b>The canonicalization rule.</b> A reactor body is signed with its
/// <c>hmac_signature</c> field <b>present and set to <c>null</c></b>, in declared field
/// order. That differs from &#167;8's own two message types (<c>AuthzRequest</c>,
/// <c>AuditEventMessage</c>), whose <c>hmac_signature</c> is <em>absent</em> from their
/// canonical bytes — see <see cref="Axiam.Sdk.Amqp.Hmac"/>, which implements that other
/// rule — and it is the single most likely place for an implementation to produce a MAC
/// that will not verify. Everything else is &#167;8 v2 verbatim: the same HKDF-derived
/// per-tenant subkey, the same <c>HMAC-SHA256</c> compared in constant time, the same
/// &#177;300 s freshness window applied in <b>both</b> directions, the same
/// <c>key_version</c> floor of 2.
/// </para>
///
/// <para>
/// Field order, event (server &#8594; reactor): <c>tenant_id</c>, <c>event</c>,
/// <c>correlation_id</c>, <c>payload</c>, <c>timeout_ms</c>, <c>key_version</c>,
/// <c>nonce</c>, <c>issued_at</c>, <c>hmac_signature</c>.
/// </para>
/// <para>
/// Field order, reply (reactor &#8594; server): <c>correlation_id</c>, <c>tenant_id</c>,
/// <c>event</c>, <c>decision</c>, <c>reason</c> (omitted when absent), <c>patch</c>
/// (omitted when absent), <c>require_mfa</c> (<b>omitted when <c>false</c></b>),
/// <c>key_version</c>, <c>nonce</c>, <c>issued_at</c>, <c>hmac_signature</c>.
/// </para>
/// <para>
/// The three conditionally-omitted fields are load-bearing: a reply that serializes
/// <c>"require_mfa": false</c> rather than omitting it produces different canonical bytes
/// and therefore a different MAC.
/// </para>
///
/// <para>
/// <b>Signing is symmetric in direction.</b> The server signs the event with the tenant
/// subkey; the reactor signs its reply with the same subkey. There is no second key and no
/// asymmetric variant in v1. An unsigned reply is not a weak reply — it is not a reply at
/// all, and the server discards it as though the reactor had never answered.
/// </para>
/// </summary>
public static class ReactorProtocol
{
    /// <summary>The topic exchange every reactor event is published to.</summary>
    public const string Exchange = "axiam.reactor.events";

    /// <summary>The &#167;8 envelope version reactor bodies are signed under.</summary>
    public const int KeyVersion = 2;

    /// <summary>
    /// The lowest <c>key_version</c> that is even considered. A body carrying less than
    /// this is refused before anything else about it is looked at — it predates the
    /// mandatory <c>nonce</c>/<c>issued_at</c> replay-protection fields.
    /// </summary>
    public const int MinAcceptedKeyVersion = 2;

    /// <summary>The <c>timeout_ms</c> a registration gets when it names none (&#167;22.8).</summary>
    public const int DefaultTimeoutMs = 500;

    /// <summary>The largest <c>timeout_ms</c> a registration may name; above this it is refused.</summary>
    public const int MaxTimeoutMs = 5_000;

    /// <summary>The chain's wall-clock ceiling: past this the remaining reactors are not contacted.</summary>
    public const int ChainCeilingMs = 5_000;

    /// <summary>The server's default per-tenant in-flight interception cap.</summary>
    public const int DefaultMaxInFlightPerTenant = 64;

    /// <summary>
    /// The &#167;8 v2 freshness window applied to <c>issued_at</c>, in both directions.
    /// </summary>
    public static readonly TimeSpan DefaultFreshnessSkew = TimeSpan.FromSeconds(300);

    private const string SignatureField = "hmac_signature";

    /// <summary>HKDF salt for the AMQP subkey. Salts are not secret; domain separation is the <c>info</c>.</summary>
    private static readonly byte[] HkdfSalt = Encoding.UTF8.GetBytes("axiam-amqp-hkdf-salt-v1");

    /// <summary>HKDF domain tag, so an AMQP subkey can never collide with one derived for another purpose.</summary>
    private static readonly byte[] HkdfDomainTag = Encoding.UTF8.GetBytes("axiam-amqp-v1");

    // ---- topology (§22.1) --------------------------------------------------

    /// <summary>
    /// The routing key an event for <paramref name="eventName"/> in
    /// <paramref name="tenantId"/> is published under.
    /// </summary>
    /// <param name="tenantId">The tenant.</param>
    /// <param name="eventName">The registry event name.</param>
    /// <returns><c>&lt;tenant_id&gt;.&lt;event&gt;</c>.</returns>
    public static string RoutingKey(Guid tenantId, string eventName) =>
        FormattableString.Invariant($"{tenantId}.{eventName}");

    /// <summary>
    /// The durable per-reactor queue the <b>server</b> declares.
    ///
    /// <para>
    /// Actors consume; they never declare topology. This helper exists so a runtime can
    /// name the queue it was registered as — never another one. A reactor that can bind is
    /// a reactor that can bind itself to <c>*.token.pre_issue</c> and read another tenant's
    /// issuance events, so this SDK holds no declare or bind capability at all.
    /// </para>
    /// </summary>
    /// <param name="tenantId">The tenant the reactor is registered in.</param>
    /// <param name="reactorId">This reactor's own registration id.</param>
    /// <returns><c>axiam.reactor.q.&lt;tenant_id&gt;.&lt;reactor_id&gt;</c>.</returns>
    public static string QueueName(Guid tenantId, Guid reactorId) =>
        FormattableString.Invariant($"axiam.reactor.q.{tenantId}.{reactorId}");

    // ---- key derivation (§8 v2) -------------------------------------------

    /// <summary>
    /// Derives a tenant's AMQP signing subkey from the deployment master key
    /// (<c>sdks/CONTRACT.md</c> &#167;8 v2, restated by &#167;22.2).
    ///
    /// <para>
    /// <c>HKDF-SHA256(salt = "axiam-amqp-hkdf-salt-v1", ikm = masterKey, info =
    /// "axiam-amqp-v1" || key_version || tenant_id_16_raw_bytes)</c>, 32 bytes out. The
    /// <c>info</c> is domain-separated, versioned and tenant-scoped, so a signature made
    /// with tenant A's subkey never verifies under tenant B's even though both derive from
    /// one master key.
    /// </para>
    /// <para>
    /// Most deployments should fetch the derived subkey from the management API rather than
    /// hold the master key in the reactor process at all; this exists for the ones that
    /// derive locally, and because a derivation that cannot be checked against the
    /// reference vectors is a derivation nobody can trust.
    /// </para>
    /// </summary>
    /// <param name="masterKey">The deployment's AMQP master signing key.</param>
    /// <param name="tenantId">The tenant to derive for.</param>
    /// <param name="keyVersion">The envelope key version, <see cref="KeyVersion"/> today.</param>
    /// <returns>The 32-byte per-tenant subkey.</returns>
    public static byte[] DeriveTenantKey(byte[] masterKey, Guid tenantId, int keyVersion = KeyVersion)
    {
        ArgumentNullException.ThrowIfNull(masterKey);
        byte[] info = new byte[HkdfDomainTag.Length + 1 + 16];
        HkdfDomainTag.CopyTo(info, 0);
        info[HkdfDomainTag.Length] = unchecked((byte)keyVersion);
        TenantIdBytes(tenantId).CopyTo(info, HkdfDomainTag.Length + 1);

        return HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, outputLength: 32, salt: HkdfSalt, info: info);
    }

    // ---- canonicalization + MAC -------------------------------------------

    /// <summary>
    /// The exact bytes an event was signed over: the received body with
    /// <c>hmac_signature</c> set to <c>null</c> in place.
    ///
    /// <para>
    /// Setting the value rather than removing the key is what makes these bytes a
    /// <em>reactor</em> body rather than a &#167;8 one. The field keeps its position:
    /// <see cref="JsonObject"/> is backed by an ordered dictionary, and assigning through
    /// the indexer on an existing key replaces the value without moving it.
    /// </para>
    /// </summary>
    /// <param name="body">The raw delivery body.</param>
    /// <returns>The canonical bytes.</returns>
    /// <exception cref="ArgumentException">When <paramref name="body"/> is not a JSON object.</exception>
    public static byte[] CanonicalEventBytes(byte[] body)
    {
        JsonObject node = ParseObject(body);
        node[SignatureField] = null;
        return Encoding.UTF8.GetBytes(node.ToJsonString());
    }

    /// <summary>
    /// Verifies an event's MAC under <paramref name="signingKey"/>.
    ///
    /// <para>
    /// This checks the signature and nothing else. <see cref="ReactorServer"/> applies the
    /// full &#167;22.3 order around it — reject <c>key_version &lt; 2</c>, verify the MAC,
    /// check freshness, check the nonce — and only then decodes the payload.
    /// </para>
    /// <para>
    /// Never throws: a malformed body, a missing or null signature, non-hex signature text
    /// and a wrong-length signature all verify as <c>false</c>. There is no
    /// accept-when-absent path.
    /// </para>
    /// </summary>
    /// <param name="signingKey">The tenant's derived AMQP subkey.</param>
    /// <param name="body">The raw delivery body.</param>
    /// <returns><c>true</c> only when the MAC matches, compared in constant time.</returns>
    public static bool VerifyEvent(byte[] signingKey, byte[] body)
    {
        try
        {
            JsonObject node = ParseObject(body);
            if (node[SignatureField] is not JsonValue value || !value.TryGetValue(out string? sigHex) || sigHex is null)
            {
                return false;
            }

            byte[] presented = Convert.FromHexString(sigHex);
            node[SignatureField] = null;
            byte[] computed = HMACSHA256.HashData(signingKey, Encoding.UTF8.GetBytes(node.ToJsonString()));

            return computed.Length == presented.Length
                && CryptographicOperations.FixedTimeEquals(computed, presented);
        }
        catch (Exception e) when (e is ArgumentException or FormatException or InvalidOperationException)
        {
            // Unparseable body, bad hex, unusable key: reject, never throw.
            // Attacker-controlled input must not be able to kill the consumer.
            return false;
        }
    }

    /// <summary>
    /// The exact bytes a reply is signed over: the reply fields in declared order, with the
    /// conditional omissions applied and <c>hmac_signature</c> present and <c>null</c>.
    /// </summary>
    /// <param name="correlationId">The event's correlation id, copied verbatim.</param>
    /// <param name="tenantId">The event's tenant.</param>
    /// <param name="eventName">The event's registry name.</param>
    /// <param name="decision">What the handler decided.</param>
    /// <param name="nonce">A fresh UUIDv4, unique per reply.</param>
    /// <param name="issuedAt">
    /// The reply's signing time; truncated to whole seconds so it round-trips through the
    /// server's RFC 3339 parser to byte-identical text.
    /// </param>
    /// <returns>The canonical bytes.</returns>
    public static byte[] CanonicalReplyBytes(
        Guid correlationId,
        Guid tenantId,
        string eventName,
        ReactorDecision decision,
        Guid nonce,
        DateTimeOffset issuedAt) =>
        Encoding.UTF8.GetBytes(
            ReplyObject(correlationId, tenantId, eventName, decision, nonce, issuedAt).ToJsonString());

    /// <summary>
    /// Builds and signs a reply — the wire bytes a reactor publishes.
    /// </summary>
    /// <param name="signingKey">
    /// The tenant's derived AMQP subkey, the same one the event was signed with.
    /// </param>
    /// <param name="correlationId">
    /// The event's correlation id, copied verbatim. The server authenticates this field
    /// inside the signed body, not the AMQP property.
    /// </param>
    /// <param name="tenantId">The event's tenant.</param>
    /// <param name="eventName">The event's registry name.</param>
    /// <param name="decision">What the handler decided.</param>
    /// <param name="nonce">
    /// A fresh UUIDv4. It is inside the signed bytes, so a unique one is what keeps two
    /// replies from being byte-identical; a constant nonce removes the only uniqueness the
    /// reply body carries beyond its timestamp.
    /// </param>
    /// <param name="issuedAt">The reply's signing time.</param>
    /// <returns>The signed reply body, ready to publish.</returns>
    public static byte[] SignedReply(
        byte[] signingKey,
        Guid correlationId,
        Guid tenantId,
        string eventName,
        ReactorDecision decision,
        Guid nonce,
        DateTimeOffset issuedAt)
    {
        JsonObject node = ReplyObject(correlationId, tenantId, eventName, decision, nonce, issuedAt);
        byte[] mac = HMACSHA256.HashData(signingKey, Encoding.UTF8.GetBytes(node.ToJsonString()));
        node[SignatureField] = Convert.ToHexString(mac).ToLowerInvariant();
        return Encoding.UTF8.GetBytes(node.ToJsonString());
    }

    /// <summary>
    /// Whether <paramref name="issuedAt"/> lies within <paramref name="skew"/> of
    /// <paramref name="now"/>, in both directions.
    ///
    /// <para>
    /// A future timestamp is not "extra fresh"; it is the shape of a captured message held
    /// for later.
    /// </para>
    /// </summary>
    /// <param name="issuedAt">The timestamp inside the signed body.</param>
    /// <param name="now">The verifier's clock reading.</param>
    /// <param name="skew">The acceptance window, <see cref="DefaultFreshnessSkew"/> by default.</param>
    /// <returns><c>true</c> when the timestamp is inside the window.</returns>
    public static bool IsFresh(DateTimeOffset issuedAt, DateTimeOffset now, TimeSpan skew) =>
        (now - issuedAt).Duration() <= skew;

    /// <summary>
    /// Renders <paramref name="instant"/> the way the server's RFC 3339 codec does,
    /// truncated to whole seconds.
    ///
    /// <para>
    /// The server verifies a reply by deserializing it and re-serializing the body, so the
    /// timestamp text has to survive that round trip unchanged. Whole seconds always do; a
    /// sub-second value whose digit count does not match the server's auto-selected
    /// precision would not.
    /// </para>
    /// </summary>
    /// <param name="instant">The moment to render.</param>
    /// <returns>An RFC 3339 UTC timestamp with no fractional part.</returns>
    public static string FormatInstant(DateTimeOffset instant) =>
        instant.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);

    // ---- internals ---------------------------------------------------------

    private static JsonObject ReplyObject(
        Guid correlationId,
        Guid tenantId,
        string eventName,
        ReactorDecision decision,
        Guid nonce,
        DateTimeOffset issuedAt)
    {
        ArgumentNullException.ThrowIfNull(eventName);
        ArgumentNullException.ThrowIfNull(decision);

        var node = new JsonObject
        {
            ["correlation_id"] = correlationId.ToString("D", CultureInfo.InvariantCulture),
            ["tenant_id"] = tenantId.ToString("D", CultureInfo.InvariantCulture),
            ["event"] = eventName,
            ["decision"] = decision.Wire,
        };

        switch (decision)
        {
            case ReactorDecision.Deny { Reason: { } reason }:
                node["reason"] = reason;
                break;

            case ReactorDecision.Mutate mutation:
                // The server's patch is a BTreeMap, so its serialization order is UTF-8
                // byte order. Sent UNFILTERED: §22.4 rule 1 forbids trimming a handler's
                // patch to the allowed subset, because one forbidden key rejects the whole
                // reply and the author must find out.
                var patch = new JsonObject();
                foreach (KeyValuePair<string, string> entry in mutation.Patch.OrderBy(e => e.Key, Utf8Order.Instance))
                {
                    patch[entry.Key] = entry.Value;
                }

                node["patch"] = patch;
                break;

            case ReactorDecision.Allow { RequireMfa: true }:
                // require_mfa is emitted ONLY when true: `"require_mfa": false` would
                // change the canonical bytes and therefore the MAC.
                node["require_mfa"] = true;
                break;

            default:
                break;
        }

        node["key_version"] = KeyVersion;
        node["nonce"] = nonce.ToString("D", CultureInfo.InvariantCulture);
        node["issued_at"] = FormatInstant(issuedAt);
        node[SignatureField] = null;
        return node;
    }

    private static JsonObject ParseObject(byte[] body)
    {
        JsonObject? node;
        try
        {
            node = JsonNode.Parse(body)?.AsObject();
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException)
        {
            throw new ArgumentException("reactor body is not valid JSON", nameof(body), e);
        }

        return node ?? throw new ArgumentException("reactor body is not a JSON object", nameof(body));
    }

    private static byte[] TenantIdBytes(Guid tenantId)
    {
        // RFC 4122 big-endian byte order — the same 16 raw bytes the server's
        // `Uuid::as_bytes()` feeds into the HKDF `info`. Guid.ToByteArray()'s default
        // little-endian layout for the first three groups would derive a different key.
        byte[] bytes = new byte[16];
        tenantId.TryWriteBytes(bytes, bigEndian: true, out _);
        return bytes;
    }

    /// <summary>
    /// Byte-order comparator for patch keys. The server's patch is a
    /// <c>BTreeMap&lt;String, String&gt;</c>, whose serialization order is UTF-8 byte
    /// order; .NET's ordinal <see cref="string"/> comparison is UTF-16 code-unit order,
    /// which agrees for every realistic claim name but diverges above the BMP. Comparing
    /// the encoded bytes removes the question rather than betting on the input.
    /// </summary>
    private sealed class Utf8Order : IComparer<string>
    {
        internal static readonly Utf8Order Instance = new();

        public int Compare(string? left, string? right)
        {
            byte[] a = Encoding.UTF8.GetBytes(left ?? string.Empty);
            byte[] b = Encoding.UTF8.GetBytes(right ?? string.Empty);
            int shared = Math.Min(a.Length, b.Length);
            for (int i = 0; i < shared; i++)
            {
                int diff = a[i] - b[i];
                if (diff != 0)
                {
                    return diff;
                }
            }

            return a.Length - b.Length;
        }
    }
}
