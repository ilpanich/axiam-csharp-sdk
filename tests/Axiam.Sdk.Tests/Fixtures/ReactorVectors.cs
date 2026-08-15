using System;
using System.IO;
using System.Text;
using System.Text.Json.Nodes;

namespace Axiam.Sdk.Tests.Fixtures;

/// <summary>
/// Loader for the <c>sdks/CONTRACT.md</c> &#167;22.13 reference vectors
/// (<c>crates/axiam-amqp/tests/fixtures/reactor_v2_reference_vectors.json</c>, copied
/// verbatim into this project's Fixtures/ directory) and for &#167;8's own vectors beside
/// them.
///
/// <para>
/// The two fixtures share a master key, a tenant and a derived subkey, which is exactly why
/// &#167;22.13 says one loader serves both: the only difference between the two message
/// families — <c>hmac_signature</c> present and <c>null</c> here, absent there — becomes a
/// test rather than a paragraph to remember.
/// </para>
/// <para>
/// <b>Fixture-reading note:</b> a vector's <c>message</c> object is a convenience rendering
/// with alphabetically sorted keys and must never be fed to a verifier directly. The one
/// authoritative field for wire order is <c>canonical_signed_json</c>, whose key order as
/// written in the fixture text <em>is</em> the declared field order. Every helper below
/// builds its wire body from that string.
/// </para>
/// </summary>
internal static class ReactorVectors
{
    internal static JsonObject Load(string fileName = "reactor_v2_reference_vectors.json")
    {
        string path = Path.Combine(AppContext.BaseDirectory, "Fixtures", fileName);
        return JsonNode.Parse(File.ReadAllText(path))!.AsObject();
    }

    /// <summary>The HKDF-derived per-tenant AMQP subkey both directions sign with.</summary>
    internal static byte[] Subkey(JsonObject root) =>
        Convert.FromHexString(root["hkdf"]!["derived_subkey_hex"]!.GetValue<string>());

    internal static byte[] MasterKey(JsonObject root) =>
        Convert.FromHexString(root["master_signing_key_hex"]!.GetValue<string>());

    internal static Guid TenantId(JsonObject root) => Guid.Parse(root["tenant_id"]!.GetValue<string>());

    internal static Guid CorrelationId(JsonObject root) =>
        Guid.Parse(root["expected_correlation_id"]!.GetValue<string>());

    internal static string Text(JsonObject obj, string field) => obj[field]!.GetValue<string>();

    /// <summary>The canonical (signed-over) tree: <c>hmac_signature</c> present and null.</summary>
    internal static JsonObject CanonicalObject(JsonObject vector) =>
        JsonNode.Parse(Text(vector, "canonical_signed_json"))!.AsObject();

    /// <summary>
    /// Reconstructs the signed wire body: the canonical bytes with <c>hmac_signature</c>
    /// carrying the committed hex instead of <c>null</c>. Assigning through the indexer on an
    /// existing key keeps its position, so the field stays exactly where the server wrote it.
    /// </summary>
    internal static byte[] WireBody(JsonObject vector) =>
        WithSignature(CanonicalObject(vector), Text(vector, "hmac_signature_hex"));

    internal static byte[] WithSignature(JsonObject canonical, string signatureHex)
    {
        canonical["hmac_signature"] = signatureHex;
        return Encoding.UTF8.GetBytes(canonical.ToJsonString());
    }

    internal static byte[] Encode(JsonObject obj) => Encoding.UTF8.GetBytes(obj.ToJsonString());
}
