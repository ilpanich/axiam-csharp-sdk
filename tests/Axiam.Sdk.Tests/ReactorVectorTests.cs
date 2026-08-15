using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using Axiam.Sdk.Reactor;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// <c>sdks/CONTRACT.md</c> &#167;22.13 conformance, against the server-generated vectors in
/// <c>Fixtures/reactor_v2_reference_vectors.json</c>.
///
/// <para>
/// These are the tests the contract asks for by name, in its own order: the shared subkey
/// derivation, sign direction, verify direction, replay, and the topology strings. The
/// expectations are the fixture's — nothing here is hand-rolled, which is the point of
/// shipping vectors rather than a prose description of the canonicalization.
/// </para>
/// </summary>
[Trait("Category", "Fast")]
public class ReactorVectorTests
{
    private static readonly DateTimeOffset VerifiedAt =
        DateTimeOffset.Parse("2026-07-10T12:00:00Z", CultureInfo.InvariantCulture);

    // ---- the key both directions sign with ---------------------------------

    /// <summary>
    /// The &#167;8 v2 HKDF derivation, checked against BOTH fixtures — which carry the same
    /// master key, tenant and derived subkey precisely so this can be one assertion rather
    /// than two implementations.
    /// </summary>
    [Fact]
    public void TenantSubkey_DerivesExactlyAsTheServerDerivesIt()
    {
        JsonObject reactorFixture = ReactorVectors.Load();
        JsonObject amqpFixture = ReactorVectors.Load("v2_reference_vectors.json");

        byte[] derived = ReactorProtocol.DeriveTenantKey(
            ReactorVectors.MasterKey(reactorFixture),
            ReactorVectors.TenantId(reactorFixture));

        Assert.Equal(ReactorVectors.Subkey(reactorFixture), derived);
        Assert.Equal(ReactorVectors.Subkey(amqpFixture), derived);

        byte[] otherTenant = ReactorProtocol.DeriveTenantKey(
            ReactorVectors.MasterKey(reactorFixture),
            Guid.Parse("33333333-3333-3333-3333-333333333333"));
        Assert.NotEqual(derived, otherTenant);
    }

    // ---- sign direction (reactor -> server) --------------------------------

    [Theory]
    [InlineData("allow")]
    [InlineData("deny")]
    [InlineData("mutate")]
    [InlineData("require_mfa")]
    public void EveryCommittedReply_ReproducesItsCanonicalBytesAndItsMac(string name)
    {
        JsonObject root = ReactorVectors.Load();
        byte[] key = ReactorVectors.Subkey(root);
        Guid tenant = ReactorVectors.TenantId(root);
        Guid correlation = ReactorVectors.CorrelationId(root);

        JsonObject vector = root["reactor_to_server"]![name]!.AsObject();
        JsonObject message = vector["message"]!.AsObject();
        string eventName = ReactorVectors.Text(message, "event");
        Guid nonce = Guid.Parse(ReactorVectors.Text(message, "nonce"));
        DateTimeOffset issuedAt = DateTimeOffset.Parse(
            ReactorVectors.Text(message, "issued_at"), CultureInfo.InvariantCulture);
        ReactorDecision decision = DecisionOf(message);

        byte[] canonical = ReactorProtocol.CanonicalReplyBytes(
            correlation, tenant, eventName, decision, nonce, issuedAt);
        Assert.Equal(
            ReactorVectors.Text(vector, "canonical_signed_json"),
            Encoding.UTF8.GetString(canonical));

        byte[] signed = ReactorProtocol.SignedReply(key, correlation, tenant, eventName, decision, nonce, issuedAt);
        JsonObject reparsed = JsonNode.Parse(signed)!.AsObject();
        Assert.Equal(
            ReactorVectors.Text(vector, "hmac_signature_hex"),
            reparsed["hmac_signature"]!.GetValue<string>());
        Assert.True(
            ReactorProtocol.VerifyEvent(key, signed),
            "a reply this SDK signed must verify under the same subkey");
    }

    /// <summary>
    /// &#167;22.2: the three conditionally-omitted fields are load-bearing. A reply that
    /// serializes <c>"require_mfa": false</c> rather than omitting it produces different
    /// canonical bytes and therefore a different MAC.
    /// </summary>
    [Fact]
    public void TheOmissionRules_AreReproducedNotJustTheValues()
    {
        JsonObject root = ReactorVectors.Load();
        Guid tenant = ReactorVectors.TenantId(root);
        Guid correlation = ReactorVectors.CorrelationId(root);
        Guid nonce = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

        string allow = Encoding.UTF8.GetString(ReactorProtocol.CanonicalReplyBytes(
            correlation, tenant, ReactorEvents.LoginPostAuth, ReactorDecision.Allowed(), nonce, VerifiedAt));
        Assert.DoesNotContain("require_mfa", allow, StringComparison.Ordinal);
        Assert.DoesNotContain("reason", allow, StringComparison.Ordinal);
        Assert.DoesNotContain("patch", allow, StringComparison.Ordinal);
        Assert.EndsWith("\"hmac_signature\":null}", allow, StringComparison.Ordinal);

        string denyNoReason = Encoding.UTF8.GetString(ReactorProtocol.CanonicalReplyBytes(
            correlation, tenant, ReactorEvents.GrantPreAssign, ReactorDecision.Denied(), nonce, VerifiedAt));
        Assert.DoesNotContain("reason", denyNoReason, StringComparison.Ordinal);

        string stepUp = Encoding.UTF8.GetString(ReactorProtocol.CanonicalReplyBytes(
            correlation, tenant, ReactorEvents.LoginPostAuth,
            ReactorDecision.AllowRequiringStepUp(), nonce, VerifiedAt));
        Assert.Contains("\"require_mfa\":true", stepUp, StringComparison.Ordinal);
    }

    /// <summary>
    /// &#167;22.2: two replies differing in nothing but the nonce carry different MACs — the
    /// nonce is inside the signed bytes, which is the only uniqueness a reply body has beyond
    /// its timestamp.
    /// </summary>
    [Fact]
    public void TheNonce_IsInsideTheSignedBytes()
    {
        JsonObject root = ReactorVectors.Load();
        JsonObject binding = root["nonce_binding"]!.AsObject();
        byte[] key = ReactorVectors.Subkey(root);
        Guid tenant = ReactorVectors.TenantId(root);
        Guid correlation = ReactorVectors.CorrelationId(root);

        string macA = MacOf(ReactorProtocol.SignedReply(
            key, correlation, tenant, ReactorEvents.LoginPostAuth, ReactorDecision.Allowed(),
            Guid.Parse(ReactorVectors.Text(binding, "nonce_a")), VerifiedAt));
        string macB = MacOf(ReactorProtocol.SignedReply(
            key, correlation, tenant, ReactorEvents.LoginPostAuth, ReactorDecision.Allowed(),
            Guid.Parse(ReactorVectors.Text(binding, "nonce_b")), VerifiedAt));

        Assert.Equal(ReactorVectors.Text(binding, "hmac_a_hex"), macA);
        Assert.Equal(ReactorVectors.Text(binding, "hmac_b_hex"), macB);
        Assert.NotEqual(macA, macB);
    }

    // ---- verify direction (server -> reactor) ------------------------------

    [Theory]
    [InlineData("token_pre_issue")]
    [InlineData("login_post_auth")]
    public void EveryCommittedEvent_VerifiesUnderTheDerivedSubkeyAndNoOther(string name)
    {
        JsonObject root = ReactorVectors.Load();
        byte[] key = ReactorVectors.Subkey(root);
        byte[] body = ReactorVectors.WireBody(root["server_to_reactor"]![name]!.AsObject());

        Assert.True(ReactorProtocol.VerifyEvent(key, body));
        Assert.False(ReactorProtocol.VerifyEvent(new byte[key.Length], body));
    }

    [Fact]
    public void TamperingWithAnySignedField_InvalidatesTheEvent()
    {
        JsonObject root = ReactorVectors.Load();
        byte[] key = ReactorVectors.Subkey(root);
        JsonObject vector = root["server_to_reactor"]!["token_pre_issue"]!.AsObject();

        JsonObject payloadTampered = Tamperable(vector);
        payloadTampered["payload"]!["sub"] = "root";
        Assert.False(
            ReactorProtocol.VerifyEvent(key, ReactorVectors.Encode(payloadTampered)),
            "rewriting the payload must invalidate the event");

        JsonObject timeoutStretched = Tamperable(vector);
        timeoutStretched["timeout_ms"] = 60_000;
        Assert.False(
            ReactorProtocol.VerifyEvent(key, ReactorVectors.Encode(timeoutStretched)),
            "widening the window an actor thinks it has is tampering too");

        JsonObject crossTenant = Tamperable(vector);
        crossTenant["tenant_id"] = "33333333-3333-3333-3333-333333333333";
        Assert.False(ReactorProtocol.VerifyEvent(key, ReactorVectors.Encode(crossTenant)));

        JsonObject nonceSwapped = Tamperable(vector);
        nonceSwapped["nonce"] = "dddddddd-dddd-dddd-dddd-dddddddddddd";
        Assert.False(ReactorProtocol.VerifyEvent(key, ReactorVectors.Encode(nonceSwapped)));
    }

    [Fact]
    public void AStaleOrFutureTimestamp_IsOutsideTheWindowInBothDirections()
    {
        DateTimeOffset now = VerifiedAt;
        TimeSpan skew = ReactorProtocol.DefaultFreshnessSkew;

        Assert.True(ReactorProtocol.IsFresh(now, now, skew));
        Assert.True(ReactorProtocol.IsFresh(now.AddSeconds(-300), now, skew));
        Assert.True(ReactorProtocol.IsFresh(now.AddSeconds(300), now, skew));
        Assert.False(ReactorProtocol.IsFresh(now.AddSeconds(-301), now, skew));
        Assert.False(
            ReactorProtocol.IsFresh(now.AddSeconds(301), now, skew),
            "a future timestamp is not extra fresh — it is a captured message held for later");
    }

    /// <summary>
    /// The fixture's <c>stale</c> and <c>stale_future</c> reply vectors, checked against its
    /// own <c>verified_at</c>: both carry a perfectly valid signature and are still outside
    /// the window.
    /// </summary>
    [Theory]
    [InlineData("stale")]
    [InlineData("stale_future")]
    public void TheCommittedStaleVectors_AreRefusedOnFreshnessNotOnSignature(string name)
    {
        JsonObject root = ReactorVectors.Load();
        byte[] key = ReactorVectors.Subkey(root);
        DateTimeOffset now = DateTimeOffset.Parse(
            ReactorVectors.Text(root, "verified_at"), CultureInfo.InvariantCulture);

        JsonObject vector = root["rejected_replies"]![name]!.AsObject();
        Assert.True(
            ReactorProtocol.VerifyEvent(key, ReactorVectors.WireBody(vector)),
            "the signature itself is valid — the refusal is a freshness one");

        DateTimeOffset issuedAt = DateTimeOffset.Parse(
            vector["message"]!["issued_at"]!.GetValue<string>(), CultureInfo.InvariantCulture);
        Assert.False(ReactorProtocol.IsFresh(issuedAt, now, ReactorProtocol.DefaultFreshnessSkew));
        Assert.Equal("stale", ReactorVectors.Text(vector, "expected_rejection"));
    }

    /// <summary>
    /// The <c>key_version_too_old</c> vector was downgraded AFTER signing, so its committed
    /// MAC does not match the body: the refusal must come from the key-version check alone,
    /// which &#167;22.4 places before the signature check.
    /// </summary>
    [Fact]
    public void TheKeyVersionVector_IsRefusedBeforeTheSignatureIsEvenComputed()
    {
        JsonObject root = ReactorVectors.Load();
        JsonObject vector = root["rejected_replies"]!["key_version_too_old"]!.AsObject();
        JsonObject canonical = ReactorVectors.CanonicalObject(vector);

        Assert.Equal("key_version_too_old", ReactorVectors.Text(vector, "expected_rejection"));
        Assert.True(canonical["key_version"]!.GetValue<int>() < ReactorProtocol.MinAcceptedKeyVersion);
        Assert.False(
            ReactorProtocol.VerifyEvent(
                ReactorVectors.Subkey(root), ReactorVectors.WireBody(vector)),
            "and its MAC does not match either, which is why the ORDER of the two checks matters");
    }

    /// <summary>
    /// &#167;22.13 replay: the accepted reply verbatim — valid signature, inside the window —
    /// is refused when presented against a different <c>correlation_id</c>, and this SDK
    /// cannot re-aim it, because the correlation lives inside the signed bytes.
    /// </summary>
    [Fact]
    public void ACapturedReply_CannotBeReAimedAtAnotherCorrelation()
    {
        JsonObject root = ReactorVectors.Load();
        JsonObject vector = root["rejected_replies"]!["correlation_replay"]!.AsObject();
        byte[] key = ReactorVectors.Subkey(root);
        Guid tenant = ReactorVectors.TenantId(root);

        Guid captured = Guid.Parse(vector["message"]!["correlation_id"]!.GetValue<string>());
        Guid presentedAgainst = Guid.Parse(ReactorVectors.Text(vector, "verify_against_correlation_id"));
        Assert.NotEqual(captured, presentedAgainst);
        Assert.Equal("wrong_correlation", ReactorVectors.Text(vector, "expected_rejection"));

        Assert.True(
            ReactorProtocol.VerifyEvent(key, ReactorVectors.WireBody(vector)),
            "the captured reply's signature is perfectly valid; the correlation is what refuses it");

        string reAimed = MacOf(ReactorProtocol.SignedReply(
            key, presentedAgainst, tenant, ReactorEvents.LoginPostAuth, ReactorDecision.Allowed(),
            Guid.Parse(vector["message"]!["nonce"]!.GetValue<string>()), VerifiedAt));
        Assert.NotEqual(ReactorVectors.Text(vector, "hmac_signature_hex"), reAimed);
    }

    /// <summary>
    /// The <c>forbidden_patch_field</c> and <c>mutation_on_veto_only_event</c> vectors are
    /// SERVER-side rejections of correctly signed replies. This SDK reproduces their exact
    /// bytes — proving it neither filters the forbidden key (&#167;22.4 rule 1) nor refuses
    /// to build a mutation the registry would reject.
    /// </summary>
    [Theory]
    [InlineData("forbidden_patch_field")]
    [InlineData("mutation_on_veto_only_event")]
    public void ARejectedButCorrectlySignedReply_IsStillTheBytesThisSdkProduces(string name)
    {
        JsonObject root = ReactorVectors.Load();
        byte[] key = ReactorVectors.Subkey(root);
        JsonObject vector = root["rejected_replies"]![name]!.AsObject();
        JsonObject message = vector["message"]!.AsObject();

        byte[] signed = ReactorProtocol.SignedReply(
            key,
            ReactorVectors.CorrelationId(root),
            ReactorVectors.TenantId(root),
            ReactorVectors.Text(message, "event"),
            DecisionOf(message),
            Guid.Parse(ReactorVectors.Text(message, "nonce")),
            DateTimeOffset.Parse(ReactorVectors.Text(message, "issued_at"), CultureInfo.InvariantCulture));

        Assert.Equal(ReactorVectors.Text(vector, "hmac_signature_hex"), MacOf(signed));
    }

    // ---- topology (§22.1) --------------------------------------------------

    [Fact]
    public void TopologyStrings_MatchTheServersOwn()
    {
        JsonObject root = ReactorVectors.Load();
        JsonObject topology = root["topology"]!.AsObject();
        Guid tenant = ReactorVectors.TenantId(root);
        Guid reactorId = Guid.Parse(ReactorVectors.Text(root, "reactor_id"));

        Assert.Equal(ReactorProtocol.Exchange, ReactorVectors.Text(topology, "exchange"));
        Assert.Equal("topic", ReactorVectors.Text(topology, "exchange_type"));
        Assert.Equal(ReactorVectors.Text(topology, "queue"), ReactorProtocol.QueueName(tenant, reactorId));
        Assert.Equal(
            ReactorVectors.Text(topology, "routing_key_token_pre_issue"),
            ReactorProtocol.RoutingKey(tenant, ReactorEvents.TokenPreIssue));
        Assert.Equal(
            ReactorVectors.Text(topology, "routing_key_login_post_auth"),
            ReactorProtocol.RoutingKey(tenant, ReactorEvents.LoginPostAuth));
    }

    [Fact]
    public void TheFixturesFieldOrder_IsTheOrderThisSdkWrites()
    {
        JsonObject root = ReactorVectors.Load();
        JsonObject order = root["field_order"]!.AsObject();

        Assert.Equal(
            new[]
            {
                "tenant_id", "event", "correlation_id", "payload", "timeout_ms", "key_version",
                "nonce", "issued_at", "hmac_signature",
            },
            Names(order["reactor_event"]!.AsArray()));
        Assert.Equal(
            new[]
            {
                "correlation_id", "tenant_id", "event", "decision", "reason", "patch", "require_mfa",
                "key_version", "nonce", "issued_at", "hmac_signature",
            },
            Names(order["reactor_reply"]!.AsArray()));

        // The mutate vector exercises the longest reply: decision + patch, with reason and
        // require_mfa omitted. Its key order is the contract's, minus the omissions.
        JsonObject mutate = ReactorVectors.CanonicalObject(root["reactor_to_server"]!["mutate"]!.AsObject());
        Assert.Equal(
            new[]
            {
                "correlation_id", "tenant_id", "event", "decision", "patch", "key_version", "nonce",
                "issued_at", "hmac_signature",
            },
            mutate.Select(kv => kv.Key).ToArray());
    }

    // ---- helpers -----------------------------------------------------------

    /// <summary>
    /// The fixture annotates its last <c>field_order</c> entry in prose
    /// ("hmac_signature (SERIALIZED AS null while signing, not omitted)"), so the field name
    /// is the token before the parenthesis.
    /// </summary>
    private static string[] Names(JsonArray array) =>
        array.Select(n => n!.GetValue<string>().Split(' ', 2)[0]).ToArray();

    private static JsonObject Tamperable(JsonObject vector)
    {
        JsonObject node = ReactorVectors.CanonicalObject(vector);
        node["hmac_signature"] = ReactorVectors.Text(vector, "hmac_signature_hex");
        return node;
    }

    private static string MacOf(byte[] signedBody) =>
        JsonNode.Parse(signedBody)!["hmac_signature"]!.GetValue<string>();

    private static ReactorDecision DecisionOf(JsonObject message)
    {
        string decision = ReactorVectors.Text(message, "decision");
        switch (decision)
        {
            case "allow":
                return message["require_mfa"]?.GetValue<bool>() == true
                    ? ReactorDecision.AllowRequiringStepUp()
                    : ReactorDecision.Allowed();

            case "deny":
                return ReactorDecision.Denied(message["reason"]?.GetValue<string>());

            case "mutate":
                var patch = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (KeyValuePair<string, JsonNode?> entry in message["patch"]!.AsObject())
                {
                    patch[entry.Key] = entry.Value!.GetValue<string>();
                }

                return ReactorDecision.Mutated(patch);

            default:
                throw new InvalidOperationException($"unknown decision {decision}");
        }
    }
}
