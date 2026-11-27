using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Amqp;
using Microsoft.Extensions.Logging;
using Moq;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Proves <see cref="AxiamAmqpConsumer"/>'s <c>sdks/CONTRACT.md</c> §8
/// ack/nack matrix and verify-before-handler invariant across every branch,
/// using a Moq-based fake <see cref="IChannel"/> (recording
/// <c>BasicAckAsync</c>/<c>BasicNackAsync(tag, multiple, requeue)</c> calls)
/// and synthesized <see cref="BasicDeliverEventArgs"/> instances. The
/// delegate under test is obtained via
/// <see cref="AxiamAmqpConsumer.CreateReceivedHandler"/> (through <c>NewHandler</c>) and invoked
/// directly — no live broker is involved.
///
/// <para>
/// Valid/tampered bodies and the matching signing key are reused verbatim
/// from 21-01's real, Rust-signer-produced fixture
/// (<c>Fixtures/amqp_hmac_vectors.json</c>), so the HMAC-fail branch below is
/// proven against an authentic tampered signature, not a hand-rolled invalid
/// one.
/// </para>
/// </summary>
[Trait("Category", "Fast")]
public class AmqpConsumerTests
{
    private static readonly string FixturePath =
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "amqp_hmac_vectors.json");

    /// <summary>The configured tenant of every consumer under test: the <c>tenant_id</c> of each discard event.</summary>
    private const string ConsumerTenant = "99999999-9999-9999-9999-999999999999";

    private static AsyncEventHandler<BasicDeliverEventArgs> NewHandler(
        IChannel channel,
        byte[] key,
        Func<byte[], CancellationToken, Task> handler,
        ILogger logger,
        ReplayGuard guard,
        AmqpEventType type = AmqpEventType.AuthzRequest,
        TimeProvider? clock = null) =>
        AxiamAmqpConsumer.CreateReceivedHandler(channel, type, ConsumerTenant, "axiam.queue", key, handler, logger, guard, CancellationToken.None, clock);

    private sealed record AckNackCall(string Type, ulong DeliveryTag, bool Multiple, bool Requeue);

    /// <summary>
    /// A hand-written fake <see cref="ILogger"/> recording the fully
    /// formatted text of every <c>LogWarning</c> call, so tests can assert on
    /// the exact logged message without pulling in a logging provider.
    /// </summary>
    private sealed class RecordingLogger : ILogger
    {
        public List<string> Warnings { get; } = new();

        /// <summary>Every warning's structured members.</summary>
        public List<Dictionary<string, string>> Events { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                Warnings.Add(formatter(state, exception));
                var members = new Dictionary<string, string>();
                if (state is IEnumerable<KeyValuePair<string, object?>> pairs)
                {
                    foreach (KeyValuePair<string, object?> pair in pairs)
                    {
                        members[pair.Key] = Convert.ToString(pair.Value, CultureInfo.InvariantCulture) ?? string.Empty;
                    }
                }
                Events.Add(members);
            }
        }
    }

    /// <summary>
    /// The fixture's "authz_request_valid" vector's <c>issued_at</c>
    /// (<c>Fixtures/amqp_hmac_vectors.json</c>) — every test below that needs a
    /// <see cref="ReplayGuard"/> passing the freshness check pins its clock to
    /// this instant (matching the reference Go SDK's <c>now func()</c> test seam)
    /// rather than depending on wall-clock time.
    /// </summary>
    private static readonly DateTimeOffset FixtureIssuedAt =
        DateTimeOffset.Parse("2026-07-10T12:00:00Z", CultureInfo.InvariantCulture);

    /// <summary>
    /// Builds a <see cref="ReplayGuard"/> whose clock is pinned to
    /// <see cref="FixtureIssuedAt"/> (or <paramref name="clock"/> when supplied),
    /// so fixture bodies signed at that fixed <c>issued_at</c> pass the freshness
    /// gate deterministically regardless of when the test actually runs.
    /// </summary>
    private static ReplayGuard NewGuard(TimeSpan? skew = null, Func<DateTimeOffset>? clock = null) =>
        new(skew, clock ?? (() => FixtureIssuedAt));

    private static (byte[] SigningKey, byte[] ValidBody, byte[] TamperedBody, string TamperedSignatureHex)
        LoadHmacFixtureBodies()
    {
        string json = File.ReadAllText(FixturePath);
        JsonObject root = JsonNode.Parse(json)!.AsObject();
        JsonArray vectors = root["vectors"]!.AsArray();

        JsonObject Find(string name) =>
            vectors.Select(v => v!.AsObject()).Single(v => v["name"]!.GetValue<string>() == name);

        JsonObject validVector = Find("authz_request_valid");
        JsonObject tamperedVector = Find("authz_request_tampered_action");

        byte[] signingKey = Convert.FromHexString(validVector["signing_key_hex"]!.GetValue<string>());
        byte[] validBody = Encoding.UTF8.GetBytes(validVector["message"]!.AsObject().DeepClone().ToJsonString());

        JsonObject tamperedMessage = tamperedVector["message"]!.AsObject().DeepClone().AsObject();
        byte[] tamperedBody = Encoding.UTF8.GetBytes(tamperedMessage.ToJsonString());
        string tamperedSignatureHex = tamperedMessage["hmac_signature"]!.GetValue<string>();

        return (signingKey, validBody, tamperedBody, tamperedSignatureHex);
    }

    private static (Mock<IChannel> ChannelMock, List<AckNackCall> Calls) FakeChannel()
    {
        var calls = new List<AckNackCall>();
        var mock = new Mock<IChannel>();

        // RabbitMQ.Client 7.x's IChannel.BasicAckAsync/BasicNackAsync return
        // ValueTask (not Task) — Moq's .Returns() must match that exactly.
        mock.Setup(c => c.BasicAckAsync(It.IsAny<ulong>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<ulong, bool, CancellationToken>((tag, multiple, _) =>
                calls.Add(new AckNackCall("ack", tag, multiple, false)))
            .Returns(ValueTask.CompletedTask);

        mock.Setup(c => c.BasicNackAsync(
                It.IsAny<ulong>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<ulong, bool, bool, CancellationToken>((tag, multiple, requeue, _) =>
                calls.Add(new AckNackCall("nack", tag, multiple, requeue)))
            .Returns(ValueTask.CompletedTask);

        return (mock, calls);
    }

    // RabbitMQ.Client 7.x's BasicDeliverEventArgs is constructor-initialized only
    // (get-only properties, no object-initializer/settable members) — all fields
    // are supplied positionally.
    private static BasicDeliverEventArgs Delivery(ulong deliveryTag, byte[] body) => new(
        consumerTag: "test-consumer",
        deliveryTag: deliveryTag,
        redelivered: false,
        exchange: "axiam.authz.request",
        routingKey: "authz.request",
        properties: new BasicProperties(),
        body: body,
        cancellationToken: CancellationToken.None);

    // ---- (a) success -> exactly one BasicAckAsync ---------------------------

    [Fact]
    public async Task ValidSignatureAndSuccessfulHandler_Acks()
    {
        (byte[] signingKey, byte[] validBody, _, _) = LoadHmacFixtureBodies();
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        bool handlerInvoked = false;

        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object,
            signingKey,
            (_, _) =>
            {
                handlerInvoked = true;
                return Task.CompletedTask;
            },
            new RecordingLogger(),
            NewGuard());

        await received(new object(), Delivery(42, validBody));

        Assert.True(handlerInvoked, "handler must be invoked for a validly-signed body");
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("ack", call.Type);
        Assert.Equal(42UL, call.DeliveryTag);
        Assert.False(call.Multiple);
    }

    // ---- (b) HMAC-fail -> nack(no requeue) + handler NEVER invoked ----------

    [Fact]
    public async Task InvalidSignature_NacksWithoutRequeue_AndNeverInvokesHandler()
    {
        (byte[] signingKey, _, byte[] tamperedBody, string tamperedSignatureHex) = LoadHmacFixtureBodies();
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        bool handlerInvoked = false;

        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object,
            signingKey,
            (_, _) =>
            {
                handlerInvoked = true;
                return Task.CompletedTask;
            },
            logger,
            NewGuard());

        await received(new object(), Delivery(7, tamperedBody));

        Assert.False(handlerInvoked, "handler must NEVER be invoked for an unverified delivery");
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.Equal(7UL, call.DeliveryTag);
        Assert.False(call.Multiple);
        Assert.False(call.Requeue, "HMAC-fail must nack WITHOUT requeue");

        Assert.NotEmpty(logger.Warnings);

        // §8.4 security assertion: the log line must never contain the HMAC value.
        Assert.All(logger.Warnings, warning => Assert.DoesNotContain(tamperedSignatureHex, warning));
    }

    // ---- (c) PoisonMessageException -> nack(no requeue) ---------------------

    [Fact]
    public async Task PoisonMessageException_NacksWithoutRequeue()
    {
        (byte[] signingKey, byte[] validBody, _, _) = LoadHmacFixtureBodies();
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();

        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object,
            signingKey,
            (_, _) => throw new PoisonMessageException("poison message"),
            new RecordingLogger(),
            NewGuard());

        await received(new object(), Delivery(99, validBody));

        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.Equal(99UL, call.DeliveryTag);
        Assert.False(call.Multiple);
        Assert.False(call.Requeue, "PoisonMessageException must nack WITHOUT requeue");
    }

    // ---- (d) transient handler exception -> nack(requeue) -------------------

    [Fact]
    public async Task TransientHandlerException_NacksWithRequeue()
    {
        (byte[] signingKey, byte[] validBody, _, _) = LoadHmacFixtureBodies();
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();

        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object,
            signingKey,
            (_, _) => throw new InvalidOperationException("transient downstream failure"),
            new RecordingLogger(),
            NewGuard());

        await received(new object(), Delivery(13, validBody));

        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.Equal(13UL, call.DeliveryTag);
        Assert.False(call.Multiple);
        Assert.True(call.Requeue, "a transient (non-poison) handler exception must nack WITH requeue");
    }

    // ---- (e) NEW-4 replay protection: key_version < 2 -> nack(no requeue), handler never invoked ----

    [Fact]
    public async Task StaleKeyVersion_NacksWithoutRequeue_AndNeverInvokesHandler()
    {
        (byte[] signingKey, _, _, _) = LoadHmacFixtureBodies();

        // key_version is itself part of the signed canonical bytes (NEW-4), so
        // this is a FRESH, genuinely validly-signed message that just happens
        // to declare key_version=1 — not a mutated/tampered v2 body (that
        // would simply fail Hmac.Verify, proving nothing about the version
        // gate specifically). This models a legacy/downgrade producer whose
        // signature is cryptographically authentic but whose declared
        // key_version predates NEW-4's replay-protection guarantees.
        const string canonical =
            "{\"correlation_id\":\"11111111-1111-1111-1111-111111111111\"," +
            "\"tenant_id\":\"22222222-2222-2222-2222-222222222222\"," +
            "\"subject_id\":\"33333333-3333-3333-3333-333333333333\"," +
            "\"action\":\"read\"," +
            "\"resource_id\":\"44444444-4444-4444-4444-444444444444\"," +
            "\"key_version\":1," +
            "\"nonce\":\"60606060-6060-6060-6060-606060606060\"," +
            "\"issued_at\":\"2026-07-10T12:00:00Z\"}";
        const string signatureHex = "2f45fc1eb76d2b7f2cbafe214c13e1970e2a539831bef9abe2dd2b06480fff47";

        JsonObject message = JsonNode.Parse(canonical)!.AsObject();
        message["hmac_signature"] = signatureHex;
        byte[] staleKeyVersionBody = Encoding.UTF8.GetBytes(message.ToJsonString());

        Assert.True(Hmac.Verify(signingKey, staleKeyVersionBody), "test fixture must carry a genuinely valid HMAC signature");

        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        bool handlerInvoked = false;

        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object,
            signingKey,
            (_, _) =>
            {
                handlerInvoked = true;
                return Task.CompletedTask;
            },
            logger,
            NewGuard());

        await received(new object(), Delivery(21, staleKeyVersionBody));

        Assert.False(handlerInvoked, "handler must NEVER be invoked for a key_version < 2 delivery");
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.False(call.Requeue, "key_version < 2 must nack WITHOUT requeue");
        Assert.NotEmpty(logger.Warnings);
    }

    // ---- (f) NEW-4 replay protection: stale issued_at -> nack(no requeue), handler never invoked ----

    [Fact]
    public async Task StaleIssuedAt_NacksWithoutRequeue_AndNeverInvokesHandler()
    {
        (byte[] signingKey, byte[] validBody, _, _) = LoadHmacFixtureBodies();
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        bool handlerInvoked = false;

        // A guard whose clock is one full day past the fixture's issued_at is
        // far outside any reasonable skew (default 5 minutes) — the message
        // is authentic (HMAC verifies) but stale.
        ReplayGuard guard = NewGuard(clock: () => FixtureIssuedAt.AddDays(1));

        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object,
            signingKey,
            (_, _) =>
            {
                handlerInvoked = true;
                return Task.CompletedTask;
            },
            logger,
            guard);

        await received(new object(), Delivery(22, validBody));

        Assert.False(handlerInvoked, "handler must NEVER be invoked for a stale issued_at delivery");
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.False(call.Requeue, "a stale issued_at must nack WITHOUT requeue");
        Assert.NotEmpty(logger.Warnings);
    }

    // ---- (g) NEW-4 replay protection: replayed nonce -> nack(no requeue), handler never invoked ----

    [Fact]
    public async Task ReplayedNonce_SecondDeliveryNacksWithoutRequeue_AndNeverInvokesHandlerForTheReplay()
    {
        (byte[] signingKey, byte[] validBody, _, _) = LoadHmacFixtureBodies();
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        int handlerInvocations = 0;

        // One shared guard across both deliveries — nonce dedup is a no-op if
        // a fresh guard were built per delivery.
        ReplayGuard guard = NewGuard();

        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object,
            signingKey,
            (_, _) =>
            {
                handlerInvocations++;
                return Task.CompletedTask;
            },
            logger,
            guard);

        // First delivery of this nonce: accepted and acked.
        await received(new object(), Delivery(31, validBody));
        // Second delivery of the exact same (still authentic) body: rejected as a replay.
        await received(new object(), Delivery(32, validBody));

        Assert.Equal(1, handlerInvocations);
        Assert.Equal(2, calls.Count);
        Assert.Equal("ack", calls[0].Type);
        Assert.Equal("nack", calls[1].Type);
        Assert.False(calls[1].Requeue, "a replayed nonce must nack WITHOUT requeue");
        Assert.NotEmpty(logger.Warnings);
    }

    // ---- #882 (D-5): the handler receives the bytes that were verified, and only those ----------------

    private static readonly byte[] ReceivedBytesKey = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();

    private static byte[] SignedWire(string signedText) =>
        Encoding.UTF8.GetBytes(signedText[..^1] + ",\"hmac_signature\":\"" +
            Convert.ToHexString(HMACSHA256.HashData(ReceivedBytesKey, Encoding.UTF8.GetBytes(signedText))).ToLowerInvariant() + "\"}");

    [Fact]
    public async Task AGenuineMessageWithSpecialCharacters_VerifiesAndTheHandlerIsHandedTheVerifiedBytes()
    {
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        byte[] wire = SignedWire(HmacVerifyTests.SpecialCharsSigned);
        byte[]? seen = null;

        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object,
            ReceivedBytesKey,
            (body, _) =>
            {
                seen = body;
                return Task.CompletedTask;
            },
            new RecordingLogger(),
            NewGuard());

        await received(new object(), Delivery(5, wire));

        Assert.Equal("ack", Assert.Single(calls).Type);
        Assert.NotNull(seen);
        Assert.Equal(wire, seen); // the very bytes the HMAC covered (plus the trailing signature member)
        using System.Text.Json.JsonDocument parsed = System.Text.Json.JsonDocument.Parse(seen!);
        // Decoded from the verified bytes: \u00e9 -> é, \u001f -> U+001F, \\u0041 -> a literal backslash-u sequence.
        Assert.Equal("docs:a&b</\"c\">/'+ é \u001f \\u0041 é€", parsed.RootElement.GetProperty("action").GetString());
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("trailing")]
    public async Task ADuplicateKeyOrTrailingContent_IsNackedWithoutRequeue_AndTheHandlerNeverRuns(string kind)
    {
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        bool handlerInvoked = false;

        byte[] body;
        if (kind == "duplicate")
        {
            // Signed over the last-wins reading, so a verifier that re-serializes would accept it.
            const string wireText = """{"correlation_id":"c1","action":"read","action":"delete","key_version":2,"nonce":"n1","issued_at":"2026-07-10T12:00:00Z"}""";
            const string lastWins = """{"correlation_id":"c1","action":"delete","key_version":2,"nonce":"n1","issued_at":"2026-07-10T12:00:00Z"}""";
            string sig = Convert.ToHexString(HMACSHA256.HashData(ReceivedBytesKey, Encoding.UTF8.GetBytes(lastWins))).ToLowerInvariant();
            body = Encoding.UTF8.GetBytes(wireText[..^1] + ",\"hmac_signature\":\"" + sig + "\"}");
        }
        else
        {
            body = SignedWire(HmacVerifyTests.SpecialCharsSigned).Concat(Encoding.UTF8.GetBytes("\n{}")).ToArray();
        }

        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object,
            ReceivedBytesKey,
            (_, _) =>
            {
                handlerInvoked = true;
                return Task.CompletedTask;
            },
            logger,
            NewGuard());

        await received(new object(), Delivery(6, body));

        Assert.False(handlerInvoked);
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.False(call.Requeue);
        Assert.NotEmpty(logger.Warnings);
    }

    [Fact]
    public async Task AValidlySignedMessageOfAnotherShape_IsNackedWithoutRequeue_AndTheHandlerNeverRuns()
    {
        // A genuine cache-invalidation message (key_version, nonce, issued_at, signature last), signed under the same
        // tenant subkey, republished to an event consumer's queue: it verifies and passes the replay gate, but it is
        // neither an AuthzRequest nor an AuditEventMessage, so it must not reach the handler.
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        bool handlerInvoked = false;
        byte[] wire = SignedWire("""{"key_version":2,"nonce":"n1","issued_at":"2026-07-10T12:00:00Z"}""");
        Assert.True(Hmac.Verify(ReceivedBytesKey, wire), "the message must be genuinely signed");

        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object,
            ReceivedBytesKey,
            (_, _) =>
            {
                handlerInvoked = true;
                return Task.CompletedTask;
            },
            logger,
            NewGuard());

        await received(new object(), Delivery(8, wire));

        Assert.False(handlerInvoked);
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.False(call.Requeue);
        Assert.NotEmpty(logger.Warnings);
    }

    [Theory]
    [InlineData(AmqpEventType.AuthzRequest, """{"correlation_id":"11111111-1111-1111-1111-111111111111","tenant_id":"22222222-2222-2222-2222-222222222222","subject_id":"33333333-3333-3333-3333-333333333333","action":"a","resource_id":"44444444-4444-4444-4444-444444444444","key_version":2,"nonce":"55555555-5555-5555-5555-555555555555","issued_at":"2026-07-10T12:00:00Z"}""")]
    [InlineData(AmqpEventType.AuthzRequest, """{"correlation_id":"11111111-1111-1111-1111-111111111111","tenant_id":"22222222-2222-2222-2222-222222222222","subject_id":"33333333-3333-3333-3333-333333333333","action":"a","resource_id":"44444444-4444-4444-4444-444444444444","scope":"x","key_version":2,"nonce":"55555555-5555-5555-5555-555555555555","issued_at":"2026-07-10T12:00:00Z"}""")]
    [InlineData(AmqpEventType.AuditEvent, """{"tenant_id":"22222222-2222-2222-2222-222222222222","actor_id":"33333333-3333-3333-3333-333333333333","actor_type":"user","action":"x","outcome":"success","key_version":2,"nonce":"55555555-5555-5555-5555-555555555555","issued_at":"2026-07-10T12:00:00Z"}""")]
    [InlineData(AmqpEventType.AuditEvent, """{"tenant_id":"22222222-2222-2222-2222-222222222222","actor_id":"33333333-3333-3333-3333-333333333333","actor_type":"user","action":"x","resource_id":"44444444-4444-4444-4444-444444444444","outcome":"success","ip_address":"1.2.3.4","metadata":{"k":"v"},"key_version":2,"nonce":"55555555-5555-5555-5555-555555555555","issued_at":"2026-07-10T12:00:00Z"}""")]
    public async Task TheConfiguredTypesLayout_ReachesTheHandler(AmqpEventType type, string signed)
    {
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        bool handlerInvoked = false;

        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object,
            ReceivedBytesKey,
            (_, _) =>
            {
                handlerInvoked = true;
                return Task.CompletedTask;
            },
            new RecordingLogger(),
            NewGuard(),
            type);

        await received(new object(), Delivery(9, SignedWire(signed)));

        Assert.True(handlerInvoked);
        Assert.Equal("ack", Assert.Single(calls).Type);
    }

    // ---- contract 1.69 §8 alignment (OI-13): reference vectors fed as wire_json; the negative list -----------

    private static JsonObject FixtureVector(string name)
    {
        JsonObject root = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "v2_reference_vectors.json")))!.AsObject();
        return root[name]!.AsObject();
    }

    private static byte[] FixtureSubkey() =>
        Convert.FromHexString(JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "v2_reference_vectors.json")))!["hkdf"]!["derived_subkey_hex"]!.GetValue<string>());

    private static async Task<(bool HandlerRan, byte[]? Seen, List<AckNackCall> Calls, RecordingLogger Logger)> Feed(
        byte[] key, byte[] body, AmqpEventType type = AmqpEventType.AuthzRequest)
    {
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        bool ran = false;
        byte[]? seen = null;
        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object, key, (b, _) => { ran = true; seen = b; return Task.CompletedTask; }, logger, NewGuard(), type);
        await received(new object(), Delivery(40, body));
        return (ran, seen, calls, logger);
    }

    [Theory]
    [InlineData("authz_request")]
    [InlineData("audit_event")]
    public async Task TheReferenceVectorWireJson_CutsToTheCanonicalBytes_VerifiesPassesTheLayoutAndDispatches(string name)
    {
        JsonObject vector = FixtureVector(name);
        byte[] wire = Encoding.UTF8.GetBytes(vector["wire_json"]!.GetValue<string>());

        Assert.True(SignedJson.TryCutTrailingSignature(wire, 64, out byte[]? canonical, out _));
        Assert.Equal(vector["canonical_signed_json"]!.GetValue<string>(), Encoding.UTF8.GetString(canonical!));
        Assert.True(Hmac.Verify(FixtureSubkey(), wire));
        AmqpEventType type = name == "authz_request" ? AmqpEventType.AuthzRequest : AmqpEventType.AuditEvent;
        Assert.True(SignedJson.MatchesLayout(canonical!, type));

        (bool ran, byte[]? seen, List<AckNackCall> calls, _) = await Feed(FixtureSubkey(), wire, type);

        Assert.True(ran);
        Assert.Equal(wire, seen);
        Assert.Equal("ack", Assert.Single(calls).Type);
    }

    public static IEnumerable<object[]> RefusedBodies()
    {
        const string good = """{"correlation_id":"c","tenant_id":"t","subject_id":"s","action":"a","resource_id":"r","key_version":2,"nonce":"n","issued_at":"2026-07-10T12:00:00Z"}""";
        yield return new object[] { "nested duplicate member", """{"correlation_id":"c","tenant_id":"t","subject_id":"s","action":"a","resource_id":"r","key_version":2,"nonce":"n","issued_at":"2026-07-10T12:00:00Z","x":{"k":1,"k":2}}""", false };
        yield return new object[] { "trailing newline", good, true };
        yield return new object[] { "trailing space", good, true };
        yield return new object[] { "reordered members", """{"tenant_id":"t","correlation_id":"c","subject_id":"s","action":"a","resource_id":"r","key_version":2,"nonce":"n","issued_at":"2026-07-10T12:00:00Z"}""", false };
        yield return new object[] { "extra member", """{"correlation_id":"c","tenant_id":"t","subject_id":"s","action":"a","resource_id":"r","key_version":2,"nonce":"n","issued_at":"2026-07-10T12:00:00Z","extra":1}""", false };
        yield return new object[] { "top-level names that fold together", """{"correlation_id":"c","tenant_id":"t","subject_id":"s","action":"a","Action":"b","resource_id":"r","key_version":2,"nonce":"n","issued_at":"2026-07-10T12:00:00Z"}""", false };
        yield return new object[] { "validly signed AuthzResponse", """{"correlation_id":"c","allowed":true,"reason_code":"allowed","tenant_id":"t","nonce":"n"}""", false };
    }

    [Theory]
    [MemberData(nameof(RefusedBodies))]
    public async Task ARefusedBody_IsNackedWithoutRequeue_AndTheHandlerNeverRuns(string name, string signedText, bool appendAfterBrace)
    {
        byte[] wire = SignedWire(signedText);
        if (appendAfterBrace)
        {
            wire = wire.Concat(Encoding.ASCII.GetBytes(name == "trailing newline" ? "\n" : " ")).ToArray();
        }

        (bool ran, _, List<AckNackCall> calls, RecordingLogger logger) = await Feed(ReceivedBytesKey, wire);

        Assert.False(ran, name);
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.False(call.Requeue);
        Assert.NotEmpty(logger.Warnings);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("number")]
    [InlineData("not last")]
    [InlineData("missing")]
    public async Task ASignatureMemberThatIsNullNonStringNotLastOrMissing_IsNackedAndNeverRepaired(string kind)
    {
        string sig = new string('a', 64);
        string body = kind switch
        {
            "null" => """{"correlation_id":"c","tenant_id":"t","subject_id":"s","action":"a","resource_id":"r","key_version":2,"nonce":"n","issued_at":"2026-07-10T12:00:00Z","hmac_signature":null}""",
            "number" => """{"correlation_id":"c","tenant_id":"t","subject_id":"s","action":"a","resource_id":"r","key_version":2,"nonce":"n","issued_at":"2026-07-10T12:00:00Z","hmac_signature":1}""",
            "not last" => $$"""{"correlation_id":"c","tenant_id":"t","subject_id":"s","action":"a","resource_id":"r","key_version":2,"nonce":"n","hmac_signature":"{{sig}}","issued_at":"2026-07-10T12:00:00Z"}""",
            _ => """{"correlation_id":"c","tenant_id":"t","subject_id":"s","action":"a","resource_id":"r","key_version":2,"nonce":"n","issued_at":"2026-07-10T12:00:00Z"}""",
        };

        (bool ran, _, List<AckNackCall> calls, _) = await Feed(ReceivedBytesKey, Encoding.UTF8.GetBytes(body));

        Assert.False(ran);
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.False(call.Requeue);
    }

    [Fact]
    public async Task AGenuineMessageWithAngleBracketsAmpersandNonAsciiAndAUnicodeEscape_VerifiesAndDispatches()
    {
        const string signed = """{"correlation_id":"11111111-1111-1111-1111-111111111111","tenant_id":"22222222-2222-2222-2222-222222222222","subject_id":"33333333-3333-3333-3333-333333333333","action":"<a>&b \u00e9 é \u001f","resource_id":"44444444-4444-4444-4444-444444444444","key_version":2,"nonce":"55555555-5555-5555-5555-555555555555","issued_at":"2026-07-10T12:00:00Z"}""";

        (bool ran, _, List<AckNackCall> calls, _) = await Feed(ReceivedBytesKey, SignedWire(signed));

        Assert.True(ran);
        Assert.Equal("ack", Assert.Single(calls).Type);
    }

    // ---- contract 1.69 D-8 / D-9 / D-10: typed consume, the discard event, BOM refusal ------------------------------

    private static string Wire(string vector) =>
        FixtureVector(vector)["wire_json"]!.GetValue<string>();

    private static string FlipLastSignatureDigit(string wireJson)
    {
        int end = wireJson.LastIndexOf("\"}", StringComparison.Ordinal);
        char c = wireJson[end - 1];
        return wireJson[..(end - 1)] + (c == '0' ? '1' : '0') + wireJson[end..];
    }

    private static string Field(Dictionary<string, string> evt, string name) => evt[name];

    [Theory]
    [InlineData("audit_event", AmqpEventType.AuthzRequest, false)]
    [InlineData("authz_request", AmqpEventType.AuditEvent, false)]
    [InlineData("audit_event", AmqpEventType.AuthzRequest, true)]
    [InlineData("authz_request", AmqpEventType.AuditEvent, true)]
    public async Task TheOtherTypesGenuineSignedWireJson_IsRefusedAsMalformed_BeforeTheHmac_EvenWithASignatureDigitChanged(
        string vector, AmqpEventType configured, bool flipped)
    {
        string wire = flipped ? FlipLastSignatureDigit(Wire(vector)) : Wire(vector);
        string signature = FixtureVector(vector)["hmac_signature_hex"]!.GetValue<string>();

        (bool ran, _, List<AckNackCall> calls, RecordingLogger logger) = await Feed(FixtureSubkey(), Encoding.UTF8.GetBytes(wire), configured);

        Assert.False(ran, "a body with another signed type's layout is never handed to the application");
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.False(call.Requeue);
        Dictionary<string, string> evt = Assert.Single(logger.Events);
        Assert.Equal("malformed", Field(evt, "reason")); // not "signature": the typed check precedes the HMAC
        Assert.Equal("axiam.authz.request", Field(evt, "exchange"));
        Assert.Equal("authz.request", Field(evt, "routing_key"));
        Assert.Equal(ConsumerTenant, Field(evt, "tenant_id"));
        Assert.Contains("timestamp", evt.Keys);
        AssertNoSecrets(logger, signature, FixtureVector(vector)["message"]!["nonce"]!.GetValue<string>());
    }

    private static void AssertNoSecrets(RecordingLogger logger, string signatureHex, string nonce)
    {
        Assert.All(logger.Warnings, w =>
        {
            Assert.DoesNotContain(signatureHex, w);
            Assert.DoesNotContain(nonce, w);
        });
        Assert.All(logger.Events, e =>
            Assert.Equal(
                new[] { "exchange", "reason", "routing_key", "tenant_id", "timestamp" },
                e.Keys.Where(k => !k.StartsWith('{')).OrderBy(k => k, StringComparer.Ordinal).ToArray()));
    }

    [Theory]
    [InlineData("authz_request", AmqpEventType.AuthzRequest)]
    [InlineData("audit_event", AmqpEventType.AuditEvent)]
    public async Task EachVectorIsAcceptedByItsOwnTypedConsumer(string vector, AmqpEventType configured)
    {
        (bool ran, _, List<AckNackCall> calls, RecordingLogger logger) = await Feed(FixtureSubkey(), Encoding.UTF8.GetBytes(Wire(vector)), configured);

        Assert.True(ran);
        Assert.Equal("ack", Assert.Single(calls).Type);
        Assert.Empty(logger.Warnings);
    }

    [Theory]
    [InlineData("authz_request", AmqpEventType.AuthzRequest)]
    [InlineData("audit_event", AmqpEventType.AuditEvent)]
    public async Task ABomPrefixedVector_IsRefusedAsMalformed_NeverStripped_NoExceptionEscapes_AndTheNextDeliveryIsProcessed(
        string vector, AmqpEventType configured)
    {
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        int handled = 0;
        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object, FixtureSubkey(), (_, _) => { handled++; return Task.CompletedTask; }, logger, NewGuard(), configured);

        byte[] good = Encoding.UTF8.GetBytes(Wire(vector));
        byte[] withBom = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(good).ToArray();

        await received(new object(), Delivery(50, withBom)); // must not throw
        await received(new object(), Delivery(51, good));

        Assert.Equal(1, handled); // only the genuine one, and still processed after the BOM body
        Assert.Equal("nack", calls[0].Type);
        Assert.False(calls[0].Requeue);
        Assert.Equal("ack", calls[1].Type);
        Assert.Equal("malformed", Assert.Single(logger.Events)["reason"]);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\r\n")]
    public async Task AnEmptyOrWhitespacePrefixedBody_IsRefusedAsMalformed(string prefix)
    {
        byte[] body = prefix.Length == 0 ? Array.Empty<byte>() : Encoding.ASCII.GetBytes(prefix + Wire("authz_request"));

        (bool ran, _, List<AckNackCall> calls, RecordingLogger logger) = await Feed(FixtureSubkey(), body);

        Assert.False(ran);
        Assert.False(Assert.Single(calls).Requeue);
        Assert.Equal("malformed", Assert.Single(logger.Events)["reason"]);
    }

    [Fact]
    public async Task AnEmptyRoutingKey_IsReportedAsReported_NotReplacedByTheQueue()
    {
        (Mock<IChannel> channelMock, _) = FakeChannel();
        var logger = new RecordingLogger();
        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(channelMock.Object, ReceivedBytesKey, (_, _) => Task.CompletedTask, logger, NewGuard());

        await received(new object(), new BasicDeliverEventArgs("t", 80, false, "", "", new BasicProperties(), Encoding.UTF8.GetBytes("x"), CancellationToken.None));

        Dictionary<string, string> evt = Assert.Single(logger.Events);
        Assert.Equal(string.Empty, evt["exchange"]);
        Assert.Equal(string.Empty, evt["routing_key"]);
    }

    [Fact]
    public async Task AFailingNack_AndAThrowingLogger_DoNotEscapeTheDeliveryLoop()
    {
        var mock = new Mock<IChannel>();
        mock.Setup(c => c.BasicNackAsync(It.IsAny<ulong>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Throws(new InvalidOperationException("channel closed"));
        var logger = new Mock<ILogger>();
        logger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);
        logger.Setup(l => l.Log(It.IsAny<LogLevel>(), It.IsAny<EventId>(), It.IsAny<It.IsAnyType>(), It.IsAny<Exception?>(),
            (Func<It.IsAnyType, Exception?, string>)It.IsAny<object>())).Throws(new InvalidOperationException("sink down"));
        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            mock.Object, FixtureSubkey(), (_, _) => Task.CompletedTask, logger.Object, NewGuard());

        await received(new object(), Delivery(60, Encoding.UTF8.GetBytes("garbage"))); // must not throw
    }

    // The reason order of §8 rule 4, one probe per position.

    private static string AuthzCanonical(string key = "2", string issuedAt = "2026-07-10T12:00:00Z", string nonce = "55555555-5555-5555-5555-555555555555") =>
        $$"""{"correlation_id":"11111111-1111-1111-1111-111111111111","tenant_id":"22222222-2222-2222-2222-222222222222","subject_id":"33333333-3333-3333-3333-333333333333","action":"read","resource_id":"44444444-4444-4444-4444-444444444444","key_version":{{key}},"nonce":"{{nonce}}","issued_at":"{{issuedAt}}"}""";

    public static IEnumerable<object[]> ReasonOrder()
    {
        string good = AuthzCanonical();
        yield return new object[] { "malformed", Encoding.UTF8.GetBytes("{not json") };
        yield return new object[] { "malformed", Encoding.UTF8.GetBytes(good + " trailing") };
        yield return new object[] { "unsigned", Encoding.UTF8.GetBytes(good) };
        // unsigned wins over a duplicate member (position 2 before 3)
        yield return new object[] { "unsigned", Encoding.UTF8.GetBytes(good[..^1] + ",\"action\":\"x\"}") };
        yield return new object[] { "malformed", SignedWire(good[..^1] + ",\"extra\":1}") }; // layout
        yield return new object[] { "signature", WrongKey(good) };
        yield return new object[] { "malformed", SignedWire(AuthzCanonical(nonce: "not-a-uuid")) }; // decode, after the HMAC
        yield return new object[] { "malformed", SignedWire(AuthzCanonical(issuedAt: "yesterday")) };
        yield return new object[] { "malformed", SignedWire(AuthzCanonical(key: "\"2\"")) };
        yield return new object[] { "key_version", SignedWire(AuthzCanonical(key: "1")) };
        yield return new object[] { "stale", SignedWire(AuthzCanonical(issuedAt: "2026-07-10T11:00:00Z")) };
    }

    private static byte[] WrongKey(string canonical) =>
        Encoding.UTF8.GetBytes(canonical[..^1] + ",\"hmac_signature\":\"" + new string('a', 64) + "\"}");

    [Theory]
    [MemberData(nameof(ReasonOrder))]
    public async Task EveryDiscard_LogsOneEventWithTheFirstReasonThatApplies(string reason, byte[] body)
    {
        (bool ran, _, List<AckNackCall> calls, RecordingLogger logger) = await Feed(ReceivedBytesKey, body);

        Assert.False(ran);
        Assert.False(Assert.Single(calls).Requeue);
        Dictionary<string, string> evt = Assert.Single(logger.Events);
        Assert.Equal(reason, evt["reason"]);
        Assert.Equal(ConsumerTenant, evt["tenant_id"]); // never read from the body
        Assert.Equal("axiam.authz.request", evt["exchange"]);
        Assert.Equal("authz.request", evt["routing_key"]);
        Assert.DoesNotContain("55555555-5555-5555-5555-555555555555", logger.Warnings[0]);
        Assert.DoesNotContain("22222222-2222-2222-2222-222222222222", logger.Warnings[0]); // the body's tenant, not ours
        Assert.Contains("timestamp", evt.Keys);
        Assert.Equal(
            new[] { "exchange", "reason", "routing_key", "tenant_id", "timestamp" },
            evt.Keys.Where(k => !k.StartsWith('{')).OrderBy(k => k, StringComparer.Ordinal).ToArray());
        Assert.DoesNotContain(new string('a', 64), logger.Warnings[0]);
    }

    [Fact]
    public async Task ANonceIsRecordedOnlyAfterEveryGatePasses_AndAReplayIsReportedAsReplay()
    {
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        int handled = 0;
        ReplayGuard guard = NewGuard();
        AsyncEventHandler<BasicDeliverEventArgs> received = NewHandler(
            channelMock.Object, ReceivedBytesKey, (_, _) => { handled++; return Task.CompletedTask; }, logger, guard);

        // Refused at the key_version gate: leaves no nonce behind...
        await received(new object(), Delivery(70, SignedWire(AuthzCanonical(key: "1"))));
        // ...so the same nonce under key_version 2 is not a replay.
        await received(new object(), Delivery(71, SignedWire(AuthzCanonical())));
        await received(new object(), Delivery(72, SignedWire(AuthzCanonical())));

        Assert.Equal(1, handled);
        Assert.Equal(new[] { "key_version", "replay" }, logger.Events.Select(e => e["reason"]).ToArray());
        Assert.Equal(new[] { "nack", "ack", "nack" }, calls.Select(c => c.Type).ToArray());
    }

    [Fact]
    public void TheConsumerTakesItsTypeAndTenant_ThereIsNoMatchAnyLayout()
    {
        System.Reflection.MethodInfo start = typeof(AxiamAmqpConsumer).GetMethod(nameof(AxiamAmqpConsumer.StartAsync))!;
        string[] names = start.GetParameters().Select(p => p.Name!).ToArray();
        Assert.Contains("eventType", names);
        Assert.Contains("tenantId", names);
        Assert.DoesNotContain(typeof(SignedJson).GetMethods(System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic),
            m => m.Name == "MatchesSignedLayout");
    }
}
