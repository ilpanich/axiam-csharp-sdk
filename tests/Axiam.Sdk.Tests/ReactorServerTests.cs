using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Core;
using Axiam.Sdk.Reactor;
using Axiam.Sdk.Tests.Fixtures;
using Microsoft.Extensions.Logging;
using Moq;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// <see cref="ReactorServer"/> end to end without a broker: the &#167;22.3 verify-before-handler
/// gate, the no-topology rule, fail-closed-on-our-own-errors, the unfiltered patch, the
/// timeout window, &#167;18 shutdown, &#167;19 telemetry, and the guarantee that the signing
/// key never reaches a log line.
///
/// <para>
/// Everything runs against a Moq-backed fake <see cref="IChannel"/> whose recorded
/// <see cref="Mock.Invocations"/> are what make "declares no exchange, queue or binding" an
/// assertion about behaviour rather than about source code.
/// </para>
/// </summary>
[Trait("Category", "Fast")]
public class ReactorServerTests
{
    /// <summary>The fixture's own <c>verified_at</c>; every event vector is fresh at this instant.</summary>
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-07-10T12:00:00Z", CultureInfo.InvariantCulture);

    private const string ReplyQueue = "amq.rabbitmq.reply-to.abc";

    private readonly JsonObject _fixture = ReactorVectors.Load();
    private readonly List<byte[]> _published = new();
    private readonly List<string> _settled = new();
    private readonly List<string> _logLines = new();

    private byte[] Subkey => ReactorVectors.Subkey(_fixture);

    private Guid TenantId => ReactorVectors.TenantId(_fixture);

    private Guid ReactorId => Guid.Parse(ReactorVectors.Text(_fixture, "reactor_id"));

    // ---- happy path --------------------------------------------------------

    [Fact]
    public async Task AVerifiedEvent_ReachesTheHandlerAndItsReplyIsSignedAndCorrelated()
    {
        ReactorEvent? seen = null;
        Mock<IChannel> channel = FakeChannel();
        await using ReactorServer server = await ServeAsync(channel, (e, _) =>
        {
            seen = e;
            return Task.FromResult(ReactorDecision.Mutated(new Dictionary<string, string>
            {
                ["ext.department"] = "eng",
            }));
        });

        await Deliver(server, EventBody("token_pre_issue"));

        Assert.NotNull(seen);
        Assert.Equal(ReactorEvents.TokenPreIssue, seen!.Event);
        Assert.Equal(TenantId, seen.TenantId);
        Assert.Equal(ReactorVectors.CorrelationId(_fixture), seen.CorrelationId);
        Assert.Equal(500, seen.TimeoutMs);
        Assert.Equal(2, seen.KeyVersion);
        Assert.Equal("alice", seen.Payload["sub"]!.GetValue<string>());
        Assert.Empty(seen.PriorPatch());

        byte[] reply = Assert.Single(_published);
        Assert.True(
            ReactorProtocol.VerifyEvent(Subkey, reply),
            "the reply must be signed with the same tenant subkey");

        JsonObject parsed = JsonNode.Parse(reply)!.AsObject();
        Assert.Equal(
            seen.CorrelationId.ToString("D", CultureInfo.InvariantCulture),
            parsed["correlation_id"]!.GetValue<string>());
        Assert.Equal("mutate", parsed["decision"]!.GetValue<string>());
        Assert.Equal("eng", parsed["patch"]!["ext.department"]!.GetValue<string>());
        Assert.Equal(2, parsed["key_version"]!.GetValue<int>());
        Assert.Contains("ack:1", _settled);

        // Replies go to the DEFAULT exchange with the reply queue as the routing key —
        // standard AMQP RPC, and publishing to "" declares nothing.
        channel.Verify(
            c => c.BasicPublishAsync(
                string.Empty, ReplyQueue, false, It.IsAny<BasicProperties>(), It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    // ---- §22.10 rule 1: no topology ----------------------------------------

    [Fact]
    public async Task TheRuntime_DeclaresNoExchangeNoQueueAndNoBinding()
    {
        Mock<IChannel> channel = FakeChannel();
        await using (ReactorServer server = await ServeAsync(channel, AlwaysAllow))
        {
            await Deliver(server, EventBody("login_post_auth"));
        }

        string[] invoked = channel.Invocations.Select(i => i.Method.Name).ToArray();
        Assert.DoesNotContain(invoked, name =>
            name.StartsWith("ExchangeDeclare", StringComparison.Ordinal) ||
            name.StartsWith("QueueDeclare", StringComparison.Ordinal) ||
            name.StartsWith("QueueBind", StringComparison.Ordinal) ||
            name.StartsWith("ExchangeBind", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheRuntime_ConsumesOnlyTheQueueItIsRegisteredAs()
    {
        Mock<IChannel> channel = FakeChannel();
        await using ReactorServer fromId = await ReactorServer.ReactorServeAsync(BaseOptions(channel));

        Assert.Equal(ReactorProtocol.QueueName(TenantId, ReactorId), fromId.Queue);
        channel.Verify(
            c => c.BasicConsumeAsync(
                ReactorProtocol.QueueName(TenantId, ReactorId), false, string.Empty, false, false, null,
                It.IsAny<IAsyncBasicConsumer>(), It.IsAny<CancellationToken>()),
            Times.Once);
        channel.Verify(
            c => c.BasicQosAsync(0, 16, false, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task AnExplicitlyNamedQueue_IsConsumedVerbatim()
    {
        Mock<IChannel> channel = FakeChannel();
        await using ReactorServer server = await ReactorServer.ReactorServeAsync(new ReactorServeOptions
        {
            Channel = channel.Object,
            TenantId = TenantId,
            SigningKey = Sensitive<byte[]>.Wrap(Subkey),
            Queue = "axiam.reactor.q.handed-to-us",
            Handler = AlwaysAllow,
            Clock = () => Now,
        });

        Assert.Equal("axiam.reactor.q.handed-to-us", server.Queue);
    }

    [Fact]
    public void HandlerAndListener_AreMutuallyExclusiveAndOneIsRequired()
    {
        ReactorServeOptions Neither() => new()
        {
            Channel = FakeChannel().Object,
            TenantId = TenantId,
            SigningKey = Sensitive<byte[]>.Wrap(Subkey),
            ReactorId = ReactorId,
        };

        Assert.Throws<InvalidOperationException>(() => Neither().ResolvedQueue);

        var both = new ReactorServeOptions
        {
            Channel = FakeChannel().Object,
            TenantId = TenantId,
            SigningKey = Sensitive<byte[]>.Wrap(Subkey),
            ReactorId = ReactorId,
            Handler = AlwaysAllow,
            Listener = (_, _) => Task.CompletedTask,
        };
        Assert.Throws<InvalidOperationException>(() => both.ResolvedQueue);

        var neitherQueue = new ReactorServeOptions
        {
            Channel = FakeChannel().Object,
            TenantId = TenantId,
            SigningKey = Sensitive<byte[]>.Wrap(Subkey),
            Handler = AlwaysAllow,
        };
        Assert.Throws<InvalidOperationException>(() => neitherQueue.ResolvedQueue);

        var bothQueues = new ReactorServeOptions
        {
            Channel = FakeChannel().Object,
            TenantId = TenantId,
            SigningKey = Sensitive<byte[]>.Wrap(Subkey),
            Queue = "q",
            ReactorId = ReactorId,
            Handler = AlwaysAllow,
        };
        Assert.Throws<InvalidOperationException>(() => bothQueues.ResolvedQueue);
    }

    // ---- §22.10 rule 2: fail closed on our own errors ----------------------

    [Fact]
    public async Task AHandlerThatThrows_ProducesNoReplyRatherThanASynthesizedAllow()
    {
        Mock<IChannel> channel = FakeChannel();
        await using (ReactorServer server = await ServeAsync(channel, (_, _) =>
                         throw new InvalidOperationException("fraud backend unreachable")))
        {
            await Deliver(server, EventBody("login_post_auth"));
        }

        Assert.Empty(_published);
        Assert.Contains("nack:1:norequeue", _settled);
        Assert.Contains(_logLines, line => line.Contains("publishing NO reply", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnEventThatFailsAnySection8Gate_NeverReachesTheHandler()
    {
        // (a) wrong signature — the payload was rewritten after signing
        await AssertHandlerNeverRuns(Tamper(node => node["payload"] = new JsonObject { ["sub"] = "root" }));

        // (b) key_version downgraded after signing — refused before the MAC is computed
        await AssertHandlerNeverRuns(Tamper(node => node["key_version"] = 1));

        // (c) stale, (d) future
        await AssertHandlerNeverRuns(SignedEvent(issuedAt: Now.AddSeconds(-301)));
        await AssertHandlerNeverRuns(SignedEvent(issuedAt: Now.AddSeconds(301)));

        // (e) another tenant's event, correctly signed with a key that verifies here
        await AssertHandlerNeverRuns(SignedEvent(tenantId: Guid.NewGuid()));
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{\"key_version\":2}")]
    [InlineData("{\"key_version\":\"two\"}")]
    public async Task EveryMalformedBody_IsRefusedBeforeTheHandler(string raw)
    {
        await AssertHandlerNeverRuns(Encoding.UTF8.GetBytes(raw));
    }

    [Theory]
    [InlineData("tenant_id")]
    [InlineData("correlation_id")]
    [InlineData("event")]
    [InlineData("payload")]
    [InlineData("timeout_ms")]
    [InlineData("nonce")]
    [InlineData("issued_at")]
    public async Task EveryMalformedField_IsRefusedWithASecurityEventAndNoReply(string field)
    {
        // Re-signed each time, so the body is authentic and ONLY the field's shape is wrong —
        // proving each gate refuses on its own merits rather than on a broken MAC.
        //
        // `event` is blanked rather than given a junk name on purpose: an unrecognised event
        // name is NOT a refusal here. The registry is the server's dispatch table, and a
        // runtime that second-guessed it would be re-deriving server policy from a stale
        // constant list. What the runtime refuses is a *missing* event.
        JsonNode? broken = field switch
        {
            "timeout_ms" => 0,
            "event" => string.Empty,
            "payload" => "not-an-object",
            _ => "not-valid",
        };

        await AssertHandlerNeverRuns(SignedEvent(mutate: node => node[field] = broken));
        Assert.Contains(_logLines, line => line.Contains("axiam_sdk_security", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AReplayedNonce_IsRefusedOnTheSecondDelivery()
    {
        int handled = 0;
        Mock<IChannel> channel = FakeChannel();
        byte[] body = EventBody("token_pre_issue");

        await using (ReactorServer server = await ServeAsync(channel, (_, _) =>
                     {
                         handled++;
                         return Task.FromResult(ReactorDecision.Allowed());
                     }))
        {
            await Deliver(server, body);
            await Deliver(server, body);
        }

        Assert.Equal(1, handled);
        Assert.Single(_published);
    }

    // ---- §22.10 rule 3: never filter a patch -------------------------------

    /// <summary>
    /// &#167;22.4 rule 1 / &#167;22.13: a handler returning a patch containing a forbidden key
    /// sends it <b>unfiltered</b>. Silently dropping <c>sub</c> would leave the reactor author
    /// believing a claim was set when it was discarded — the exact failure the server refuses
    /// to produce.
    /// </summary>
    [Fact]
    public async Task AForbiddenPatchKey_IsSentUnfilteredRatherThanQuietlyDropped()
    {
        Mock<IChannel> channel = FakeChannel();
        await using (ReactorServer server = await ServeAsync(channel, (_, _) => Task.FromResult(
                         ReactorDecision.Mutated(new Dictionary<string, string>
                         {
                             ["ext.department"] = "eng",
                             ["sub"] = "root",
                         }))))
        {
            await Deliver(server, EventBody("token_pre_issue"));
        }

        JsonObject patch = JsonNode.Parse(Assert.Single(_published))!["patch"]!.AsObject();
        Assert.Equal("root", patch["sub"]!.GetValue<string>());
        Assert.Equal("eng", patch["ext.department"]!.GetValue<string>());
        Assert.False(
            ReactorEvents.Spec(ReactorEvents.TokenPreIssue)!.PatchFieldAllowed("sub"),
            "and the SDK knew it was forbidden — it sent it anyway, so the author finds out");
    }

    // ---- §22.3 / rule 4: the window ----------------------------------------

    [Fact]
    public async Task AReply_IsAbandonedRatherThanPublishedAfterTheWindowClosed()
    {
        var clock = new MovingClock(Now);
        Mock<IChannel> channel = FakeChannel();
        await using (ReactorServer server = await ServeAsync(channel, (e, _) =>
                     {
                         clock.Advance(TimeSpan.FromMilliseconds(e.TimeoutMs + 1));
                         return Task.FromResult(ReactorDecision.Allowed());
                     }, clock.Now))
        {
            await Deliver(server, EventBody("token_pre_issue"));
        }

        Assert.Empty(_published);
        Assert.Contains("ack:1", _settled);
        Assert.Contains(_logLines, line => line.Contains("abandoning the reply", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnEvent_CarriesItsWindowToTheHandler()
    {
        ReactorEvent? seen = null;
        Mock<IChannel> channel = FakeChannel();
        await using ReactorServer server = await ServeAsync(channel, (e, _) =>
        {
            seen = e;
            return Task.FromResult(ReactorDecision.Allowed());
        });

        await Deliver(server, EventBody("login_post_auth"));

        Assert.Equal(1000, seen!.TimeoutMs);
        Assert.Equal(Now.AddMilliseconds(1000), seen.Deadline);
        Assert.Equal(TimeSpan.FromSeconds(1), seen.Remaining(Now));
        Assert.Equal(TimeSpan.Zero, seen.Remaining(Now.AddSeconds(5)));
    }

    [Fact]
    public async Task TheTimeout_IsClampedToTheChainCeiling()
    {
        ReactorEvent? seen = null;
        Mock<IChannel> channel = FakeChannel();
        await using ReactorServer server = await ServeAsync(channel, (e, _) =>
        {
            seen = e;
            return Task.FromResult(ReactorDecision.Allowed());
        });

        await Deliver(server, SignedEvent(timeoutMs: 60_000));

        Assert.Equal(ReactorProtocol.ChainCeilingMs, seen!.TimeoutMs);
    }

    [Fact]
    public async Task ADeliveryWithNoReplyTo_PublishesNothing()
    {
        Mock<IChannel> channel = FakeChannel();
        await using (ReactorServer server = await ServeAsync(channel, AlwaysAllow))
        {
            await Deliver(server, EventBody("token_pre_issue"), replyTo: null);
        }

        Assert.Empty(_published);
        Assert.Contains("ack:1", _settled);
        Assert.Contains(_logLines, line => line.Contains("carried no reply_to", StringComparison.Ordinal));
    }

    // ---- §22.5 listeners ---------------------------------------------------

    [Fact]
    public async Task AListener_ObservesAndPublishesNothing()
    {
        ReactorEvent? observed = null;
        Mock<IChannel> channel = FakeChannel();
        await using (ReactorServer server = await ReactorServer.ReactorServeAsync(new ReactorServeOptions
        {
            Channel = channel.Object,
            TenantId = TenantId,
            SigningKey = Sensitive<byte[]>.Wrap(Subkey),
            ReactorId = ReactorId,
            Listener = (e, _) =>
            {
                observed = e;
                return Task.CompletedTask;
            },
            Logger = new RecordingLogger(_logLines),
            Clock = () => Now,
        }))
        {
            await Deliver(server, EventBody("token_pre_issue"));
        }

        Assert.NotNull(observed);
        Assert.Empty(_published);
        Assert.Contains("ack:1", _settled);
    }

    [Fact]
    public async Task AListenerThatThrows_AlsoPublishesNothing()
    {
        Mock<IChannel> channel = FakeChannel();
        await using (ReactorServer server = await ReactorServer.ReactorServeAsync(new ReactorServeOptions
        {
            Channel = channel.Object,
            TenantId = TenantId,
            SigningKey = Sensitive<byte[]>.Wrap(Subkey),
            ReactorId = ReactorId,
            Listener = (_, _) => throw new InvalidOperationException("counter backend down"),
            Logger = new RecordingLogger(_logLines),
            Clock = () => Now,
        }))
        {
            await Deliver(server, EventBody("token_pre_issue"));
        }

        Assert.Empty(_published);
        Assert.Contains("nack:1:norequeue", _settled);
    }

    // ---- §18 deterministic shutdown ----------------------------------------

    [Fact]
    public async Task Dispose_CancelsTheConsumerAndIsIdempotent()
    {
        Mock<IChannel> channel = FakeChannel();
        ReactorServer server = await ServeAsync(channel, AlwaysAllow);

        Assert.False(server.IsClosed);
        Assert.Equal(0, server.InFlight);

        await server.DisposeAsync();
        await server.DisposeAsync();

        Assert.True(server.IsClosed);
        channel.Verify(c => c.BasicCancelAsync(It.IsAny<string>(), false, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ADeliveryArrivingAfterClose_IsRequeuedRatherThanAnswered()
    {
        Mock<IChannel> channel = FakeChannel();
        ReactorServer server = await ServeAsync(channel, AlwaysAllow);
        await server.DisposeAsync();

        await Deliver(server, EventBody("token_pre_issue"));

        Assert.Empty(_published);
        Assert.Contains("nack:1:requeue", _settled);
    }

    [Fact]
    public async Task ClosingOverATornDownChannel_StillCompletes()
    {
        Mock<IChannel> channel = FakeChannel();
        channel.Setup(c => c.BasicCancelAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("channel already closed"));

        ReactorServer server = await ServeAsync(channel, AlwaysAllow);
        await server.DisposeAsync();

        Assert.True(server.IsClosed);
    }

    // ---- §19 telemetry -----------------------------------------------------

    [Fact]
    public async Task OnePairOfTelemetryEvents_IsEmittedPerDispatch()
    {
        var events = new List<TelemetryEvent>();
        Mock<IChannel> channel = FakeChannel();
        await using (ReactorServer server = await ReactorServer.ReactorServeAsync(
                         BaseOptions(channel, telemetry: events.Add)))
        {
            await Deliver(server, EventBody("token_pre_issue"));
        }

        RequestStartEvent start = Assert.Single(events.OfType<RequestStartEvent>());
        RequestEndEvent end = Assert.Single(events.OfType<RequestEndEvent>());

        Assert.Equal(ReactorServer.TelemetryOperation, start.Operation);
        Assert.Equal(ReactorServer.TelemetryMethod, start.Method);
        Assert.Equal(1, start.Attempt);
        // The path template is the EVENT name — a closed set of five values, never a UUID.
        Assert.Equal(ReactorEvents.TokenPreIssue, start.PathTemplate);
        Assert.Contains(ReactorEvents.Registry, spec => spec.Name == start.PathTemplate);

        Assert.Equal(TelemetryOutcome.Success, end.Outcome);
        Assert.Null(end.StatusCode);
    }

    [Fact]
    public async Task ATelemetryHookThatThrows_CannotFailTheDispatch()
    {
        Mock<IChannel> channel = FakeChannel();
        await using (ReactorServer server = await ReactorServer.ReactorServeAsync(
                         BaseOptions(channel, telemetry: _ => throw new InvalidOperationException("sink down"))))
        {
            await Deliver(server, EventBody("token_pre_issue"));
        }

        Assert.Single(_published);
        Assert.Contains("ack:1", _settled);
    }

    [Fact]
    public async Task AFailedDispatch_ClosesItsTelemetryPairWithFailure()
    {
        var events = new List<TelemetryEvent>();
        Mock<IChannel> channel = FakeChannel();
        await using (ReactorServer server = await ReactorServer.ReactorServeAsync(
                         BaseOptions(
                             channel,
                             telemetry: events.Add,
                             handler: (_, _) => throw new InvalidOperationException("nope"))))
        {
            await Deliver(server, EventBody("token_pre_issue"));
        }

        Assert.Equal(TelemetryOutcome.Failure, Assert.Single(events.OfType<RequestEndEvent>()).Outcome);
    }

    // ---- §22.12 the signing key is never logged ----------------------------

    [Fact]
    public async Task TheSigningKey_NeverAppearsInAnyLogLineAndNeitherDoesThePayload()
    {
        string subkeyHex = ReactorVectors.Text(_fixture["hkdf"]!.AsObject(), "derived_subkey_hex");
        Mock<IChannel> channel = FakeChannel();

        await using (ReactorServer server = await ServeAsync(channel, (_, _) => throw new InvalidOperationException("boom")))
        {
            await Deliver(server, EventBody("token_pre_issue"));
            await Deliver(server, Encoding.UTF8.GetBytes("{\"key_version\":2,\"hmac_signature\":\"00\"}"));
        }

        Assert.NotEmpty(_logLines);
        string all = string.Join("\n", _logLines);
        Assert.DoesNotContain(subkeyHex, all, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("alice", all, StringComparison.Ordinal);

        // The Sensitive wrapper itself never renders the key either.
        Assert.Equal("[SENSITIVE]", Sensitive<byte[]>.Wrap(Subkey).ToString());
    }

    [Fact]
    public async Task AnEventsToString_CarriesNoPayload()
    {
        ReactorEvent? seen = null;
        Mock<IChannel> channel = FakeChannel();
        await using ReactorServer server = await ServeAsync(channel, (e, _) =>
        {
            seen = e;
            return Task.FromResult(ReactorDecision.Allowed());
        });

        await Deliver(server, EventBody("token_pre_issue"));

        string rendered = seen!.ToString();
        Assert.DoesNotContain("alice", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("portal", rendered, StringComparison.Ordinal);
        Assert.Contains(ReactorEvents.TokenPreIssue, rendered, StringComparison.Ordinal);
        Assert.Contains(seen.CorrelationId.ToString(), rendered, StringComparison.Ordinal);
    }

    // ---- chained events ----------------------------------------------------

    [Fact]
    public async Task AnEarlierReactorsPatch_IsSurfacedAsReadOnlyContext()
    {
        ReactorEvent? seen = null;
        Mock<IChannel> channel = FakeChannel();
        await using ReactorServer server = await ServeAsync(channel, (e, _) =>
        {
            seen = e;
            return Task.FromResult(ReactorDecision.Allowed());
        });

        await Deliver(server, SignedEvent(payload: new JsonObject
        {
            ["sub"] = "alice",
            [ReactorEvent.ReactorPatchKey] = new JsonObject
            {
                ["ext.cost_center"] = "42",
                ["ext.numeric"] = 7, // not a string — ignored rather than coerced
            },
        }));

        IReadOnlyDictionary<string, string> prior = seen!.PriorPatch();
        Assert.Equal("42", prior["ext.cost_center"]);
        Assert.False(prior.ContainsKey("ext.numeric"));
        Assert.Single(prior);
    }

    [Fact]
    public async Task AnEventExposesItsRegistrySpec()
    {
        ReactorEvent? seen = null;
        Mock<IChannel> channel = FakeChannel();
        await using ReactorServer server = await ServeAsync(channel, (e, _) =>
        {
            seen = e;
            return Task.FromResult(ReactorDecision.Allowed());
        });

        await Deliver(server, EventBody("token_pre_issue"));

        Assert.Equal(ReactorEvents.TokenPreIssue, seen!.Spec()!.Name);
        Assert.True(seen.Spec()!.Mutable);
        Assert.Equal(FailurePolicy.FailOpen, seen.Spec()!.DefaultFailurePolicy);
        Assert.Equal(Now, seen.IssuedAt);
        Assert.Equal(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), seen.Nonce);
    }

    // ---- helpers -----------------------------------------------------------

    private static Task<ReactorDecision> AlwaysAllow(ReactorEvent e, CancellationToken ct) =>
        Task.FromResult(ReactorDecision.Allowed());

    private async Task AssertHandlerNeverRuns(byte[] body)
    {
        bool ran = false;
        _published.Clear();
        Mock<IChannel> channel = FakeChannel();

        await using (ReactorServer server = await ServeAsync(channel, (_, _) =>
                     {
                         ran = true;
                         return Task.FromResult(ReactorDecision.Allowed());
                     }))
        {
            await Deliver(server, body);
        }

        Assert.False(ran, "the handler must be unreachable for a refused event");
        Assert.Empty(_published);
    }

    private ReactorServeOptions BaseOptions(
        Mock<IChannel> channel,
        TelemetryHook? telemetry = null,
        ReactorHandler? handler = null,
        Func<DateTimeOffset>? clock = null) => new()
    {
        Channel = channel.Object,
        TenantId = TenantId,
        SigningKey = Sensitive<byte[]>.Wrap(Subkey),
        ReactorId = ReactorId,
        Handler = handler ?? AlwaysAllow,
        Logger = new RecordingLogger(_logLines),
        Clock = clock ?? (() => Now),
        TelemetryHook = telemetry,
    };

    private Task<ReactorServer> ServeAsync(
        Mock<IChannel> channel, ReactorHandler handler, Func<DateTimeOffset>? clock = null) =>
        ReactorServer.ReactorServeAsync(BaseOptions(channel, handler: handler, clock: clock));

    private async Task Deliver(ReactorServer server, byte[] body, string? replyTo = ReplyQueue)
    {
        var properties = new BasicProperties
        {
            CorrelationId = ReactorVectors.CorrelationId(_fixture).ToString(),
        };
        if (replyTo is not null)
        {
            properties.ReplyTo = replyTo;
        }

        await server.CreateReceivedHandler()(
            new object(),
            new BasicDeliverEventArgs(
                consumerTag: "test-consumer",
                deliveryTag: 1,
                redelivered: false,
                exchange: ReactorProtocol.Exchange,
                routingKey: ReactorProtocol.RoutingKey(TenantId, ReactorEvents.TokenPreIssue),
                properties: properties,
                body: body,
                cancellationToken: CancellationToken.None));
    }

    private byte[] EventBody(string vectorName) =>
        ReactorVectors.WireBody(_fixture["server_to_reactor"]![vectorName]!.AsObject());

    private byte[] Tamper(Action<JsonObject> mutation)
    {
        JsonObject vector = _fixture["server_to_reactor"]!["token_pre_issue"]!.AsObject();
        JsonObject node = ReactorVectors.CanonicalObject(vector);
        node["hmac_signature"] = ReactorVectors.Text(vector, "hmac_signature_hex");
        mutation(node);
        return ReactorVectors.Encode(node);
    }

    /// <summary>
    /// Builds a server-side event body longhand — the same declared field order and the same
    /// <c>"hmac_signature": null</c> canonicalization the AXIAM server uses, written out here
    /// rather than delegating to <see cref="ReactorProtocol"/>.
    ///
    /// <para>
    /// Writing it twice is the point. If a test signed events with the very code under test, a
    /// canonicalization bug would cancel out and every assertion would still pass — which is
    /// exactly the failure mode the &#167;22.13 vectors exist to catch. Those vectors remain
    /// the ground truth; this helper only varies the fields the fixture pins.
    /// </para>
    /// </summary>
    private byte[] SignedEvent(
        Guid? tenantId = null,
        string eventName = ReactorEvents.TokenPreIssue,
        DateTimeOffset? issuedAt = null,
        int timeoutMs = 500,
        JsonObject? payload = null,
        Action<JsonObject>? mutate = null)
    {
        var node = new JsonObject
        {
            ["tenant_id"] = (tenantId ?? TenantId).ToString("D", CultureInfo.InvariantCulture),
            ["event"] = eventName,
            ["correlation_id"] = Guid.NewGuid().ToString("D", CultureInfo.InvariantCulture),
            ["payload"] = payload ?? new JsonObject { ["sub"] = "alice" },
            ["timeout_ms"] = timeoutMs,
            ["key_version"] = 2,
            ["nonce"] = Guid.NewGuid().ToString("D", CultureInfo.InvariantCulture),
            ["issued_at"] = ReactorProtocol.FormatInstant(issuedAt ?? Now),
            ["hmac_signature"] = null,
        };
        mutate?.Invoke(node);

        byte[] mac = HMACSHA256.HashData(Subkey, Encoding.UTF8.GetBytes(node.ToJsonString()));
        node["hmac_signature"] = Convert.ToHexString(mac).ToLowerInvariant();
        return ReactorVectors.Encode(node);
    }

    private Mock<IChannel> FakeChannel()
    {
        var mock = new Mock<IChannel>();

        mock.Setup(c => c.BasicQosAsync(
                It.IsAny<uint>(), It.IsAny<ushort>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        mock.Setup(c => c.BasicConsumeAsync(
                It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>(),
                It.IsAny<IDictionary<string, object?>>(), It.IsAny<IAsyncBasicConsumer>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync("consumer-tag");

        mock.Setup(c => c.BasicCancelAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        mock.Setup(c => c.BasicAckAsync(It.IsAny<ulong>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<ulong, bool, CancellationToken>((tag, _, _) =>
                _settled.Add(FormattableString.Invariant($"ack:{tag}")))
            .Returns(ValueTask.CompletedTask);

        mock.Setup(c => c.BasicNackAsync(
                It.IsAny<ulong>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<ulong, bool, bool, CancellationToken>((tag, _, requeue, _) =>
                _settled.Add(FormattableString.Invariant($"nack:{tag}:{(requeue ? "requeue" : "norequeue")}")))
            .Returns(ValueTask.CompletedTask);

        mock.Setup(c => c.BasicPublishAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<BasicProperties>(),
                It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<CancellationToken>()))
            .Callback<string, string, bool, BasicProperties, ReadOnlyMemory<byte>, CancellationToken>(
                (_, _, _, _, body, _) => _published.Add(body.ToArray()))
            .Returns(ValueTask.CompletedTask);

        return mock;
    }

    /// <summary>A clock a handler can move forward, to close a window without sleeping.</summary>
    private sealed class MovingClock
    {
        private DateTimeOffset _now;

        internal MovingClock(DateTimeOffset start) => _now = start;

        internal Func<DateTimeOffset> Now => () => _now;

        internal void Advance(TimeSpan by) => _now += by;
    }

    /// <summary>
    /// Records the fully formatted text of every warning and debug line, so tests can scan the
    /// serialized output for the fixture's key value exactly as &#167;12/&#167;14/&#167;15/&#167;20
    /// require elsewhere.
    /// </summary>
    private sealed class RecordingLogger : ILogger
    {
        private readonly List<string> _lines;

        internal RecordingLogger(List<string> lines) => _lines = lines;

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            _lines.Add(formatter(state, exception));
    }
}
