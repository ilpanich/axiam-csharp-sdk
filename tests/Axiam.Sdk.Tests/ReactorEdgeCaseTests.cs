using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Core;
using Axiam.Sdk.Reactor;
using Axiam.Sdk.Tests.Fixtures;
using Moq;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// The edges of the &#167;22 primitives: a body that is not a body, a signature that is not a
/// signature, the patch ordering rule, and the &#167;18 drain.
///
/// <para>
/// <see cref="ReactorVectorTests"/> proves the protocol produces the <em>right</em> bytes
/// against the server's own vectors. This class proves it refuses the wrong ones without
/// throwing into a delivery loop — every predicate below has to answer <c>false</c> rather
/// than blow up, because a verifier that throws on a malformed body is a verifier an attacker
/// can use to kill the consumer.
/// </para>
/// </summary>
[Trait("Category", "Fast")]
public class ReactorEdgeCaseTests
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-07-10T12:00:00Z", CultureInfo.InvariantCulture);

    private static readonly Guid Tenant = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Correlation = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid Nonce = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

    /// <summary>
    /// A non-zero key on purpose. HMAC-SHA256 zero-pads a key shorter than its 64-byte block,
    /// so an all-zero 32-byte key and an EMPTY key produce identical MACs — an all-zero
    /// fixture key would make the "wrong key must not verify" assertion below vacuously true.
    /// </summary>
    private static byte[] Key => Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();

    // ---- canonicalization --------------------------------------------------

    [Fact]
    public void CanonicalEventBytes_RewritesTheSignatureToNullInPlace()
    {
        byte[] signed = ReactorProtocol.SignedReply(
            Key, Correlation, Tenant, ReactorEvents.LoginPostAuth, ReactorDecision.Allowed(), Nonce, Now);
        Assert.Contains("\"hmac_signature\":\"", Encoding.UTF8.GetString(signed), StringComparison.Ordinal);

        string canonical = Encoding.UTF8.GetString(ReactorProtocol.CanonicalEventBytes(signed));

        Assert.EndsWith("\"hmac_signature\":null}", canonical, StringComparison.Ordinal);
        Assert.Equal(
            Encoding.UTF8.GetString(ReactorProtocol.CanonicalReplyBytes(
                Correlation, Tenant, ReactorEvents.LoginPostAuth, ReactorDecision.Allowed(), Nonce, Now)),
            canonical);
    }

    [Theory]
    [InlineData("[1,2,3]")]
    [InlineData("\"a string\"")]
    [InlineData("not json at all")]
    [InlineData("")]
    public void ABodyThatIsNotAJsonObject_IsRefusedRatherThanCanonicalized(string raw)
    {
        Assert.Throws<ArgumentException>(() => ReactorProtocol.CanonicalEventBytes(Encoding.UTF8.GetBytes(raw)));
    }

    // ---- verification answers false; it never throws -----------------------

    [Theory]
    [InlineData("}{", "not JSON")]
    [InlineData("[]", "a JSON array")]
    [InlineData("", "empty")]
    [InlineData("{\"key_version\":2}", "no signature field")]
    [InlineData("{\"key_version\":2,\"hmac_signature\":null}", "a null signature")]
    [InlineData("{\"key_version\":2,\"hmac_signature\":7}", "a numeric signature")]
    [InlineData("{\"key_version\":2,\"hmac_signature\":\"abc\"}", "an odd-length hex signature")]
    [InlineData("{\"key_version\":2,\"hmac_signature\":\"zzzz\"}", "a non-hex signature")]
    [InlineData("{\"key_version\":2,\"hmac_signature\":\"ab\"}", "a short but valid hex signature")]
    public void EveryMalformedBody_FailsVerificationRatherThanThrowing(string raw, string why)
    {
        Assert.False(
            ReactorProtocol.VerifyEvent(Key, Encoding.UTF8.GetBytes(raw)),
            $"{why} must verify as false — there is no accept-when-absent path");
    }

    [Fact]
    public void ADifferentSigningKey_NeverVerifiesABodySignedWithTheTenantSubkey()
    {
        // HMAC-SHA256 accepts a key of any length (including empty) rather than throwing, so
        // "wrong key" is a verification failure and not an exception — which is exactly what a
        // reactor wants: an attacker must not be able to kill the consumer with a bad body.
        byte[] signed = ReactorProtocol.SignedReply(
            Key, Correlation, Tenant, ReactorEvents.LoginPostAuth, ReactorDecision.Allowed(), Nonce, Now);

        Assert.True(ReactorProtocol.VerifyEvent(Key, signed));
        Assert.False(ReactorProtocol.VerifyEvent(Array.Empty<byte>(), signed));
        Assert.False(ReactorProtocol.VerifyEvent(new byte[32], signed));
        Assert.False(ReactorProtocol.VerifyEvent(Enumerable.Repeat((byte)0xAB, 32).ToArray(), signed));
    }

    [Fact]
    public void SigningRefusesNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => ReactorProtocol.CanonicalReplyBytes(
            Correlation, Tenant, null!, ReactorDecision.Allowed(), Nonce, Now));
        Assert.Throws<ArgumentNullException>(() => ReactorProtocol.CanonicalReplyBytes(
            Correlation, Tenant, ReactorEvents.LoginPostAuth, null!, Nonce, Now));
        Assert.Throws<ArgumentNullException>(() => ReactorProtocol.DeriveTenantKey(null!, Tenant));
    }

    // ---- patch key ordering ------------------------------------------------

    [Fact]
    public void PatchKeys_AreOrderedByUtf8BytesIncludingThePrefixCase()
    {
        string body = Encoding.UTF8.GetString(ReactorProtocol.CanonicalReplyBytes(
            Correlation,
            Tenant,
            ReactorEvents.TokenPreIssue,
            // "ext.a" is a strict prefix of "ext.ab": equal on every shared byte, so the
            // comparator has to fall through to the length difference.
            ReactorDecision.Mutated(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ext.b"] = "3",
                ["ext.ab"] = "2",
                ["ext.a"] = "1",
                ["ext.é"] = "4",
            }),
            Nonce,
            Now));

        Assert.Contains(
            "\"ext.a\":\"1\",\"ext.ab\":\"2\",\"ext.b\":\"3\"",
            body,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"ext.b\":\"3\",\"ext.\\u00E9\":\"4\"",
            body,
            StringComparison.Ordinal);
    }

    // ---- the runtime's remaining refusal paths -----------------------------

    [Fact]
    public async Task ABodyThatParsesToJsonNull_IsRefusedBeforeTheHandler()
    {
        await AssertRefused(Encoding.UTF8.GetBytes("null"));
    }

    /// <summary>
    /// A body whose MAC is <em>perfectly valid</em> but which carries no <c>nonce</c> at all.
    /// A correct signature over a body missing its replay-protection field is not a lesser
    /// failure than a forged one: the message predates &#167;8 v2, and v2 was a hard cutover
    /// with no grace path.
    /// </summary>
    [Fact]
    public async Task ACorrectlySignedBodyMissingItsNonce_IsStillRefused()
    {
        JsonObject vector = ReactorVectors.Load()["server_to_reactor"]!["token_pre_issue"]!.AsObject();
        JsonObject node = ReactorVectors.CanonicalObject(vector);
        node.Remove("nonce");

        byte[] key = ReactorVectors.Subkey(ReactorVectors.Load());
        byte[] mac = System.Security.Cryptography.HMACSHA256.HashData(
            key, Encoding.UTF8.GetBytes(node.ToJsonString()));
        byte[] body = ReactorVectors.WithSignature(node, Convert.ToHexString(mac).ToLowerInvariant());

        Assert.True(ReactorProtocol.VerifyEvent(key, body), "the signature itself is valid");
        await AssertRefused(body);
    }

    [Fact]
    public async Task AHandlerReturningNull_ProducesNoReply()
    {
        var published = new List<byte[]>();
        var settled = new List<string>();
        Mock<IChannel> channel = FakeChannel(published, settled);

        await using (ReactorServer server = await ReactorServer.ReactorServeAsync(
                         Options(channel, handler: (_, _) => Task.FromResult<ReactorDecision>(null!))))
        {
            await Deliver(server, EventBody());
        }

        Assert.Empty(published);
        Assert.Contains("nack:norequeue", settled);
    }

    /// <summary>
    /// &#167;22.13 "Runtime": shutdown drains in-flight events per &#167;18. The handler below
    /// is parked on a gate, so the dispose call has to actually wait for it rather than
    /// returning while a decision is still being made.
    /// </summary>
    [Fact]
    public async Task Shutdown_DrainsInFlightEventsRatherThanAbandoningThem()
    {
        var published = new List<byte[]>();
        var settled = new List<string>();
        Mock<IChannel> channel = FakeChannel(published, settled);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        ReactorServer server = await ReactorServer.ReactorServeAsync(Options(channel, handler: async (_, _) =>
        {
            entered.SetResult();
            await release.Task;
            return ReactorDecision.Allowed();
        }));

        Task dispatch = Deliver(server, EventBody());
        await entered.Task;
        Assert.Equal(1, server.InFlight);

        Task shutdown = server.DisposeAsync().AsTask();
        Assert.False(shutdown.IsCompleted, "dispose must wait for the in-flight handler");

        release.SetResult();
        await dispatch;
        await shutdown;

        Assert.Equal(0, server.InFlight);
        Assert.True(server.IsClosed);
        Assert.Single(published);
    }

    [Fact]
    public async Task ADeliveryWhoseHandlerOutlastsTheGrace_DoesNotBlockShutdownForever()
    {
        var published = new List<byte[]>();
        var settled = new List<string>();
        Mock<IChannel> channel = FakeChannel(published, settled);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        ReactorServer server = await ReactorServer.ReactorServeAsync(new ReactorServeOptions
        {
            Channel = channel.Object,
            TenantId = Tenant,
            SigningKey = Sensitive<byte[]>.Wrap(ReactorVectors.Subkey(ReactorVectors.Load())),
            ReactorId = Guid.NewGuid(),
            Queue = null,
            Handler = async (_, _) =>
            {
                entered.SetResult();
                await release.Task;
                return ReactorDecision.Allowed();
            },
            ShutdownGrace = TimeSpan.FromMilliseconds(50),
            Clock = () => Now,
        });

        Task dispatch = Deliver(server, EventBody());
        await entered.Task;

        await server.DisposeAsync();
        Assert.True(server.IsClosed);

        release.SetResult();
        await dispatch;
    }

    // ---- helpers -----------------------------------------------------------

    private static async Task AssertRefused(byte[] body)
    {
        var published = new List<byte[]>();
        var settled = new List<string>();
        Mock<IChannel> channel = FakeChannel(published, settled);
        bool ran = false;

        await using (ReactorServer server = await ReactorServer.ReactorServeAsync(
                         Options(channel, handler: (_, _) =>
                         {
                             ran = true;
                             return Task.FromResult(ReactorDecision.Allowed());
                         })))
        {
            await Deliver(server, body);
        }

        Assert.False(ran);
        Assert.Empty(published);
    }

    private static ReactorServeOptions Options(Mock<IChannel> channel, ReactorHandler handler) => new()
    {
        Channel = channel.Object,
        TenantId = Tenant,
        SigningKey = Sensitive<byte[]>.Wrap(ReactorVectors.Subkey(ReactorVectors.Load())),
        ReactorId = Guid.Parse(ReactorVectors.Text(ReactorVectors.Load(), "reactor_id")),
        Handler = handler,
        Clock = () => Now,
    };

    private static byte[] EventBody() =>
        ReactorVectors.WireBody(ReactorVectors.Load()["server_to_reactor"]!["token_pre_issue"]!.AsObject());

    private static Task Deliver(ReactorServer server, byte[] body) =>
        server.CreateReceivedHandler()(
            new object(),
            new BasicDeliverEventArgs(
                consumerTag: "test-consumer",
                deliveryTag: 1,
                redelivered: false,
                exchange: ReactorProtocol.Exchange,
                routingKey: ReactorProtocol.RoutingKey(Tenant, ReactorEvents.TokenPreIssue),
                properties: new BasicProperties { ReplyTo = "amq.rabbitmq.reply-to.abc" },
                body: body,
                cancellationToken: CancellationToken.None));

    private static Mock<IChannel> FakeChannel(List<byte[]> published, List<string> settled)
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
            .Callback(() => settled.Add("ack"))
            .Returns(ValueTask.CompletedTask);
        mock.Setup(c => c.BasicNackAsync(
                It.IsAny<ulong>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<ulong, bool, bool, CancellationToken>((_, _, requeue, _) =>
                settled.Add(requeue ? "nack:requeue" : "nack:norequeue"))
            .Returns(ValueTask.CompletedTask);
        mock.Setup(c => c.BasicPublishAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<BasicProperties>(),
                It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<CancellationToken>()))
            .Callback<string, string, bool, BasicProperties, ReadOnlyMemory<byte>, CancellationToken>(
                (_, _, _, _, body, _) => published.Add(body.ToArray()))
            .Returns(ValueTask.CompletedTask);

        return mock;
    }
}
