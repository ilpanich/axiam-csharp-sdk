using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
/// CONTRACT.md &#167;8 "Signed authorization responses" (contract 1.68; audit finding N2, decision D-9):
/// the AMQP authorization requester. It is a new feature (no SDK had one), so every test here passes against the
/// code as written; the contract's four test vectors are verified byte for byte over the RECEIVED bytes.
/// </summary>
[Trait("Category", "Fast")]
public sealed class AxiamAuthzRequesterTests
{
    // Contract 1.68 §8 test vectors.
    private const string MasterKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private const string SubkeyHex = "919e125ec83799c1e113a27707cac5008a2608d0557e00dfe1b3a316abed4b89";
    private const string Tenant = "11111111-1111-1111-1111-111111111111";
    private const string OtherTenant = "99999999-9999-9999-9999-999999999999";
    private const string Correlation = "22222222-2222-2222-2222-222222222222";
    private const string Nonce = "55555555-5555-5555-5555-555555555555";
    private const string Subject = "33333333-3333-3333-3333-333333333333";
    private const string Resource = "44444444-4444-4444-4444-444444444444";

    private sealed record Vector(string Name, string Canonical, string Signature, bool Allowed, string? Reason, string? Code)
    {
        internal byte[] Wire() => Encoding.UTF8.GetBytes(Canonical[..^1] + ",\"hmac_signature\":\"" + Signature + "\"}");
    }

    private static readonly Vector[] Vectors =
    [
        new("1 allow",
            """{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":true,"reason_code":"allowed","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}""",
            "8d81f0437df6c6fffafd13f4265bd41d3cfd6fcbf7c251b3bb79e0846578574a", true, null, "allowed"),
        new("2 deny no_grant",
            """{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action 'documents:read'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}""",
            "f3105ee678acd79da6ffd28c02b86311e16bb8d8dfd3fd0addbacdf73bd5a400", false, "no permission grants action 'documents:read'", "no_grant"),
        new("3 deny denied_by_rule",
            """{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"an explicit deny rule refuses action 'documents:read'","reason_code":"denied_by_rule","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}""",
            "4bfc2ce9a035bd4a028ee2a5cb75a08832915c60cd2b176c8d4bf28910a61adc", false, "an explicit deny rule refuses action 'documents:read'", "denied_by_rule"),
        new("4 escapes encoders disagree on",
            """{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action 'docs:a&b</\"c\">/é€'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}""",
            "5194142df4bf66b07e9e8d516caf6be099af025219ab12deb26fea39e93490ff", false, "no permission grants action 'docs:a&b</\"c\">/é€'", "no_grant"),
    ];

    public static IEnumerable<object[]> VectorNames() => Vectors.Select(v => new object[] { v.Name });

    private static byte[] Subkey => Convert.FromHexString(SubkeyHex);

    /// <summary>HKDF-SHA256(salt, ikm = master, info = "axiam-amqp-v1" || key_version || tenant_id raw 16 bytes): the contract's derivation.</summary>
    private static byte[] SubkeyFor(string tenant, byte keyVersion)
    {
        byte[] info = Encoding.ASCII.GetBytes("axiam-amqp-v1")
            .Append(keyVersion)
            .Concat(Convert.FromHexString(tenant.Replace("-", string.Empty)))
            .ToArray();
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, Convert.FromHexString(MasterKeyHex), 32, Encoding.ASCII.GetBytes("axiam-amqp-hkdf-salt-v1"), info);
    }

    private static byte[] SignWith(byte[] key, string canonical) =>
        Encoding.UTF8.GetBytes(canonical[..^1] + ",\"hmac_signature\":\"" + Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant() + "\"}");

    private sealed class FakeTransport : IAuthzTransport
    {
        private readonly object _gate = new();
        public string Queue { get; set; } = "amq.gen-Xk3p";
        public Func<AuthzDelivery, Task>? OnDelivery { get; private set; }
        public Action? OnClosed { get; private set; }
        public List<(string Queue, string ReplyTo, string CorrelationId, byte[] Body)> Published { get; } = new();
        public int Cancelled { get; private set; }

        public Task CancelAsync(CancellationToken cancellationToken)
        {
            Cancelled++;
            return Task.CompletedTask;
        }

        public Task<string> DeclareReplyQueueAsync(Func<AuthzDelivery, Task> onDelivery, Action onClosed, CancellationToken cancellationToken)
        {
            OnDelivery = onDelivery;
            OnClosed = onClosed;
            return Task.FromResult(Queue);
        }

        public Task PublishRequestAsync(string queue, string replyTo, string correlationId, byte[] body, CancellationToken cancellationToken)
        {
            lock (_gate)
            {
                Published.Add((queue, replyTo, correlationId, body));
            }
            return Task.CompletedTask;
        }

        public async Task<(string Queue, string ReplyTo, string CorrelationId, byte[] Body)> WaitForPublishedAsync(int count)
        {
            for (int i = 0; i < 2000; i++)
            {
                lock (_gate)
                {
                    if (Published.Count >= count)
                    {
                        return Published[count - 1];
                    }
                }
                await Task.Delay(1);
            }
            throw new TimeoutException("no request was published");
        }
    }

    private sealed class Settlement
    {
        public int Acked { get; private set; }
        public int NackedWithoutRequeue { get; private set; }
        public AuthzDelivery Delivery(byte[] body) => new(
            body,
            () => { Acked++; return ValueTask.CompletedTask; },
            () => { NackedWithoutRequeue++; return ValueTask.CompletedTask; });
    }

    private sealed class RecordingLogger : ILogger
    {
        public List<string> Warnings { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                Warnings.Add(formatter(state, exception));
            }
        }
    }

    private static Task<AxiamAuthzRequester> NewRequester(FakeTransport? transport = null, AxiamAuthzRequesterOptions? options = null) =>
        AxiamAuthzRequester.CreateAsync(transport ?? new FakeTransport(), Tenant, Subkey, options, null, CancellationToken.None);

    /// <summary>Feeds <paramref name="body"/> to the requester; returns the decision if it completed the vectors' outstanding request.</summary>
    private static async Task<(AmqpAuthzDecision? Decision, Settlement Settled)> OfferAsync(AxiamAuthzRequester requester, Task<AmqpAuthzDecision> outstanding, byte[] body)
    {
        var settled = new Settlement();
        await requester.HandleAsync(settled.Delivery(body));
        return (outstanding.IsCompletedSuccessfully ? await outstanding : null, settled);
    }

    // ---- derivation and vectors --------------------------------------------------------

    [Fact]
    public void TheTestDerivation_MatchesTheContractsSubkey()
    {
        Assert.Equal(SubkeyHex, Convert.ToHexString(SubkeyFor(Tenant, 2)).ToLowerInvariant());
    }

    [Theory]
    [MemberData(nameof(VectorNames))]
    public async Task EachContractVector_VerifiesOverTheReceivedBytes_AndIsAcked(string name)
    {
        Vector v = Vectors.Single(x => x.Name == name);
        await using AxiamAuthzRequester requester = await NewRequester();
        Task<AmqpAuthzDecision> outstanding = requester.ExpectAsync(Correlation, Nonce);

        (AmqpAuthzDecision? decision, Settlement settled) = await OfferAsync(requester, outstanding, v.Wire());

        Assert.NotNull(decision);
        Assert.Equal(v.Allowed, decision!.Allowed);
        Assert.Equal(v.Reason, decision.Reason);
        Assert.Equal(v.Code, decision.ReasonCode);
        Assert.False(decision.Unsigned);
        Assert.Equal(1, settled.Acked);

        // Retired on acceptance: the same response again finds nothing and is nacked without requeue.
        (_, Settlement again) = await OfferAsync(requester, outstanding, v.Wire());
        Assert.Equal(0, again.Acked);
        Assert.Equal(1, again.NackedWithoutRequeue);
    }

    // ---- discarded, never an allow, never a completed request ----------------------------

    public static IEnumerable<object[]> Discarded()
    {
        Vector v1 = Vectors[0], v2 = Vectors[1];
        byte[] good = Subkey;
        byte[] Flip(Vector v, string from, string to) => Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(v.Wire()).Replace(from, to));
        byte[] Re(byte[] key, string canonical) => SignWith(key, canonical);

        yield return new object[] { "vector 1 under another tenant's subkey", Re(SubkeyFor(OtherTenant, 2), v1.Canonical) };
        yield return new object[] { "vector 1 under key_version 3", Re(SubkeyFor(Tenant, 3), v1.Canonical) };
        yield return new object[] { "tampered decision: allowed flipped to false, signature kept", Flip(v1, "\"allowed\":true", "\"allowed\":false") };
        yield return new object[] { "tampered decision: vector 2 flipped to true, signature kept", Flip(v2, "\"allowed\":false", "\"allowed\":true") };
        yield return new object[] { "tampered reason_code", Flip(v2, "no_grant", "allowed") };
        yield return new object[] { "response for another nonce", Re(good, v1.Canonical.Replace(Nonce, "66666666-6666-6666-6666-666666666666")) };
        yield return new object[] { "response for another correlation_id", Re(good, v1.Canonical.Replace(Correlation, "77777777-7777-7777-7777-777777777777")) };
        yield return new object[] { "response for another tenant, validly signed with our key", Re(good, v1.Canonical.Replace(Tenant, OtherTenant)) };
        yield return new object[]
        {
            "no allowed: a signed AuthzRequest on the response queue",
            Re(good, $$"""{"correlation_id":"{{Correlation}}","tenant_id":"{{Tenant}}","subject_id":"{{Subject}}","action":"documents:read","resource_id":"{{Resource}}","key_version":2,"nonce":"{{Nonce}}","issued_at":"2026-07-10T12:00:00Z"}"""),
        };
        yield return new object[] { "allowed not a boolean", Re(good, v1.Canonical.Replace("\"allowed\":true", "\"allowed\":\"true\"")) };
        yield return new object[] { "no tenant_id", Re(good, v1.Canonical.Replace($"\"tenant_id\":\"{Tenant}\",", string.Empty)) };
        yield return new object[] { "no nonce", Re(good, v1.Canonical.Replace($",\"nonce\":\"{Nonce}\"", string.Empty)) };
        yield return new object[] { "signature not the trailing member", Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(v1.Wire()).Replace("\"allowed\":true", "\"allowed\":true,\"x\":1")) };
        yield return new object[] { "duplicate allowed keys, validly signed", Re(good, v1.Canonical.Replace("\"allowed\":true", "\"allowed\":false,\"allowed\":true")) };
        yield return new object[] { "case-variant allowed key, validly signed", Re(good, v1.Canonical.Replace("\"reason_code\"", "\"ALLOWED\":false,\"reason_code\"")) };
        yield return new object[] { "trailing whitespace after the closing brace", v1.Wire().Append((byte)'\n').ToArray() };
        yield return new object[] { "non-hex signature", Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(v1.Wire()).Replace(v1.Signature, new string('z', 64))) };
        yield return new object[] { "short signature", Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(v1.Wire()).Replace(v1.Signature, v1.Signature[..62])) };
        yield return new object[] { "null signature member", Encoding.UTF8.GetBytes(v1.Canonical[..^1] + ",\"hmac_signature\":null}") };
        yield return new object[] { "case-variant signature member", Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(v1.Wire()).Replace("hmac_signature", "HMAC_signature")) };
        yield return new object[] { "not JSON", Encoding.UTF8.GetBytes("not json") };
        yield return new object[] { "a JSON array", Encoding.UTF8.GetBytes("[true]") };
        yield return new object[] { "invalid UTF-8", v1.Wire().Concat(new byte[] { 0xff }).ToArray() };
    }

    [Theory]
    [MemberData(nameof(Discarded))]
    public async Task ABadResponse_IsDiscarded_NeverAnAllow_AndTheRequestKeepsWaiting(string name, byte[] body)
    {
        _ = name;
        var logger = new RecordingLogger();
        await using AxiamAuthzRequester requester = await NewRequester(options: new AxiamAuthzRequesterOptions { Logger = logger });
        Task<AmqpAuthzDecision> outstanding = requester.ExpectAsync(Correlation, Nonce);

        (AmqpAuthzDecision? decision, Settlement settled) = await OfferAsync(requester, outstanding, body);

        Assert.Null(decision);
        Assert.False(outstanding.IsCompleted);
        Assert.Equal(0, settled.Acked);
        Assert.Equal(1, settled.NackedWithoutRequeue);
        Assert.Single(logger.Warnings);
        Assert.DoesNotContain("8d81f043", logger.Warnings[0]); // never a signature value

        // The genuine answer still completes it.
        (AmqpAuthzDecision? genuine, _) = await OfferAsync(requester, outstanding, Vectors[0].Wire());
        Assert.NotNull(genuine);
        Assert.True(genuine!.Allowed);
    }

    // ---- unsigned responses ------------------------------------------------------------

    private static readonly byte[] Unsigned = Encoding.UTF8.GetBytes($$"""{"correlation_id":"{{Correlation}}","allowed":true,"reason_code":"allowed"}""");

    [Fact]
    public async Task AnUnsignedResponse_IsRefusedByDefault()
    {
        await using AxiamAuthzRequester requester = await NewRequester();
        Task<AmqpAuthzDecision> outstanding = requester.ExpectAsync(Correlation, Nonce);

        (AmqpAuthzDecision? decision, Settlement settled) = await OfferAsync(requester, outstanding, Unsigned);

        Assert.Null(decision);
        Assert.Equal(1, settled.NackedWithoutRequeue);
    }

    [Fact]
    public async Task AnUnsignedResponse_IsAcceptedWithTheOptOut_FlaggedAndLogged()
    {
        var logger = new RecordingLogger();
        await using AxiamAuthzRequester requester = await NewRequester(options: new AxiamAuthzRequesterOptions { AllowUnsignedResponses = true, Logger = logger });
        Task<AmqpAuthzDecision> outstanding = requester.ExpectAsync(Correlation, Nonce);

        (AmqpAuthzDecision? decision, _) = await OfferAsync(requester, outstanding, Unsigned);

        Assert.NotNull(decision);
        Assert.True(decision!.Allowed);
        Assert.True(decision.Unsigned);
        Assert.Equal("allowed", decision.ReasonCode);
        Assert.Contains(logger.Warnings, w => w.Contains("UNSIGNED", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("""{"correlation_id":"77777777-7777-7777-7777-777777777777","allowed":true}""")]
    [InlineData("""{"correlation_id":"22222222-2222-2222-2222-222222222222"}""")]
    [InlineData("""{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":"yes"}""")]
    public async Task TheOptOut_NeedsAnOutstandingCorrelationId_AndABooleanAllowed(string body)
    {
        await using AxiamAuthzRequester requester = await NewRequester(options: new AxiamAuthzRequesterOptions { AllowUnsignedResponses = true });
        Task<AmqpAuthzDecision> outstanding = requester.ExpectAsync(Correlation, Nonce);

        (AmqpAuthzDecision? decision, _) = await OfferAsync(requester, outstanding, Encoding.UTF8.GetBytes(body));

        Assert.Null(decision);
    }

    [Fact]
    public async Task TheOptOut_NeverAdmitsAResponseCarryingAFailingSignature()
    {
        await using AxiamAuthzRequester requester = await NewRequester(options: new AxiamAuthzRequesterOptions { AllowUnsignedResponses = true });
        Task<AmqpAuthzDecision> outstanding = requester.ExpectAsync(Correlation, Nonce);

        byte[] tampered = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Vectors[1].Wire()).Replace("\"allowed\":false", "\"allowed\":true"));
        byte[] nullSignature = Encoding.UTF8.GetBytes($$"""{"correlation_id":"{{Correlation}}","allowed":true,"hmac_signature":null}""");
        byte[] caseVariant = Encoding.UTF8.GetBytes($$"""{"correlation_id":"{{Correlation}}","allowed":true,"HMAC_SIGNATURE":"{{new string('0', 64)}}"}""");

        foreach (byte[] body in new[] { tampered, nullSignature, caseVariant })
        {
            (AmqpAuthzDecision? decision, _) = await OfferAsync(requester, outstanding, body);
            Assert.Null(decision);
        }
    }

    // ---- end to end over the RabbitMQ.Client adapter with a fake channel ----------------

    [Fact]
    public async Task CheckAsync_EndToEnd_OverAFakeChannel()
    {
        (Mock<IChannel> channel, FakeBroker broker) = FakeChannel();
        await using AxiamAuthzRequester requester = await AxiamAuthzRequester.CreateAsync(
            channel.Object, Tenant, Subkey, new AxiamAuthzRequesterOptions { Timeout = TimeSpan.FromSeconds(5) });

        // The private reply queue: broker-named, not durable, EXCLUSIVE, auto-delete; consumed exclusively, manual ack.
        Assert.Equal("amq.gen-abc", requester.ReplyTo);
        Assert.Equal(("", false, true, true), broker.Declared);
        Assert.True(broker.ConsumeExclusive);
        Assert.False(broker.ConsumeAutoAck);

        Task<AmqpAuthzDecision> check = requester.CheckAsync(Subject, "docs:a&b</\"c\">", Resource, "confidential");
        FakeBroker.Publication pub = await broker.WaitForPublicationAsync(1);

        // Default-exchange routing to the request queue, a private reply_to, a correlation_id property equal to the body's.
        Assert.Equal(("", "axiam.authz.request", "amq.gen-abc"), (pub.Exchange, pub.RoutingKey, pub.ReplyTo));
        using JsonDocument request = JsonDocument.Parse(pub.Body);
        JsonElement r = request.RootElement;
        Assert.Equal(pub.CorrelationId, r.GetProperty("correlation_id").GetString());
        Assert.Equal(Tenant, r.GetProperty("tenant_id").GetString());
        Assert.Equal(2, r.GetProperty("key_version").GetInt32());
        Assert.Equal("confidential", r.GetProperty("scope").GetString());
        string nonce = r.GetProperty("nonce").GetString()!;
        Assert.NotEqual(pub.CorrelationId, nonce);

        // Raw characters as serde_json writes them, and a signature that verifies over the canonical bytes.
        string text = Encoding.UTF8.GetString(pub.Body);
        Assert.Contains("\"action\":\"docs:a&b</\\\"c\\\">\"", text);
        Assert.True(AxiamAuthzRequester.TryCutTrailingSignature(pub.Body, out byte[]? canonical, out string? sigHex));
        Assert.Equal(Convert.ToHexString(HMACSHA256.HashData(Subkey, canonical!)).ToLowerInvariant(), sigHex);
        // Field order: ... resource_id, scope, key_version, nonce, issued_at.
        Assert.True(text.IndexOf("\"resource_id\"", StringComparison.Ordinal) < text.IndexOf("\"scope\"", StringComparison.Ordinal));
        Assert.True(text.IndexOf("\"key_version\"", StringComparison.Ordinal) < text.IndexOf("\"nonce\"", StringComparison.Ordinal));
        Assert.True(text.IndexOf("\"nonce\"", StringComparison.Ordinal) < text.IndexOf("\"issued_at\"", StringComparison.Ordinal));

        // A forgery with the right ids under another tenant's key is discarded (nacked); the genuine answer completes the check.
        string answer = $$"""{"correlation_id":"{{pub.CorrelationId}}","allowed":true,"reason_code":"allowed","tenant_id":"{{Tenant}}","nonce":"{{nonce}}"}""";
        await broker.DeliverAsync(11, SignWith(SubkeyFor(OtherTenant, 2), answer));
        Assert.False(check.IsCompleted);
        Assert.Equal(new[] { "nack:11:norequeue" }, broker.Settled);

        await broker.DeliverAsync(12, SignWith(Subkey, answer));
        AmqpAuthzDecision decision = await check;
        Assert.True(decision.Allowed);
        Assert.Equal("allowed", decision.ReasonCode);
        Assert.Equal(new[] { "nack:11:norequeue", "ack:12" }, broker.Settled);

        // Fresh, distinct ids per request.
        Task<AmqpAuthzDecision> second = requester.CheckAsync(Subject, "documents:read", Resource);
        FakeBroker.Publication pub2 = await broker.WaitForPublicationAsync(2);
        Assert.NotEqual(pub.CorrelationId, pub2.CorrelationId);
        using JsonDocument request2 = JsonDocument.Parse(pub2.Body);
        Assert.NotEqual(nonce, request2.RootElement.GetProperty("nonce").GetString());
        Assert.False(request2.RootElement.TryGetProperty("scope", out _)); // omitted when absent

        // Closing releases the outstanding check.
        await requester.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => second);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => requester.CheckAsync(Subject, "a", Resource));
    }

    [Fact]
    public async Task CheckAsync_WithAContractVectorAnswer_ReturnsTheDecodedDecision()
    {
        // The same flow with the real vector 4: reason echoes characters encoders disagree on.
        var transport = new FakeTransport();
        await using AxiamAuthzRequester requester = await NewRequester(transport);
        Task<AmqpAuthzDecision> check = requester.CheckAsync(Subject, "docs:a&b</\"c\">/é€", Resource);
        (_, _, string correlation, byte[] body) = await transport.WaitForPublishedAsync(1);
        string nonce = JsonDocument.Parse(body).RootElement.GetProperty("nonce").GetString()!;

        string canonical = $$"""{"correlation_id":"{{correlation}}","allowed":false,"reason":"no permission grants action 'docs:a&b</\"c\">/é€'","reason_code":"no_grant","tenant_id":"{{Tenant}}","nonce":"{{nonce}}"}""";
        await transport.OnDelivery!(new Settlement().Delivery(SignWith(Subkey, canonical)));

        AmqpAuthzDecision decision = await check;
        Assert.False(decision.Allowed);
        Assert.Equal("no permission grants action 'docs:a&b</\"c\">/é€'", decision.Reason);
    }

    [Fact]
    public async Task CheckAsync_TimesOutWithoutAnAnswer_AndLeavesNothingOutstanding()
    {
        await using AxiamAuthzRequester requester = await NewRequester(options: new AxiamAuthzRequesterOptions { Timeout = TimeSpan.FromMilliseconds(30) });

        await Assert.ThrowsAsync<TimeoutException>(() => requester.CheckAsync(Subject, "a", Resource));

        Assert.Equal(0, requester.OutstandingCount);
    }

    [Fact]
    public async Task CheckAsync_HonoursTheCallersCancellation()
    {
        await using AxiamAuthzRequester requester = await NewRequester();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(30));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => requester.CheckAsync(Subject, "a", Resource, cancellationToken: cts.Token));

        Assert.Equal(0, requester.OutstandingCount);
    }

    [Fact]
    public async Task AChannelShutdown_ClosesTheRequester()
    {
        var transport = new FakeTransport();
        AxiamAuthzRequester requester = await NewRequester(transport);
        Task<AmqpAuthzDecision> check = requester.CheckAsync(Subject, "a", Resource);
        await transport.WaitForPublishedAsync(1);

        transport.OnClosed!();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => check);
    }

    // ---- construction and request building ---------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("axiam.authz.response")]
    [InlineData("axiam.mail.outbound")]
    public async Task ANonPrivateReplyQueue_IsRefused(string queue)
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() => NewRequester(new FakeTransport { Queue = queue }));
    }

    [Fact]
    public async Task ABadTenantOrAMissingKey_IsRefused()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => AxiamAuthzRequester.CreateAsync(new FakeTransport(), "not-a-uuid", Subkey, null, null, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => AxiamAuthzRequester.CreateAsync(new FakeTransport(), Tenant, Array.Empty<byte>(), null, null, CancellationToken.None));
    }

    [Fact]
    public async Task ConnectAsync_RefusesAPlaintextBrokerUri()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => AxiamAuthzRequester.ConnectAsync("amqp://broker.example", Tenant, Subkey));
    }

    [Theory]
    [InlineData("subject not a UUID", "x", "a", Resource)]
    [InlineData("resource not a UUID", Subject, "a", "x")]
    [InlineData("empty action", Subject, "", Resource)]
    public void AnUnsignableRequest_IsRefused(string name, string subject, string action, string resource)
    {
        _ = name;
        Assert.ThrowsAny<ArgumentException>(() =>
            AxiamAuthzRequester.BuildRequest(Subkey, Correlation, Tenant, subject, action, resource, null, Nonce, DateTimeOffset.UnixEpoch));
    }

    [Fact]
    public void TheRequest_ReproducesTheServersAuthzRequestReferenceVector_ByteForByte()
    {
        // CSH-R1-5: the server re-serializes an AuthzRequest with serde and verifies the HMAC over THOSE bytes.
        // crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json, "authz_request".
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "v2_reference_vectors.json")));
        JsonElement vector = doc.RootElement.GetProperty("authz_request");
        string canonical = vector.GetProperty("canonical_signed_json").GetString()!;
        string signature = vector.GetProperty("hmac_signature_hex").GetString()!;

        byte[] wire = AxiamAuthzRequester.BuildRequest(
            Subkey, Correlation, Tenant, Subject, "documents:read", Resource, "confidential", Nonce,
            new DateTimeOffset(2026, 7, 10, 12, 0, 0, TimeSpan.Zero));

        Assert.Equal(canonical[..^1] + ",\"hmac_signature\":\"" + signature + "\"}", Encoding.UTF8.GetString(wire));
    }

    [Fact]
    public async Task DisposingARequester_CancelsTheConsumer_SoACallerOwnedChannelKeepsNoQueueAlive()
    {
        // CSH-R1-4: the requester does not own the channel here, so disposing must cancel the consumer itself
        // (that is what lets the exclusive auto-delete reply queue go away while the channel lives on).
        var transport = new FakeTransport();
        AxiamAuthzRequester requester = await AxiamAuthzRequester.CreateAsync(transport, Tenant, Subkey, null, null, CancellationToken.None);

        await requester.DisposeAsync();
        await requester.DisposeAsync(); // idempotent

        Assert.Equal(1, transport.Cancelled);
    }

    [Fact]
    public async Task ABrokerSideConsumerCancel_ClosesTheRequester_SoACheckFailsAtOnce()
    {
        // CSH-R3-2: a deleted reply queue cancels the consumer while the channel stays open; the requester must
        // close (ObjectDisposedException) instead of publishing with a dead reply_to and waiting out the timeout.
        (Mock<IChannel> channel, FakeBroker broker) = FakeChannel();
        await using AxiamAuthzRequester requester = await AxiamAuthzRequester.CreateAsync(
            channel.Object, Tenant, Subkey, new AxiamAuthzRequesterOptions { Timeout = TimeSpan.FromSeconds(30) });

        await broker.Consumer!.HandleBasicCancelAsync("consumer-tag");

        await Assert.ThrowsAsync<ObjectDisposedException>(() => requester.CheckAsync(Subject, "read", Resource));
    }

    [Fact]
    public void ALoneSurrogateInTheActionOrScope_IsRefused()
    {
        string lone = new string(new[] { 'a', (char)0xD800, 'b' });
        Assert.ThrowsAny<ArgumentException>(() =>
            AxiamAuthzRequester.BuildRequest(Subkey, Correlation, Tenant, Subject, lone, Resource, null, Nonce, DateTimeOffset.UnixEpoch));
        Assert.ThrowsAny<ArgumentException>(() =>
            AxiamAuthzRequester.BuildRequest(Subkey, Correlation, Tenant, Subject, "a", Resource, lone, Nonce, DateTimeOffset.UnixEpoch));
    }

    [Fact]
    public void TheRequestWritesStringsAsSerdeJsonDoes()
    {
        byte[] wire = AxiamAuthzRequester.BuildRequest(Subkey, Correlation, Tenant, Subject, "a\u0001\n\u2028/<>&é", Resource, "s\"\\", Nonce,
            new DateTimeOffset(2026, 7, 10, 12, 0, 0, TimeSpan.Zero));

        string text = Encoding.UTF8.GetString(wire);
        Assert.Contains("\"action\":\"a\\u0001\\n\u2028/<>&é\"", text);
        Assert.Contains("\"scope\":\"s\\\"\\\\\"", text);
        Assert.Contains("\"issued_at\":\"2026-07-10T12:00:00Z\"", text);
        Assert.True(AxiamAuthzRequester.TryCutTrailingSignature(wire, out byte[]? canonical, out string? sig));
        Assert.Equal(Convert.ToHexString(HMACSHA256.HashData(Subkey, canonical!)).ToLowerInvariant(), sig);
    }

    // ---- a fake IChannel ---------------------------------------------------------------

    private sealed class FakeBroker
    {
        private readonly object _gate = new();
        public sealed record Publication(string Exchange, string RoutingKey, string? ReplyTo, string? CorrelationId, byte[] Body);

        public (string Queue, bool Durable, bool Exclusive, bool AutoDelete) Declared { get; set; }
        public bool ConsumeExclusive { get; set; }
        public bool ConsumeAutoAck { get; set; } = true;
        public AsyncEventingBasicConsumer? Consumer { get; set; }
        public List<string> Settled { get; } = new();
        public List<Publication> Publications { get; } = new();

        public void Add(Publication p)
        {
            lock (_gate)
            {
                Publications.Add(p);
            }
        }

        public async Task<Publication> WaitForPublicationAsync(int count)
        {
            for (int i = 0; i < 2000; i++)
            {
                lock (_gate)
                {
                    if (Publications.Count >= count)
                    {
                        return Publications[count - 1];
                    }
                }
                await Task.Delay(1);
            }
            throw new TimeoutException("nothing was published");
        }

        public Task DeliverAsync(ulong tag, byte[] body) =>
            Consumer!.HandleBasicDeliverAsync("tag", tag, false, "", "amq.gen-abc", new BasicProperties(), body);
    }

    private static (Mock<IChannel> Mock, FakeBroker Broker) FakeChannel()
    {
        var broker = new FakeBroker();
        var mock = new Mock<IChannel>();

        mock.Setup(c => c.QueueDeclareAsync(
                It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<bool>(),
                It.IsAny<IDictionary<string, object?>>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<string, bool, bool, bool, IDictionary<string, object?>?, bool, bool, CancellationToken>(
                (q, durable, exclusive, autoDelete, _, _, _, _) => broker.Declared = (q, durable, exclusive, autoDelete))
            .ReturnsAsync(new QueueDeclareOk("amq.gen-abc", 0, 0));

        mock.Setup(c => c.BasicConsumeAsync(
                It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>(),
                It.IsAny<IDictionary<string, object?>>(), It.IsAny<IAsyncBasicConsumer>(), It.IsAny<CancellationToken>()))
            .Callback<string, bool, string, bool, bool, IDictionary<string, object?>?, IAsyncBasicConsumer, CancellationToken>(
                (_, autoAck, _, _, exclusive, _, consumer, _) =>
                {
                    broker.ConsumeAutoAck = autoAck;
                    broker.ConsumeExclusive = exclusive;
                    broker.Consumer = (AsyncEventingBasicConsumer)consumer;
                })
            .ReturnsAsync("consumer-tag");

        mock.Setup(c => c.BasicAckAsync(It.IsAny<ulong>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<ulong, bool, CancellationToken>((tag, _, _) => broker.Settled.Add($"ack:{tag}"))
            .Returns(ValueTask.CompletedTask);
        mock.Setup(c => c.BasicNackAsync(It.IsAny<ulong>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<ulong, bool, bool, CancellationToken>((tag, _, requeue, _) => broker.Settled.Add($"nack:{tag}:{(requeue ? "requeue" : "norequeue")}"))
            .Returns(ValueTask.CompletedTask);

        mock.Setup(c => c.BasicPublishAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<BasicProperties>(),
                It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<CancellationToken>()))
            .Callback<string, string, bool, BasicProperties, ReadOnlyMemory<byte>, CancellationToken>(
                (exchange, key, _, props, body, _) => broker.Add(new FakeBroker.Publication(exchange, key, props.ReplyTo, props.CorrelationId, body.ToArray())))
            .Returns(ValueTask.CompletedTask);

        return (mock, broker);
    }
}
