using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

namespace Axiam.Sdk.Amqp;

/// <summary>
/// A verified answer to one AMQP authorization request (CONTRACT.md &#167;8, "Signed authorization
/// responses", contract 1.68).
/// </summary>
/// <param name="Allowed">The decision. <c>true</c> only for a response that verified under the tenant subkey: no
/// response without a valid signature is ever surfaced, so there is nothing to flag.</param>
/// <param name="Reason">The server's human-readable reason; <c>null</c> when absent.</param>
/// <param name="ReasonCode">The machine-readable code (<c>allowed</c>, <c>no_grant</c>,
/// <c>denied_by_rule</c>, <c>tenant_suspended</c>, &#8230;); <c>null</c> when absent. A code this SDK does not
/// know is surfaced verbatim (&#167;11.2 rule 9).</param>
public sealed record AmqpAuthzDecision(bool Allowed, string? Reason, string? ReasonCode);

/// <summary>
/// Options for <see cref="AxiamAuthzRequester"/>. There is deliberately no option to accept an unsigned response
/// (CONTRACT.md &#167;8, contract 1.69): see the remarks of <see cref="AxiamAuthzRequester"/>.
/// </summary>
public sealed class AxiamAuthzRequesterOptions
{
    /// <summary>Receives the security event for every discarded response (CONTRACT.md &#167;8 consumer obligation 4:
    /// <c>timestamp</c>, <c>exchange</c>, <c>routing_key</c>, the requester's own <c>tenant_id</c> and a
    /// <c>reason</c>). Nothing it receives contains a signature value, a nonce, or any member read from the discarded
    /// body. Defaults to a silent logger.</summary>
    public ILogger? Logger { get; init; }

    /// <summary>Bounds each <see cref="AxiamAuthzRequester.CheckAsync"/> (default 10 seconds). Zero or
    /// negative is ignored.</summary>
    public TimeSpan Timeout { get; init; } = AxiamAuthzRequester.DefaultTimeout;
}

/// <summary>
/// One delivery from the private reply queue, with the two settlements the requester uses. <see cref="Exchange"/>
/// and <see cref="RoutingKey"/> are what the broker reported for the delivery, or <c>null</c> where the transport
/// cannot report them (the requester then names the values it consumes from: <c>""</c> and its reply queue).
/// </summary>
internal readonly record struct AuthzDelivery(
    byte[] Body,
    Func<ValueTask> Ack,
    Func<ValueTask> NackWithoutRequeue,
    string? Exchange = null,
    string? RoutingKey = null);

/// <summary>
/// The seam between <see cref="AxiamAuthzRequester"/> and a broker: it declares the private reply queue and
/// publishes requests. <see cref="RabbitMqAuthzTransport"/> is the <c>RabbitMQ.Client</c> implementation; tests
/// supply a fake.
/// </summary>
internal interface IAuthzTransport
{
    /// <summary>
    /// Declares an EXCLUSIVE, auto-delete, non-durable, broker-named queue only this requester consumes (an
    /// <c>amq.gen-&#8230;</c> queue), starts consuming it with manual acknowledgement, and returns its name.
    /// <paramref name="onClosed"/> is invoked when the queue or the channel goes away.
    /// </summary>
    Task<string> DeclareReplyQueueAsync(Func<AuthzDelivery, Task> onDelivery, Action onClosed, CancellationToken cancellationToken);

    /// <summary>Publishes <paramref name="body"/> on the default exchange with routing key
    /// <paramref name="queue"/>, AMQP <c>reply_to</c> = <paramref name="replyTo"/> and
    /// <c>correlation_id</c> = <paramref name="correlationId"/>.</summary>
    Task PublishRequestAsync(string queue, string replyTo, string correlationId, byte[] body, CancellationToken cancellationToken);

    /// <summary>
    /// Cancels the reply-queue consumer. On a caller-owned channel this is what lets the exclusive auto-delete queue
    /// go away (auto-delete needs the last consumer to cancel); it is a no-op when nothing was declared. Must not throw
    /// for a channel that is already closed.
    /// </summary>
    Task CancelAsync(CancellationToken cancellationToken);
}

/// <summary>The <c>RabbitMQ.Client</c> 7.x implementation of <see cref="IAuthzTransport"/>.</summary>
internal sealed class RabbitMqAuthzTransport : IAuthzTransport
{
    private readonly IChannel _channel;
    private string? _consumerTag;

    internal RabbitMqAuthzTransport(IChannel channel) => _channel = channel ?? throw new ArgumentNullException(nameof(channel));

    public async Task<string> DeclareReplyQueueAsync(Func<AuthzDelivery, Task> onDelivery, Action onClosed, CancellationToken cancellationToken)
    {
        // Empty name: the broker names it (amq.gen-...). Exclusive: only this connection may consume it.
        // Auto-delete: it goes with its consumer. Not durable: nothing about it survives a restart.
        QueueDeclareOk declared = await _channel.QueueDeclareAsync(
            queue: string.Empty, durable: false, exclusive: true, autoDelete: true,
            arguments: null, passive: false, noWait: false, cancellationToken).ConfigureAwait(false);

        var consumer = new AsyncEventingBasicConsumer(_channel);
        consumer.ReceivedAsync += (_, ea) =>
        {
            ulong tag = ea.DeliveryTag;
            var delivery = new AuthzDelivery(
                ea.Body.ToArray(), // library-owned memory is only valid for this event
                () => _channel.BasicAckAsync(tag, multiple: false),
                () => _channel.BasicNackAsync(tag, multiple: false, requeue: false),
                ea.Exchange,
                ea.RoutingKey);
            return onDelivery(delivery);
        };
        consumer.ShutdownAsync += (_, _) =>
        {
            onClosed();
            return Task.CompletedTask;
        };
        // A broker-side cancel (the reply queue was deleted while the channel stays open) raises UnregisteredAsync,
        // not ShutdownAsync; without this the requester would keep publishing with a dead reply_to.
        consumer.UnregisteredAsync += (_, _) =>
        {
            onClosed();
            return Task.CompletedTask;
        };

        _consumerTag = await _channel.BasicConsumeAsync(
            declared.QueueName, autoAck: false, consumerTag: string.Empty, noLocal: false,
            exclusive: true, arguments: null, consumer, cancellationToken).ConfigureAwait(false);
        return declared.QueueName;
    }

    public async Task CancelAsync(CancellationToken cancellationToken)
    {
        string? tag = Interlocked.Exchange(ref _consumerTag, null);
        if (tag is null || !_channel.IsOpen)
        {
            return;
        }
        try
        {
            await _channel.BasicCancelAsync(tag, noWait: false, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The channel closed under us: the broker has already removed the consumer and the queue.
        }
    }

    public async Task PublishRequestAsync(string queue, string replyTo, string correlationId, byte[] body, CancellationToken cancellationToken)
    {
        var properties = new BasicProperties
        {
            ContentType = "application/json",
            CorrelationId = correlationId,
            ReplyTo = replyTo,
        };
        await _channel.BasicPublishAsync(
            exchange: string.Empty, routingKey: queue, mandatory: false,
            basicProperties: properties, body: body, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// The AMQP authorization requester (CONTRACT.md &#167;8, "Signed authorization responses", contract 1.68;
/// audit finding N2). It publishes a signed <c>AuthzRequest</c> on <c>axiam.authz.request</c> with a private,
/// exclusive, broker-named <c>reply_to</c> queue, and accepts an answer only when it verifies as the server's
/// signed response to THAT request.
/// </summary>
/// <remarks>
/// <para>
/// <b>Verify the received bytes, deliver the same bytes (audit C2).</b> The signature is checked over the
/// delivery body with its trailing <c>hmac_signature</c> member cut out &#8212; never over a re-serialization,
/// whose string escaping would differ from the server's for a <c>reason</c> that echoes
/// <c>&lt; &gt; &amp;</c> or non-ASCII text &#8212; and the decision handed to the caller is decoded from those
/// very canonical bytes.
/// </para>
/// <para>
/// <b>What a response must satisfy</b> (consumer obligations 1&#8211;4): <c>allowed</c> a JSON boolean and
/// <c>tenant_id</c>, <c>nonce</c> and <c>hmac_signature</c> present, with the signature the last member and no
/// duplicate or case-variant keys; <c>HMAC-SHA256</c> under the subkey of the requester's OWN tenant and the
/// <c>key_version</c> it sent, compared in constant time; and <c>tenant_id</c>, <c>correlation_id</c> and
/// <c>nonce</c> equal to one outstanding request, which is then retired. Anything else is nacked without
/// requeue, logged as a security event without a signature value, and never an allow; the check keeps waiting
/// for the genuine answer until it times out.
/// </para>
/// <para>
/// <b>Trust boundary.</b> The key is the tenant's own subkey, so a valid signature proves the answer came from a
/// holder of it, not from the server in particular; this is why every requester uses its own exclusive reply
/// queue (see the contract's trust-boundary clause). The requester takes the subkey for <c>key_version</c> 2 from
/// the caller &#8212; derive it as &#167;8 describes, from the key the management API returns; it never reads it
/// from a response.
/// </para>
/// <para>
/// A broker confirm is not evidence that AXIAM decided a request, and a minimal-profile server
/// (<c>AXIAM__AMQP__ENABLED=false</c>) reads no AMQP queue at all: a check then times out. Use REST or gRPC there.
/// </para>
/// <para>
/// <b>Server version, and no unsigned responses.</b> The AMQP authorization requester requires an AXIAM server of
/// 1.68 or later (contract 1.68). Such a server signs every authorization response with the tenant's AMQP subkey and
/// answers on the requester's private <c>reply_to</c> queue. A server older than 1.68 ignores <c>reply_to</c> and
/// answers, unsigned, only on the shared <c>axiam.authz.response</c> queue, which this requester never reads: against
/// it every check times out. There is no option to accept unsigned responses (CONTRACT 1.69 &#167;8): no AXIAM
/// server sends one to a reply queue, so an unsigned response can only have been published by someone else, and it
/// is discarded and logged. During a rolling upgrade from a pre-1.68 server, use REST or gRPC authorization until
/// every replica runs 1.68 or later.
/// </para>
/// <para>
/// <b>The discard event.</b> Every response that is discarded (reason <c>malformed</c>, <c>unsigned</c>,
/// <c>signature</c>, <c>tenant</c> or <c>unknown_request</c>) logs one warning on <see cref="AxiamAuthzRequesterOptions.Logger"/>
/// with exactly the members <c>timestamp</c> (RFC 3339 UTC), <c>exchange</c>, <c>routing_key</c> (the requester's own
/// reply queue), <c>tenant_id</c> (the requester's OWN tenant, never the one the response claims) and <c>reason</c>.
/// The body is unauthenticated input: no signature, nonce, correlation id or other body member is ever logged.
/// </para>
/// </remarks>
public sealed class AxiamAuthzRequester : IAsyncDisposable
{
    /// <summary>The queue the server consumes <c>AuthzRequest</c> from.</summary>
    public const string RequestQueue = "axiam.authz.request";

    /// <summary>The <c>key_version</c> this requester sends; the caller supplies the matching tenant subkey.</summary>
    public const int KeyVersion = 2;

    /// <summary>The default bound on one <see cref="CheckAsync"/>.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

    /// <summary>The prefix of the server's own queues; it does not honour a <c>reply_to</c> that starts with it (&#167;8 rule 5).</summary>
    private const string ServerQueuePrefix = "axiam.";

    private static readonly byte[] SignatureMember = Encoding.ASCII.GetBytes(",\"hmac_signature\":\"");
    private const int SignatureHexLength = 64;

    private sealed class Pending
    {
        internal Pending(string nonce) => Nonce = nonce;

        internal string Nonce { get; }

        internal TaskCompletionSource<AmqpAuthzDecision> Result { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private readonly IAuthzTransport _transport;
    private readonly string _tenantId;
    private readonly byte[] _signingKey;
    private readonly ILogger _logger;
    private readonly TimeSpan _timeout;
    private readonly object _gate = new();
    private readonly Dictionary<string, Pending> _pending = new(StringComparer.Ordinal); // keyed by correlation_id
    private readonly Func<IAsyncDisposable?>? _ownedResources;
    private bool _closed;
    private string _replyTo = string.Empty;

    /// <summary>The clock for <c>issued_at</c>; a test seam.</summary>
    internal TimeProvider Clock { get; set; } = TimeProvider.System;

    private AxiamAuthzRequester(
        IAuthzTransport transport,
        string tenantId,
        byte[] signingKey,
        AxiamAuthzRequesterOptions? options,
        Func<IAsyncDisposable?>? ownedResources)
    {
        _transport = transport;
        _tenantId = tenantId;
        _signingKey = (byte[])signingKey.Clone();
        _logger = options?.Logger ?? NullLogger.Instance;
        _timeout = options?.Timeout is { } t && t > TimeSpan.Zero ? t : DefaultTimeout;
        _ownedResources = ownedResources;
    }

    /// <summary>The private reply queue requests name in their <c>reply_to</c>.</summary>
    public string ReplyTo => _replyTo;

    /// <summary>
    /// Opens a private reply queue on <paramref name="channel"/> and returns a requester for
    /// <paramref name="tenantId"/>. The channel stays the caller's: disposing the requester stops consuming but
    /// does not close it. For a connection this SDK opens (and verifies, &#167;8b), see
    /// <see cref="ConnectAsync"/>.
    /// </summary>
    /// <param name="channel">A channel on a connection the caller opened over <c>amqps://</c> (&#167;8b).</param>
    /// <param name="tenantId">The requester's OWN tenant: the only tenant a response is accepted for.</param>
    /// <param name="signingKey">The tenant's AMQP subkey for <see cref="KeyVersion"/> (&#167;8: HKDF of the key
    /// the management API returns).</param>
    /// <param name="options">Optional behaviour.</param>
    /// <param name="cancellationToken">Cancels the queue declaration.</param>
    public static Task<AxiamAuthzRequester> CreateAsync(
        IChannel channel,
        string tenantId,
        byte[] signingKey,
        AxiamAuthzRequesterOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(channel);
        return CreateAsync(new RabbitMqAuthzTransport(channel), tenantId, signingKey, options, null, cancellationToken);
    }

    /// <summary>
    /// Connects to <paramref name="amqpUri"/> (<c>amqps://</c> only, &#167;8b, with the broker verified), opens a
    /// channel, and returns a requester that owns both: disposing it closes them.
    /// </summary>
    /// <param name="amqpUri">The broker URI; anything but <c>amqps://</c> is refused.</param>
    /// <param name="tenantId">The requester's OWN tenant.</param>
    /// <param name="signingKey">The tenant's AMQP subkey for <see cref="KeyVersion"/>.</param>
    /// <param name="options">Optional behaviour.</param>
    /// <param name="brokerCaCertificate">The CA of a privately-issued broker certificate, or <c>null</c>.</param>
    /// <param name="clientCertificate">A client certificate with its private key for mutual TLS, or <c>null</c>.</param>
    /// <param name="cancellationToken">Cancels connecting and the queue declaration.</param>
    public static async Task<AxiamAuthzRequester> ConnectAsync(
        string amqpUri,
        string tenantId,
        byte[] signingKey,
        AxiamAuthzRequesterOptions? options = null,
        X509Certificate2? brokerCaCertificate = null,
        X509Certificate2? clientCertificate = null,
        CancellationToken cancellationToken = default)
    {
        ConnectionFactory factory = Reactor.ReactorConnections.CreateConnectionFactory(amqpUri, brokerCaCertificate, clientCertificate);
        IConnection connection = await factory.CreateConnectionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            IChannel channel = await connection.CreateChannelAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
            try
            {
                return await CreateAsync(
                    new RabbitMqAuthzTransport(channel), tenantId, signingKey, options,
                    () => new CloseChannelAndConnection(channel, connection), cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
                throw;
            }
        }
        catch
        {
            await connection.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private sealed class CloseChannelAndConnection : IAsyncDisposable
    {
        private readonly IChannel _channel;
        private readonly IConnection _connection;

        internal CloseChannelAndConnection(IChannel channel, IConnection connection)
        {
            _channel = channel;
            _connection = connection;
        }

        public async ValueTask DisposeAsync()
        {
            await _channel.CloseAsync().ConfigureAwait(false);
            await _connection.CloseAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Test entry: a requester over a caller-supplied <see cref="IAuthzTransport"/>.</summary>
    internal static async Task<AxiamAuthzRequester> CreateAsync(
        IAuthzTransport transport,
        string tenantId,
        byte[] signingKey,
        AxiamAuthzRequesterOptions? options,
        Func<IAsyncDisposable?>? ownedResources,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(signingKey);
        if (!Guid.TryParse(tenantId, out Guid tenant))
        {
            throw new ArgumentException("the authz requester's tenant_id is not a UUID", nameof(tenantId));
        }
        if (signingKey.Length == 0)
        {
            throw new ArgumentException("the authz requester needs the tenant signing key", nameof(signingKey));
        }

        var requester = new AxiamAuthzRequester(transport, tenant.ToString("D", CultureInfo.InvariantCulture), signingKey, options, ownedResources);
        string queue = await transport.DeclareReplyQueueAsync(requester.HandleAsync, () => requester.Close(), cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(queue) || queue.StartsWith(ServerQueuePrefix, StringComparison.Ordinal))
        {
            // The server answers a reply_to naming one of its own queues on the shared axiam.authz.response
            // instead (§8 rule 5), which would put this requester back on the shared queue the contract forbids.
            requester.Close();
            try
            {
                await transport.CancelAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Best effort, as on dispose.
            }
            throw new InvalidOperationException($"the authz reply queue '{queue}' is not a private queue");
        }

        requester._replyTo = queue;
        return requester;
    }

    /// <summary>
    /// Asks the server whether <paramref name="subjectId"/> may perform <paramref name="action"/> on
    /// <paramref name="resourceId"/> (optionally narrowed by <paramref name="scope"/>) and waits for the verified
    /// answer. A response that fails verification or binding is discarded and the call keeps waiting for the
    /// genuine one until it is cancelled or times out: a failed verification is never an allow and never
    /// completes the request.
    /// </summary>
    /// <exception cref="TimeoutException">No verified answer arrived within the configured timeout.</exception>
    /// <exception cref="ObjectDisposedException">The requester, or its reply queue, is closed.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public async Task<AmqpAuthzDecision> CheckAsync(
        string subjectId,
        string action,
        string resourceId,
        string? scope = null,
        CancellationToken cancellationToken = default)
    {
        string correlationId = NewUuid(); // unpredictable: a CSPRNG v4 UUID
        string nonce = NewUuid();         // fresh per request, independent of the correlation_id
        byte[] body = BuildRequest(_signingKey, correlationId, _tenantId, subjectId, action, resourceId, scope, nonce, Clock.GetUtcNow());

        var pending = new Pending(nonce);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            _pending[correlationId] = pending;
        }

        try
        {
            await _transport.PublishRequestAsync(RequestQueue, _replyTo, correlationId, body, cancellationToken).ConfigureAwait(false);
            return await pending.Result.Task.WaitAsync(_timeout, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            lock (_gate)
            {
                _pending.Remove(correlationId);
            }
        }
    }

    /// <summary>Stops accepting answers; outstanding and later checks fail with
    /// <see cref="ObjectDisposedException"/>. The reply queue is exclusive and auto-delete, so the broker removes
    /// it with the channel.</summary>
    public async ValueTask DisposeAsync()
    {
        bool first = Close();
        if (first)
        {
            // Stop consuming so an exclusive auto-delete reply queue on a CALLER-OWNED channel is deleted too (it
            // goes only when its last consumer cancels, and that channel stays open).
            try
            {
                await _transport.CancelAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Best effort: a broker that is already gone has dropped the queue.
            }
        }
        if (_ownedResources?.Invoke() is { } owned)
        {
            await owned.DisposeAsync().ConfigureAwait(false);
        }
    }

    internal bool Close()
    {
        List<Pending> outstanding;
        lock (_gate)
        {
            if (_closed)
            {
                return false;
            }
            _closed = true;
            outstanding = new List<Pending>(_pending.Values);
        }
        foreach (Pending p in outstanding)
        {
            p.Result.TrySetException(new ObjectDisposedException(nameof(AxiamAuthzRequester)));
        }
        return true;
    }

    /// <summary>Registers an outstanding request without publishing one; a test entry (the contract vectors fix
    /// the <c>correlation_id</c> and <c>nonce</c>).</summary>
    internal Task<AmqpAuthzDecision> ExpectAsync(string correlationId, string nonce)
    {
        var pending = new Pending(nonce);
        lock (_gate)
        {
            _pending[correlationId] = pending;
        }
        return pending.Result.Task;
    }

    internal int OutstandingCount
    {
        get
        {
            lock (_gate)
            {
                return _pending.Count;
            }
        }
    }

    // ---- the response path -----------------------------------------------------------------

    /// <summary>Why a response was discarded: the five <c>reason</c> codes of the discard event (CONTRACT.md &#167;8
    /// consumer obligation 4).</summary>
    private static class Discard
    {
        internal const string Malformed = "malformed";
        internal const string Unsigned = "unsigned";
        internal const string Signature = "signature";
        internal const string Tenant = "tenant";
        internal const string UnknownRequest = "unknown_request";
    }

    /// <summary>Verifies one delivery and completes the matching request, or discards it (nack without requeue
    /// plus the security event).</summary>
    internal async Task HandleAsync(AuthzDelivery delivery)
    {
        // After Close: the answer is not decoded or dispatched, only nacked without requeue; no event (§8 consumer
        // obligation 4): the requester no longer has a request this could answer.
        bool closed;
        lock (_gate)
        {
            closed = _closed;
        }
        if (closed)
        {
            await delivery.NackWithoutRequeue().ConfigureAwait(false);
            return;
        }

        (AmqpAuthzDecision? decision, string? correlationId, string? failure) = VerifyResponse(delivery.Body);
        if (decision is null || correlationId is null)
        {
            LogDiscard(delivery, failure ?? Discard.Malformed);
            await delivery.NackWithoutRequeue().ConfigureAwait(false);
            return;
        }

        // Retired on acceptance: a second response for it finds nothing and is dropped.
        Pending? pending;
        lock (_gate)
        {
            _pending.Remove(correlationId, out pending);
        }
        if (pending is null)
        {
            LogDiscard(delivery, Discard.UnknownRequest);
            await delivery.NackWithoutRequeue().ConfigureAwait(false);
            return;
        }

        pending.Result.TrySetResult(decision);
        await delivery.Ack().ConfigureAwait(false);
    }

    /// <summary>
    /// The one security event of a discarded response (CONTRACT.md &#167;8 consumer obligation 4; protocol rule 4).
    /// Carries exactly <c>timestamp</c>, <c>exchange</c>, <c>routing_key</c>, <c>tenant_id</c> and <c>reason</c>:
    /// <c>tenant_id</c> is the requester's own tenant, <c>routing_key</c> its own reply queue where the transport does
    /// not report the delivery's, and nothing is read from the body, which is unauthenticated input.
    /// </summary>
    private void LogDiscard(AuthzDelivery delivery, string reason)
    {
        string timestamp = Clock.GetUtcNow().UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        _logger.LogWarning(
            "axiam_sdk_security: AMQP authz response discarded (timestamp={timestamp}, exchange={exchange}, routing_key={routing_key}, tenant_id={tenant_id}, reason={reason})",
            timestamp, delivery.Exchange ?? string.Empty, delivery.RoutingKey ?? _replyTo, _tenantId, reason);
    }

    /// <summary>
    /// Applies consumer obligations 1&#8211;3 to <paramref name="body"/>. It never re-serializes: the signature is
    /// checked over <paramref name="body"/> minus its trailing signature member, and the decision is decoded from
    /// those same bytes. The outstanding map is read, not changed. On a discard the third member is one of the
    /// <see cref="Discard"/> codes.
    /// </summary>
    private (AmqpAuthzDecision? Decision, string? CorrelationId, string? Failure) VerifyResponse(byte[] body)
    {
        if (SignedJson.HasAmbiguousKeys(body))
        {
            return Fail(Discard.Malformed); // not an object with unambiguous keys
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(body);
        }
        catch (JsonException)
        {
            return Fail(Discard.Malformed);
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return Fail(Discard.Malformed);
            }

            // A member named hmac_signature in any letter case is a signature member: a body carrying one is
            // malformed or fails verification, never "unsigned".
            bool hasSignatureMember = false;
            foreach (JsonProperty property in root.EnumerateObject())
            {
                if (string.Equals(property.Name, "hmac_signature", StringComparison.OrdinalIgnoreCase))
                {
                    hasSignatureMember = true;
                    break;
                }
            }

            if (!hasSignatureMember)
            {
                return Fail(Discard.Unsigned); // rule 1: no hmac_signature at all; there is no opt-out (contract 1.69)
            }

            // The canonical bytes: body with the final `,"hmac_signature":"<64 hex>"` taken out of the
            // closing brace. A body not ending in that member is discarded (rule 1) — never repaired.
            if (!TryCutTrailingSignature(body, out byte[]? canonical, out string? signatureHex))
            {
                return Fail(Discard.Malformed);
            }
            if (!root.TryGetProperty("hmac_signature", out JsonElement embedded) ||
                embedded.ValueKind != JsonValueKind.String ||
                embedded.GetString() != signatureHex)
            {
                return Fail(Discard.Malformed);
            }

            // Reason order step 3 (before the HMAC): allowed, tenant_id, nonce and correlation_id present and
            // well-typed in the received bytes, else malformed. The verified bytes are read again below.
            if (!root.TryGetProperty("allowed", out JsonElement receivedAllowed) ||
                receivedAllowed.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
                !TryString(root, "correlation_id", required: true, out _) ||
                !TryString(root, "tenant_id", required: true, out _) ||
                !TryString(root, "nonce", required: true, out _))
            {
                return Fail(Discard.Malformed);
            }

            // Rule 2: HMAC-SHA256 under the requester's own tenant subkey, constant-time.
            byte[] expected = Convert.FromHexString(signatureHex!);
            byte[] computed = HMACSHA256.HashData(_signingKey, canonical!);
            if (!CryptographicOperations.FixedTimeEquals(computed, expected))
            {
                return Fail(Discard.Signature);
            }

            // Everything below reads the VERIFIED canonical bytes, never `body` (audit C2).
            JsonDocument verified;
            try
            {
                verified = JsonDocument.Parse(canonical!);
            }
            catch (JsonException)
            {
                return Fail(Discard.Malformed);
            }

            using (verified)
            {
                JsonElement v = verified.RootElement;
                if (v.ValueKind != JsonValueKind.Object ||
                    !v.TryGetProperty("allowed", out JsonElement vAllowed) ||
                    vAllowed.ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
                    !TryString(v, "correlation_id", required: true, out string? correlationId) ||
                    !TryString(v, "tenant_id", required: true, out string? tenantId) ||
                    !TryString(v, "nonce", required: true, out string? nonce) ||
                    !TryString(v, "reason", required: false, out string? reason) ||
                    !TryString(v, "reason_code", required: false, out string? reasonCode))
                {
                    return Fail(Discard.Malformed); // tenant_id, nonce or correlation_id missing, or a member of the wrong type
                }

                // Rule 3: bound to this requester's tenant and to one outstanding request.
                if (!string.Equals(tenantId, _tenantId, StringComparison.Ordinal))
                {
                    return Fail(Discard.Tenant);
                }
                bool outstanding;
                lock (_gate)
                {
                    outstanding = _pending.TryGetValue(correlationId!, out Pending? p) &&
                                  string.Equals(p.Nonce, nonce, StringComparison.Ordinal);
                }
                if (!outstanding)
                {
                    return Fail(Discard.UnknownRequest);
                }

                return (new AmqpAuthzDecision(vAllowed.ValueKind == JsonValueKind.True, reason, reasonCode), correlationId, null);
            }
        }
    }

    private static (AmqpAuthzDecision?, string?, string?) Fail(string reason) => (null, null, reason);

    /// <summary>Reads a string member; an absent or null optional member is <c>null</c>, a member of any other
    /// type (or an absent/empty required one) is a failure.</summary>
    private static bool TryString(JsonElement obj, string name, bool required, out string? value)
    {
        value = null;
        if (!obj.TryGetProperty(name, out JsonElement element) || element.ValueKind == JsonValueKind.Null)
        {
            return !required;
        }
        if (element.ValueKind != JsonValueKind.String)
        {
            return false;
        }
        value = element.GetString();
        return !required || !string.IsNullOrEmpty(value);
    }

    /// <summary>
    /// Removes the final <c>,"hmac_signature":"&lt;64 hex&gt;"</c> member from <paramref name="body"/>
    /// (see <see cref="SignedJson.TryCutTrailingSignature"/>); the requester's signatures are exactly 64 hex digits.
    /// </summary>
    internal static bool TryCutTrailingSignature(byte[] body, out byte[]? canonical, out string? signatureHex) =>
        SignedJson.TryCutTrailingSignature(body, SignatureHexLength, out canonical, out signatureHex);

    // ---- the request path ------------------------------------------------------------------

    /// <summary>
    /// Serializes and signs an <c>AuthzRequest</c> in the server's field order (<c>correlation_id</c>,
    /// <c>tenant_id</c>, <c>subject_id</c>, <c>action</c>, <c>resource_id</c>, optional <c>scope</c>,
    /// <c>key_version</c>, <c>nonce</c>, <c>issued_at</c>), compact, with the signature appended as the trailing
    /// member. Strings are written the way <c>serde_json</c> writes them (see <see cref="AppendJsonString"/>), and
    /// the server verifies the bytes it would itself produce.
    /// </summary>
    internal static byte[] BuildRequest(
        byte[] key,
        string correlationId,
        string tenantId,
        string subjectId,
        string action,
        string resourceId,
        string? scope,
        string nonce,
        DateTimeOffset now)
    {
        if (!Guid.TryParse(subjectId, out Guid subject))
        {
            throw new ArgumentException("subject_id is not a UUID", nameof(subjectId));
        }
        if (!Guid.TryParse(resourceId, out Guid resource))
        {
            throw new ArgumentException("resource_id is not a UUID", nameof(resourceId));
        }
        ArgumentException.ThrowIfNullOrEmpty(action);

        var json = new StringBuilder(256);
        json.Append("{\"correlation_id\":\"").Append(correlationId)
            .Append("\",\"tenant_id\":\"").Append(tenantId)
            .Append("\",\"subject_id\":\"").Append(subject.ToString("D", CultureInfo.InvariantCulture))
            .Append("\",\"action\":");
        AppendJsonString(json, action);
        json.Append(",\"resource_id\":\"").Append(resource.ToString("D", CultureInfo.InvariantCulture)).Append('"');
        if (scope is not null)
        {
            json.Append(",\"scope\":");
            AppendJsonString(json, scope);
        }
        json.Append(",\"key_version\":").Append(KeyVersion.ToString(CultureInfo.InvariantCulture))
            .Append(",\"nonce\":\"").Append(nonce)
            .Append("\",\"issued_at\":\"").Append(now.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture))
            .Append("\"}");

        byte[] canonical = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetBytes(json.ToString());
        string signature = Convert.ToHexString(HMACSHA256.HashData(key, canonical)).ToLowerInvariant();

        // canonical minus its closing brace, then the signature member as the LAST member.
        var wire = new byte[canonical.Length - 1 + SignatureMember.Length + SignatureHexLength + 2];
        canonical.AsSpan(0, canonical.Length - 1).CopyTo(wire);
        SignatureMember.CopyTo(wire, canonical.Length - 1);
        Encoding.ASCII.GetBytes(signature, 0, SignatureHexLength, wire, canonical.Length - 1 + SignatureMember.Length);
        wire[^2] = (byte)'"';
        wire[^1] = (byte)'}';
        return wire;
    }

    /// <summary>
    /// Writes <paramref name="value"/> as a JSON string exactly as <c>serde_json</c> does: <c>"</c> and <c>\</c>
    /// escaped, the short escapes <c>\b \f \n \r \t</c>, every other control character below U+0020 as
    /// <c>\u00XX</c> with lower-case hex, and everything else &#8212; <c>/</c>, <c>&lt;</c>, <c>&gt;</c>, <c>&amp;</c>,
    /// U+2028/U+2029 and all non-ASCII &#8212; raw. <c>System.Text.Json</c>'s encoders escape more than this, so
    /// the signed bytes would differ. A lone surrogate cannot be UTF-8 and is refused.
    /// </summary>
    private static void AppendJsonString(StringBuilder sb, string value)
    {
        sb.Append('"');
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                sb.Append(c).Append(value[++i]);
                continue;
            }
            if (char.IsSurrogate(c))
            {
                throw new ArgumentException("action and scope must be valid UTF-16 (no lone surrogate)");
            }
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20)
                    {
                        sb.Append("\\u00").Append(((int)c).ToString("x2", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
        sb.Append('"');
    }

    /// <summary>A version-4 UUID from a CSPRNG, lower-case and hyphenated: unpredictable, as the contract's
    /// trust-boundary clause requires of <c>correlation_id</c> and <c>nonce</c>.</summary>
    private static string NewUuid()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        bytes[6] = (byte)((bytes[6] & 0x0f) | 0x40);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
        return new Guid(bytes, bigEndian: true).ToString("D", CultureInfo.InvariantCulture);
    }
}
