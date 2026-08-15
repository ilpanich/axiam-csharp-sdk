using System;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Amqp;
using Axiam.Sdk.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

namespace Axiam.Sdk.Reactor;

/// <summary>
/// The &#167;22 reactor runtime: consume the server-declared queue, verify, decide, sign,
/// reply.
///
/// <para>
/// Start one with <see cref="ReactorServeAsync"/>. Per delivery it:
/// </para>
/// <list type="number">
/// <item><description>rejects <c>key_version &lt; 2</c> — before the signature is even
/// computed;</description></item>
/// <item><description>verifies the HMAC over the canonical bytes (&#167;22.2:
/// <c>hmac_signature</c> present and <c>null</c>);</description></item>
/// <item><description>checks <c>issued_at</c> against the freshness window, in both
/// directions;</description></item>
/// <item><description>checks <c>nonce</c> against a seen-set;</description></item>
/// <item><description><em>then</em> decodes the payload and calls the handler;</description></item>
/// <item><description>signs the reply with the same tenant subkey and publishes it to the
/// delivery's <c>reply_to</c> queue, echoing <c>correlation_id</c> both as an AMQP property
/// and — the one the server authenticates — inside the signed body.</description></item>
/// </list>
///
/// <para>
/// A runtime that hands an unverified payload to user code has already lost: the handler
/// will act on it, and "we checked afterwards" is not a check. The handler call site here
/// is structurally unreachable until every gate above has passed.
/// </para>
///
/// <para><b>Four rules this class holds to</b></para>
/// <list type="number">
/// <item><description><b>It declares no topology.</b> No <c>ExchangeDeclareAsync</c>, no
/// <c>QueueDeclareAsync</c>, no <c>QueueBindAsync</c>, anywhere — asserted by a test
/// against the AMQP client's own recorded invocations. Actors consume; the server
/// declares.</description></item>
/// <item><description><b>It fails closed on its own errors.</b> A handler that throws, or a
/// body it cannot decode, produces <em>no reply</em> — never a synthesized <c>allow</c>.
/// Answering <c>allow</c> on behalf of a handler that crashed would override the operator's
/// <c>fail_closed</c> setting from inside the library.</description></item>
/// <item><description><b>It does not filter a patch.</b> A handler's patch goes on the wire
/// exactly as returned, forbidden keys included.</description></item>
/// <item><description><b>It honours <c>timeout_ms</c>.</b> When the handler returns after
/// the window closed, the reply is abandoned rather than published late — the server has
/// already stopped listening.</description></item>
/// </list>
///
/// <para><b>Interaction with &#167;16, &#167;18 and &#167;19</b></para>
/// <para>
/// <b>&#167;16 does not apply to a reply.</b> A correlation is single-use and a late reply
/// is discarded, so re-sending one could only add load to a server that has already moved
/// on. The recovery mechanism for an unanswered dispatch is the registration's
/// <c>failure_policy</c>, on the server, not a retry here. Connection recovery is the
/// RabbitMQ client's, left on exactly as <see cref="AxiamAmqpConsumer"/> leaves it.
/// </para>
/// <para>
/// <b>&#167;18:</b> <see cref="DisposeAsync"/> is idempotent, cancels the consumer so no new
/// delivery starts, drains what is in flight up to the configured grace period, and does
/// not close the caller's channel or connection.
/// </para>
/// <para>
/// <b>&#167;19:</b> one <c>RequestStart</c>/<c>RequestEnd</c> pair per dispatched event, with
/// the event name as the path template — a closed set of five values, so it cannot become a
/// cardinality bomb.
/// </para>
/// </summary>
public sealed class ReactorServer : IAsyncDisposable
{
    /// <summary>The &#167;19 operation name every reactor telemetry event carries.</summary>
    public const string TelemetryOperation = "ReactorServeAsync";

    /// <summary>The &#167;19 "method" label for an AMQP dispatch.</summary>
    public const string TelemetryMethod = "AMQP";

    /// <summary>The drain grace period <see cref="DisposeAsync"/> uses when none was configured.</summary>
    public static readonly TimeSpan DefaultShutdownGrace = TimeSpan.FromSeconds(10);

    private readonly ReactorServeOptions _options;
    private readonly IChannel _channel;
    private readonly byte[] _signingKey;
    private readonly ILogger _logger;
    private readonly TimeSpan _freshnessSkew;
    private readonly TimeSpan _shutdownGrace;
    private readonly Func<DateTimeOffset> _clock;
    private readonly TelemetryHook? _telemetryHook;
    private readonly ReplayGuard _replayGuard;
    private readonly CancellationTokenSource _shutdown = new();

    private int _inFlight;
    private int _closed;
    private string? _consumerTag;

    private ReactorServer(ReactorServeOptions options)
    {
        _options = options;
        _channel = options.Channel;
        _signingKey = options.SigningKey.Expose();
        _logger = options.Logger ?? NullLogger.Instance;
        _freshnessSkew = options.FreshnessSkew is { } skew && skew > TimeSpan.Zero
            ? skew
            : ReactorProtocol.DefaultFreshnessSkew;
        _shutdownGrace = options.ShutdownGrace is { } grace && grace > TimeSpan.Zero
            ? grace
            : DefaultShutdownGrace;
        _clock = options.Clock ?? (static () => DateTimeOffset.UtcNow);
        _telemetryHook = options.TelemetryHook;
        Queue = options.ResolvedQueue;

        // §22.2 restates §8 v2's consumer obligations unchanged, so this is the SAME gate
        // AxiamAmqpConsumer already runs — reused rather than reimplemented, because two
        // implementations of one security control is one too many. Its clock seam is
        // internal, which is why the reactor can share it without widening the public API.
        _replayGuard = new ReplayGuard(_freshnessSkew, _clock);
    }

    /// <summary>The server-declared queue this runtime consumes.</summary>
    public string Queue { get; }

    /// <summary>How many events are being handled right now; drains to zero during shutdown.</summary>
    public int InFlight => Volatile.Read(ref _inFlight);

    /// <summary>Whether <see cref="DisposeAsync"/> has run.</summary>
    public bool IsClosed => Volatile.Read(ref _closed) != 0;

    /// <summary>
    /// Starts serving reactor events (<c>sdks/CONTRACT.md</c> &#167;22.10 —
    /// <c>ReactorServeAsync</c>).
    ///
    /// <para>
    /// Applies the configured QoS prefetch and registers a manual-ack consumer on the
    /// <b>server-declared</b> queue. Nothing is declared and nothing is bound.
    /// </para>
    /// </summary>
    /// <param name="options">The configuration.</param>
    /// <param name="cancellationToken">Cancellation for the QoS/consume setup calls.</param>
    /// <returns>
    /// A running server; dispose it to stop, ideally with <c>await using</c>.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// When neither or both of handler/listener, or of queue/reactorId, were supplied.
    /// </exception>
    public static async Task<ReactorServer> ReactorServeAsync(
        ReactorServeOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var server = new ReactorServer(options);

        await options.Channel
            .BasicQosAsync(prefetchSize: 0, prefetchCount: options.Prefetch, global: false, cancellationToken)
            .ConfigureAwait(false);

        var consumer = new AsyncEventingBasicConsumer(options.Channel);
        consumer.ReceivedAsync += server.CreateReceivedHandler();

        server._consumerTag = await options.Channel.BasicConsumeAsync(
            server.Queue,
            autoAck: false,
            consumerTag: string.Empty,
            noLocal: false,
            exclusive: false,
            arguments: null,
            consumer,
            cancellationToken).ConfigureAwait(false);

        return server;
    }

    /// <summary>
    /// Stops serving, deterministically (&#167;18).
    ///
    /// <para>
    /// Cancels the consumer first so no new delivery can start, then waits for in-flight
    /// handlers up to the configured grace period. Idempotent. It does not close the channel
    /// or the connection — the caller owns those, exactly as <see cref="AxiamAmqpConsumer"/>
    /// leaves them.
    /// </para>
    /// </summary>
    /// <returns>A task that completes once the drain finishes or the grace period elapses.</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }

        if (_consumerTag is { } tag)
        {
            try
            {
                await _channel.BasicCancelAsync(tag, noWait: false).ConfigureAwait(false);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                // A channel already torn down by the broker cannot be cancelled, and
                // failing shutdown over that would turn a clean stop into an exception on
                // the way out. The exception TYPE only — never a key, never a URI.
                _logger.LogDebug(
                    "axiam_sdk_reactor: consumer cancel failed during shutdown ({Failure})",
                    e.GetType().Name);
            }
        }

        // Stopwatch, deliberately not the configured clock: a test pinning the clock to a
        // fixed instant must not turn the drain into an unbounded wait.
        var elapsed = Stopwatch.StartNew();
        while (Volatile.Read(ref _inFlight) > 0 && elapsed.Elapsed < _shutdownGrace)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(10)).ConfigureAwait(false);
        }

        await _shutdown.CancelAsync().ConfigureAwait(false);
        _shutdown.Dispose();
    }

    /// <summary>
    /// The &#167;22 delivery pipeline, bound to this server.
    ///
    /// <para>
    /// Internal so tests can invoke it against synthesized
    /// <see cref="BasicDeliverEventArgs"/> and a fake <see cref="IChannel"/> — every branch
    /// below is provable without a live broker.
    /// </para>
    /// </summary>
    /// <returns>The callback registered with <c>BasicConsumeAsync</c>.</returns>
    internal AsyncEventHandler<BasicDeliverEventArgs> CreateReceivedHandler()
    {
        return async (_, ea) =>
        {
            Interlocked.Increment(ref _inFlight);
            try
            {
                await HandleAsync(ea).ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Decrement(ref _inFlight);
            }
        };
    }

    private async Task HandleAsync(BasicDeliverEventArgs ea)
    {
        // MUST copy — library-owned memory is only valid for the duration of this event
        // (RabbitMQ.Client 7.x migration note).
        byte[] body = ea.Body.ToArray();
        DateTimeOffset received = _clock();

        if (IsClosed)
        {
            // Cancelled, but the broker had already pushed this one. Requeue it: the next
            // runtime to attach is entitled to it, and answering after shutdown began would
            // be a reply nobody is waiting on.
            await _channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: true).ConfigureAwait(false);
            return;
        }

        ReactorEvent? reactorEvent = VerifyAndDecode(body, received, ea);
        if (reactorEvent is null)
        {
            // Every rejection path has already logged. Nack without requeue: a body that
            // failed §8 v2 will fail it again on redelivery, and its window is closing
            // either way.
            await _channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: false).ConfigureAwait(false);
            return;
        }

        Emit(new RequestStartEvent(TelemetryOperation, TelemetryMethod, reactorEvent.Event, 1));
        var span = Stopwatch.StartNew();

        if (_options.Listener is { } listener)
        {
            // §22.5: a listener never publishes a reply, and the server never reads one.
            // Observe and ack.
            try
            {
                await listener(reactorEvent, _shutdown.Token).ConfigureAwait(false);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                ReportHandlerFailure(reactorEvent, e);
                EmitEnd(reactorEvent, span, TelemetryOutcome.Failure);
                await _channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: false).ConfigureAwait(false);
                return;
            }

            EmitEnd(reactorEvent, span, TelemetryOutcome.Success);
            await _channel.BasicAckAsync(ea.DeliveryTag, multiple: false).ConfigureAwait(false);
            return;
        }

        ReactorDecision? decision;
        try
        {
            decision = await _options.Handler!(reactorEvent, _shutdown.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // §22.10 rule 2: no reply. The operator's failure_policy decides what a crashed
            // handler costs — an SDK that answers `allow` here has overridden a fail_closed
            // setting from inside the library.
            ReportHandlerFailure(reactorEvent, e);
            EmitEnd(reactorEvent, span, TelemetryOutcome.Failure);
            await _channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: false).ConfigureAwait(false);
            return;
        }

        if (decision is null)
        {
            ReportHandlerFailure(reactorEvent, cause: null);
            EmitEnd(reactorEvent, span, TelemetryOutcome.Failure);
            await _channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: false).ConfigureAwait(false);
            return;
        }

        // §22.3 / §22.10 rule 4: a late reply is discarded, and the CPU spent producing it
        // was spent for nothing. Abandon rather than answer into a closed window.
        if (_clock() >= reactorEvent.Deadline)
        {
            _logger.LogWarning(
                "axiam_sdk_reactor: handler finished after the {TimeoutMs} ms window closed for " +
                "event={Event} correlation={CorrelationId}; abandoning the reply",
                reactorEvent.TimeoutMs, reactorEvent.Event, reactorEvent.CorrelationId);
            EmitEnd(reactorEvent, span, TelemetryOutcome.Failure);
            await _channel.BasicAckAsync(ea.DeliveryTag, multiple: false).ConfigureAwait(false);
            return;
        }

        string? replyTo = ea.BasicProperties?.ReplyTo;
        if (string.IsNullOrWhiteSpace(replyTo))
        {
            _logger.LogWarning(
                "axiam_sdk_reactor: delivery for event={Event} correlation={CorrelationId} carried no " +
                "reply_to; publishing NO reply",
                reactorEvent.Event, reactorEvent.CorrelationId);
            EmitEnd(reactorEvent, span, TelemetryOutcome.Failure);
            await _channel.BasicAckAsync(ea.DeliveryTag, multiple: false).ConfigureAwait(false);
            return;
        }

        byte[] reply = ReactorProtocol.SignedReply(
            _signingKey,
            reactorEvent.CorrelationId,
            reactorEvent.TenantId,
            reactorEvent.Event,
            decision,
            Guid.NewGuid(),
            _clock());

        var properties = new BasicProperties
        {
            ContentType = "application/json",
            CorrelationId = reactorEvent.CorrelationId.ToString("D", CultureInfo.InvariantCulture),
        };

        // Default exchange, routing key = the reply queue: standard AMQP RPC. Publishing to
        // "" is not declaring topology — every broker routes the default exchange to the
        // same-named queue without any declaration.
        await _channel.BasicPublishAsync(
            exchange: string.Empty,
            routingKey: replyTo,
            mandatory: false,
            basicProperties: properties,
            body: reply).ConfigureAwait(false);

        EmitEnd(reactorEvent, span, TelemetryOutcome.Success);
        await _channel.BasicAckAsync(ea.DeliveryTag, multiple: false).ConfigureAwait(false);
    }

    /// <summary>
    /// The &#167;22.3 gate, in order: key version, MAC, freshness, nonce, then decode.
    /// Returns <c>null</c> — never a partially-trusted event — when any gate refuses.
    /// </summary>
    private ReactorEvent? VerifyAndDecode(byte[] body, DateTimeOffset now, BasicDeliverEventArgs ea)
    {
        JsonObject? root;
        try
        {
            root = JsonNode.Parse(body)?.AsObject();
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException or ArgumentException)
        {
            return Reject(ea, "body is not valid JSON");
        }

        if (root is null)
        {
            return Reject(ea, "body is not a JSON object");
        }

        if (IntField(root, "key_version") is not { } keyVersion || keyVersion < ReactorProtocol.MinAcceptedKeyVersion)
        {
            return Reject(ea, "key_version below the accepted floor");
        }

        if (!ReactorProtocol.VerifyEvent(_signingKey, body))
        {
            // §8.4: the fact of failure and the routing context, never the received or
            // expected MAC and never the key.
            return Reject(ea, "signature missing or invalid");
        }

        if (!ReplayGuard.TryExtractMetadata(body, out ReplayMetadata metadata))
        {
            return Reject(ea, "nonce or issued_at missing");
        }

        if (!DateTimeOffset.TryParse(
                metadata.IssuedAt,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out DateTimeOffset issuedAt))
        {
            return Reject(ea, "issued_at unparseable");
        }

        if (ParseGuid(metadata.Nonce) is not { } nonce)
        {
            return Reject(ea, "nonce is not a UUID");
        }

        // Freshness (both directions) and the nonce seen-set, from the SAME §8 v2 gate the
        // audit/authz consumer already runs — reused rather than reimplemented. It comes
        // strictly after the MAC verified, so the values it reads are authenticated ones,
        // and it records the nonce only when the message passes, so a body refused on
        // freshness does not burn a nonce a legitimate retry might reuse.
        if (!_replayGuard.Check(metadata))
        {
            return Reject(ea, "issued_at outside the freshness window, or nonce replay");
        }

        if (ParseGuid(StringField(root, "tenant_id")) is not { } tenantId)
        {
            return Reject(ea, "tenant_id missing or malformed");
        }

        if (tenantId != _options.TenantId)
        {
            // Cannot happen through a correctly declared queue, and is exactly the thing
            // worth refusing anyway if it ever does.
            return Reject(ea, "event names a different tenant");
        }

        if (ParseGuid(StringField(root, "correlation_id")) is not { } correlationId)
        {
            return Reject(ea, "correlation_id missing or malformed");
        }

        if (StringField(root, "event") is not { } eventName || string.IsNullOrWhiteSpace(eventName))
        {
            return Reject(ea, "event missing");
        }

        if (root["payload"] is not JsonObject payload)
        {
            return Reject(ea, "payload missing or not an object");
        }

        if (IntField(root, "timeout_ms") is not { } timeoutMs || timeoutMs <= 0)
        {
            return Reject(ea, "timeout_ms missing or out of range");
        }

        int effectiveTimeout = Math.Min(timeoutMs, ReactorProtocol.ChainCeilingMs);
        return new ReactorEvent(
            tenantId,
            eventName,
            correlationId,
            payload,
            effectiveTimeout,
            keyVersion,
            nonce,
            issuedAt,
            now.AddMilliseconds(effectiveTimeout));
    }

    private ReactorEvent? Reject(BasicDeliverEventArgs ea, string reason)
    {
        _logger.LogWarning(
            "axiam_sdk_security: reactor event rejected ({Reason}); no reply will be sent " +
            "(exchange={Exchange}, routingKey={RoutingKey})",
            reason, ea.Exchange, ea.RoutingKey);
        return null;
    }

    private void ReportHandlerFailure(ReactorEvent reactorEvent, Exception? cause)
    {
        _logger.LogWarning(
            "axiam_sdk_reactor: handler produced no decision for event={Event} correlation={CorrelationId}; " +
            "publishing NO reply, the registration's failure_policy applies ({Failure})",
            reactorEvent.Event, reactorEvent.CorrelationId, cause?.GetType().Name ?? "null decision");
    }

    private void EmitEnd(ReactorEvent reactorEvent, Stopwatch span, TelemetryOutcome outcome) =>
        Emit(new RequestEndEvent(
            TelemetryOperation, TelemetryMethod, reactorEvent.Event, 1, null, span.Elapsed, outcome));

    private void Emit(TelemetryEvent telemetryEvent)
    {
        if (_telemetryHook is null)
        {
            return;
        }

        try
        {
            _telemetryHook(telemetryEvent);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // §19.2 rule 2: telemetry is not permitted to fail the dispatch that fired it.
            _logger.LogDebug("axiam_sdk_reactor: telemetry hook threw ({Failure})", e.GetType().Name);
        }
    }

    private static string? StringField(JsonObject root, string field) =>
        root[field] is JsonValue value && value.TryGetValue(out string? text) ? text : null;

    private static int? IntField(JsonObject root, string field) =>
        root[field] is JsonValue value && value.TryGetValue(out int number) ? number : null;

    private static Guid? ParseGuid(string? raw) =>
        raw is not null && Guid.TryParseExact(raw, "D", out Guid parsed) ? parsed : null;
}
