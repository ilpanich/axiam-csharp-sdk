using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

namespace Axiam.Sdk.Amqp;

/// <summary>
/// AMQP event consumer: verify-before-handler HMAC gate plus the
/// <c>sdks/CONTRACT.md</c> §8 ack/nack matrix, built on <c>RabbitMQ.Client</c>
/// 7.x's async consumer API with automatic connection/topology recovery
/// enabled (D-11).
///
/// <para>
/// <see cref="StartAsync"/> NEVER hands an unverified delivery to the
/// caller-supplied handler — <see cref="Hmac.Verify"/> runs first, and the
/// handler call site is structurally unreachable until it returns
/// <c>true</c>. The handler is handed the very bytes
/// the HMAC covered (the delivery body, signature member included), never a re-serialization of them. The remaining outcomes follow the exact §8 decision matrix:
/// </para>
/// <list type="bullet">
/// <item><description>Every discard — <c>nack(requeue: false)</c>, the handler never invoked — is logged as ONE
/// warning-level security event carrying exactly <c>timestamp</c>, <c>exchange</c>, <c>routing_key</c>,
/// <c>tenant_id</c> (the consumer's OWN configured tenant, never one read from the body) and <c>reason</c>, the first
/// that applies in the order of &#167;8 rule 4: <c>malformed</c> (not one JSON object: the first byte is not <c>{</c>,
/// or it does not parse), <c>unsigned</c> (no <c>hmac_signature</c> member), <c>malformed</c> (a duplicate or folded
/// member, a signature that is not a trailing 64-hex member, or a layout that is not the configured
/// <see cref="AmqpEventType"/>'s — before the HMAC is computed), <c>signature</c>, <c>malformed</c> (the verified
/// bytes do not decode), <c>key_version</c>, <c>stale</c>, <c>replay</c>. The event never contains a signature, a
/// nonce, a key, the body, or any member read from it.</description></item>
/// <item><description>Handler returns normally → <c>BasicAckAsync</c>.</description></item>
/// <item><description>Handler throws <see cref="PoisonMessageException"/> (poison
/// message) → <c>BasicNackAsync(requeue: false)</c>.</description></item>
/// <item><description>Handler throws any other exception (transient/retryable)
/// → <c>BasicNackAsync(requeue: true)</c>.</description></item>
/// </list>
/// <para>
/// No body escapes the consumer (&#167;8 step 2, contract 1.69): whatever the bytes — empty, not UTF-8, a byte-order mark,
/// deeply nested, truncated, of another type — nothing is thrown out of the delivery loop and the next delivery is
/// handled.
/// </para>
/// </summary>
public sealed class AxiamAmqpConsumer : IAsyncDisposable
{
    /// <summary>Default QoS prefetch count.</summary>
    public const ushort DefaultPrefetchCount = 10;

    /// <summary>Default network-recovery interval applied to the connection factory.</summary>
    public static readonly TimeSpan DefaultNetworkRecoveryInterval = TimeSpan.FromSeconds(5);

    private IConnection? _connection;
    private IChannel? _channel;

    /// <summary>
    /// Connects to <paramref name="amqpUri"/>, opens a channel with automatic
    /// recovery enabled, and registers an <see cref="AsyncEventingBasicConsumer"/>
    /// on <paramref name="queue"/> that verifies every delivery's HMAC-SHA256
    /// signature (§8, via <see cref="Hmac.Verify"/>) BEFORE
    /// <paramref name="handler"/> is invoked, then applies the §8 ack/nack
    /// matrix documented on this class.
    /// </summary>
    /// <param name="amqpUri">The AMQP connection URI.</param>
    /// <param name="queue">The queue name to consume from.</param>
    /// <param name="eventType">The ONE signed type this consumer consumes (§8 step 2c, contract 1.69). A body with
    /// any other layout is refused as <c>malformed</c>, before the HMAC. To consume both types, run two consumers.</param>
    /// <param name="tenantId">The consumer's OWN tenant: the tenant whose subkey <paramref name="signingKey"/> is. It
    /// is the <c>tenant_id</c> of every discard event; nothing is read from a body for it.</param>
    /// <param name="signingKey">The per-tenant AMQP HMAC signing secret (§8.1
    /// — obtain from the AXIAM management API; never hardcode).</param>
    /// <param name="handler">Invoked ONLY after HMAC verification AND the NEW-4
    /// replay-protection gate (<see cref="ReplayGuard"/>) both succeed.
    /// Throw <see cref="PoisonMessageException"/> to drop a message without
    /// requeue; any other exception is treated as transient and requeues.</param>
    /// <param name="logger">Receives the §8.4 security event on HMAC
    /// verification (or NEW-4 replay-protection) failure; the event never
    /// contains the HMAC, nonce, or issued_at value. Defaults to a silent
    /// no-op logger.</param>
    /// <param name="replaySkew">The NEW-4 freshness window applied to each
    /// delivery's <c>issued_at</c> field (also sets the nonce dedup store's TTL,
    /// 2×<paramref name="replaySkew"/>). Defaults to
    /// <see cref="ReplayGuard.DefaultSkew"/> (±5 minutes) when <c>null</c> or
    /// non-positive.</param>
    /// <param name="cancellationToken">Cancellation token for connection/channel
    /// setup and for every ack/nack call issued by the registered consumer.</param>
    public async Task StartAsync(
        string amqpUri,
        string queue,
        AmqpEventType eventType,
        string tenantId,
        byte[] signingKey,
        Func<byte[], CancellationToken, Task> handler,
        ILogger? logger = null,
        TimeSpan? replaySkew = null,
        CancellationToken cancellationToken = default)
    {
        logger ??= NullLogger.Instance;
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(handler);

        // §8b rules 1 and 5: amqps:// or nothing, checked before a socket opens
        // and with no fallback path to take. A signed AuthzRequest still names
        // its subject, resource and action in cleartext — HMAC proves who wrote
        // the message, it does not keep the message off the wire.
        Reactor.ReactorConnections.RequireAmqps(amqpUri);

        var factory = new ConnectionFactory
        {
            Uri = new Uri(amqpUri),
            AutomaticRecoveryEnabled = true, // default true — kept explicit for clarity (D-11)
            TopologyRecoveryEnabled = true, // default true
            NetworkRecoveryInterval = DefaultNetworkRecoveryInterval,
            ConsumerDispatchConcurrency = 1, // default; sequential dispatch — safe default,
                                              // bump only if the handler is proven concurrency-safe
        };

        _connection = await factory.CreateConnectionAsync(cancellationToken).ConfigureAwait(false);
        _channel = await _connection.CreateChannelAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
        await _channel.BasicQosAsync(0, DefaultPrefetchCount, false, cancellationToken).ConfigureAwait(false);

        // One ReplayGuard per StartAsync call, shared across every delivery
        // dispatched by this consumer — nonce dedup is meaningless if a fresh
        // guard were created per delivery (NEW-4).
        var replayGuard = new ReplayGuard(replaySkew);

        var consumer = new AsyncEventingBasicConsumer(_channel);
        consumer.ReceivedAsync += CreateReceivedHandler(_channel, eventType, tenantId, queue, signingKey, handler, logger, replayGuard, cancellationToken);

        await _channel.BasicConsumeAsync(queue, autoAck: false, consumerTag: string.Empty, noLocal: false,
            exclusive: false, arguments: null, consumer, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Builds the §8 verify-before-handler / ack-nack-matrix delegate bound
    /// to <paramref name="channel"/>. Internal so <c>AmqpConsumerTests</c> can
    /// construct and invoke it directly against synthesized
    /// <see cref="BasicDeliverEventArgs"/> and a fake <see cref="IChannel"/>,
    /// proving every matrix branch without a live broker.
    /// </summary>
    /// <param name="eventType">The one signed type consumed (§8 step 2c).</param>
    /// <param name="tenantId">The consumer's own tenant, the <c>tenant_id</c> of every discard event.</param>
    /// <param name="queue">The queue consumed from: the routing key reported when the delivery carries none.</param>
    /// <param name="replayGuard">The NEW-4 replay-protection gate, evaluated
    /// immediately after <see cref="Hmac.Verify"/> succeeds and BEFORE
    /// <paramref name="handler"/> is invoked. Callers MUST share one instance
    /// across every delivery on a given consumer — a fresh instance per
    /// delivery makes nonce dedup a no-op.</param>
    internal static AsyncEventHandler<BasicDeliverEventArgs> CreateReceivedHandler(
        IChannel channel,
        AmqpEventType eventType,
        string tenantId,
        string queue,
        byte[] signingKey,
        Func<byte[], CancellationToken, Task> handler,
        ILogger logger,
        ReplayGuard replayGuard,
        CancellationToken cancellationToken = default,
        TimeProvider? clock = null)
    {
        clock ??= TimeProvider.System;
        return async (_, ea) =>
        {
            // No body escapes the consumer (§8 step 2, contract 1.69): nothing thrown while handling one delivery
            // leaves this delegate, so the next delivery is always handled. The exception is not logged: its text
            // could carry body content.
            try
            {
                await HandleDeliveryAsync(channel, eventType, tenantId, queue, signingKey, handler, logger, replayGuard, clock, ea, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Deliberately empty.
            }
        };
    }

    private static async Task HandleDeliveryAsync(
        IChannel channel,
        AmqpEventType eventType,
        string tenantId,
        string queue,
        byte[] signingKey,
        Func<byte[], CancellationToken, Task> handler,
        ILogger logger,
        ReplayGuard replayGuard,
        TimeProvider clock,
        BasicDeliverEventArgs ea,
        CancellationToken cancellationToken)
    {
        byte[] body = ea.Body.ToArray(); // MUST copy — library-owned memory is only valid
                                          // for the duration of this event (7.x migration note)

        // The discard (§8 step 2g, rule 4): ONE warning with exactly timestamp, exchange, routing_key, tenant_id and
        // reason, then nack without requeue. The handler is structurally unreachable after it. Nothing from the
        // body, no signature and no nonce is ever logged.
        async Task DiscardAsync(string reason)
        {
            try
            {
                logger.LogWarning(
                    "axiam_sdk_security: AMQP event discarded (timestamp={timestamp}, exchange={exchange}, routing_key={routing_key}, tenant_id={tenant_id}, reason={reason})",
                    clock.GetUtcNow().UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
                    ea.Exchange ?? string.Empty,
                    ea.RoutingKey ?? queue, // as the broker reported it: "" is a valid routing key
                    tenantId,
                    reason);
            }
            finally
            {
                await channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: false, cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        // (1) one JSON object: the first byte is `{` (a BOM, whitespace or any other prefix is refused, never
        // stripped) and the body parses to the end with nothing after it.
        if (!SignedJson.StartsWithObject(body) || !SignedJson.IsOneJsonObject(body))
        {
            await DiscardAsync(Reason.Malformed).ConfigureAwait(false);
            return;
        }

        // (2) no hmac_signature member at all.
        if (!SignedJson.HasSignatureMember(body))
        {
            await DiscardAsync(Reason.Unsigned).ConfigureAwait(false);
            return;
        }

        // (3) steps 2a-2c: unambiguous keys, a trailing 64-hex signature member, and the layout of the ONE
        // configured type. A body with another signed type's layout stops here, before the HMAC is computed
        // and before anything is decoded (D-9).
        if (SignedJson.HasAmbiguousKeys(body) ||
            !SignedJson.TryCutTrailingSignature(body, 64, out byte[]? canonical, out string? _) ||
            !SignedJson.MatchesLayout(canonical!, eventType))
        {
            await DiscardAsync(Reason.Malformed).ConfigureAwait(false);
            return;
        }

        // (4) the HMAC over the received bytes, constant-time.
        if (!Hmac.Verify(signingKey, body))
        {
            await DiscardAsync(Reason.Signature).ConfigureAwait(false);
            return; // handler is structurally unreachable for an unverified message
        }

        // (5) the verified canonical bytes decode into the configured type.
        if (!SignedJson.DecodesAs(canonical!, eventType) || !ReplayGuard.TryExtractMetadata(canonical!, out ReplayMetadata metadata))
        {
            await DiscardAsync(Reason.Malformed).ConfigureAwait(false);
            return;
        }

        // (6)-(8) the NEW-4 gates over the now-authenticated values, in order. The nonce is recorded only when
        // every gate passes, so a message refused at (1)-(7) leaves none behind.
        switch (replayGuard.Evaluate(metadata))
        {
            case ReplayVerdict.Accepted:
                break;
            case ReplayVerdict.KeyVersion:
                await DiscardAsync(Reason.KeyVersion).ConfigureAwait(false);
                return;
            case ReplayVerdict.Stale:
                await DiscardAsync(Reason.Stale).ConfigureAwait(false);
                return;
            default:
                await DiscardAsync(Reason.Replay).ConfigureAwait(false);
                return;
        }

        try
        {
            await handler(body, cancellationToken).ConfigureAwait(false); // handler NEVER sees an unverified message
            await channel.BasicAckAsync(ea.DeliveryTag, multiple: false, cancellationToken).ConfigureAwait(false);
        }
        catch (PoisonMessageException)
        {
            await channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: false, cancellationToken)
                .ConfigureAwait(false); // poison message, no requeue
        }
        catch (Exception)
        {
            await channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: true, cancellationToken)
                .ConfigureAwait(false); // transient/retryable, requeue
        }
    }

    /// <summary>The closed vocabulary of the discard event's <c>reason</c> (CONTRACT.md &#167;8 rule 4).</summary>
    private static class Reason
    {
        internal const string Malformed = "malformed";
        internal const string Unsigned = "unsigned";
        internal const string Signature = "signature";
        internal const string KeyVersion = "key_version";
        internal const string Stale = "stale";
        internal const string Replay = "replay";
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_channel is not null)
        {
            await _channel.CloseAsync().ConfigureAwait(false);
        }

        if (_connection is not null)
        {
            await _connection.CloseAsync().ConfigureAwait(false);
        }
    }
}
