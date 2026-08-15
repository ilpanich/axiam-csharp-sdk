using System;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Core;
using Microsoft.Extensions.Logging;
using RabbitMQ.Client;

namespace Axiam.Sdk.Reactor;

/// <summary>
/// A reactor's decision function: one event in, one of three answers out
/// (<c>sdks/CONTRACT.md</c> &#167;22.10).
///
/// <para>
/// Invoked only after the runtime has verified the event under &#167;8 v2, so an
/// implementation never sees an unauthenticated payload.
/// </para>
/// <para>
/// <b>Throwing produces no reply.</b> The runtime will not synthesize an <c>allow</c> on
/// your behalf — that would override the operator's <c>fail_closed</c> setting from inside
/// the library. A handler that throws is a reactor that did not answer, and the
/// registration's <c>failure_policy</c> decides what that costs.
/// </para>
/// <para>
/// <b>Answer inside the window.</b> <see cref="ReactorEvent.TimeoutMs"/> is how long the
/// server will actually wait. A late reply is discarded and the CPU spent producing it was
/// spent for nothing, so a handler doing expensive work should consult
/// <see cref="ReactorEvent.Remaining"/> and shed load rather than push on.
/// </para>
/// </summary>
/// <param name="reactorEvent">The verified event.</param>
/// <param name="cancellationToken">Cancelled when the runtime is shutting down.</param>
/// <returns>The decision to sign and publish; never <c>null</c>.</returns>
public delegate Task<ReactorDecision> ReactorHandler(ReactorEvent reactorEvent, CancellationToken cancellationToken);

/// <summary>
/// A fire-and-forget observer of reactor events (<c>mode: "listen"</c>,
/// <c>sdks/CONTRACT.md</c> &#167;22.5).
///
/// <para>
/// The server never waits for a listener and never reads a reply, so a listener cannot
/// affect any outcome. That is why this returns a plain <see cref="Task"/> rather than a
/// <see cref="ReactorDecision"/>: an SDK listener handler MUST NOT publish a reply, and a
/// type that cannot express one is a stronger guarantee than a paragraph saying so.
/// </para>
/// <para>
/// <b>Write it idempotently.</b> A redelivery after a broker hiccup is normal. A listener
/// that double-counts is a listener that was assuming exactly-once delivery it was never
/// promised.
/// </para>
/// </summary>
/// <param name="reactorEvent">The verified event.</param>
/// <param name="cancellationToken">Cancelled when the runtime is shutting down.</param>
/// <returns>A task that completes when the observation is done.</returns>
public delegate Task ReactorObserver(ReactorEvent reactorEvent, CancellationToken cancellationToken);

/// <summary>
/// Configuration for <see cref="ReactorServer.ReactorServeAsync"/>.
///
/// <para>
/// Exactly one of <see cref="Handler"/> (intercept) or <see cref="Listener"/> (observe)
/// must be supplied, and exactly one of <see cref="Queue"/> or <see cref="ReactorId"/> must
/// name the queue to consume.
/// </para>
/// <para>
/// <b>The queue is the server's, not yours.</b> Whichever you use, the runtime only ever
/// <em>consumes</em> it. It declares no exchange, no queue and no binding, and it cannot
/// name a queue belonging to another reactor: <see cref="ReactorId"/> derives
/// <c>axiam.reactor.q.&lt;tenant&gt;.&lt;id&gt;</c> from the tenant and reactor id this
/// runtime is configured as, and nothing else.
/// </para>
/// </summary>
public sealed class ReactorServeOptions
{
    /// <summary>
    /// An open AMQP channel. Its connection MUST have been opened over <c>amqps://</c> with
    /// a trusted CA (&#167;8b) — a reactor reply is an instruction to change a token, and
    /// HMAC gives authenticity, not confidentiality. The caller owns the channel's
    /// lifecycle.
    /// </summary>
    public required IChannel Channel { get; init; }

    /// <summary>
    /// The tenant this reactor is registered in. An event naming any other tenant is
    /// discarded.
    /// </summary>
    public required Guid TenantId { get; init; }

    /// <summary>
    /// The tenant's HKDF-derived AMQP subkey — the same key the server signed the event
    /// with. Wrapped in <see cref="Sensitive{T}"/> because it is a credential
    /// (&#167;22.12): it is never logged at any level and never appears in a reconnect
    /// diagnostic. Derive it with <see cref="ReactorProtocol.DeriveTenantKey"/> or fetch it
    /// from the management API.
    /// </summary>
    public required Sensitive<byte[]> SigningKey { get; init; }

    /// <summary>The intercept decision function, or <c>null</c> for a listener.</summary>
    public ReactorHandler? Handler { get; init; }

    /// <summary>The observe callback, or <c>null</c> for an interceptor.</summary>
    public ReactorObserver? Listener { get; init; }

    /// <summary>
    /// An explicitly named server-declared queue — use this when the registration's queue
    /// name was handed to you rather than derived. Mutually exclusive with
    /// <see cref="ReactorId"/>.
    /// </summary>
    public string? Queue { get; init; }

    /// <summary>
    /// This reactor's own registration id. The runtime will not name a queue for any other
    /// reactor: a reactor that can pick its own queue is a reactor that can read another
    /// tenant's issuance events. Mutually exclusive with <see cref="Queue"/>.
    /// </summary>
    public Guid? ReactorId { get; init; }

    /// <summary>Where rejection diagnostics go. Defaults to a silent no-op logger.</summary>
    public ILogger? Logger { get; init; }

    /// <summary>
    /// The &#167;8 v2 acceptance window applied to <c>issued_at</c> in both directions.
    /// Defaults to <see cref="ReactorProtocol.DefaultFreshnessSkew"/> (300 s) when
    /// <c>null</c> or non-positive.
    /// </summary>
    public TimeSpan? FreshnessSkew { get; init; }

    /// <summary>
    /// How long <see cref="ReactorServer.DisposeAsync"/> waits for in-flight events to drain
    /// (&#167;18). Defaults to 10 s when <c>null</c> or non-positive.
    /// </summary>
    public TimeSpan? ShutdownGrace { get; init; }

    /// <summary>The channel QoS prefetch applied before consuming. Defaults to 16.</summary>
    public ushort Prefetch { get; init; } = 16;

    /// <summary>
    /// The clock used for freshness, deadlines and reply timestamps. Defaults to
    /// <see cref="DateTimeOffset.UtcNow"/>; overridable so tests need no wall clock.
    /// </summary>
    public Func<DateTimeOffset>? Clock { get; init; }

    /// <summary>
    /// The &#167;19 telemetry sink. Receives one <c>RequestStart</c>/<c>RequestEnd</c> pair
    /// per dispatched event. A hook that throws cannot fail the dispatch that fired it.
    /// </summary>
    public TelemetryHook? TelemetryHook { get; init; }

    /// <summary>The server-declared queue this runtime will consume.</summary>
    /// <exception cref="InvalidOperationException">
    /// When neither or both of <see cref="Queue"/> and <see cref="ReactorId"/> were given.
    /// </exception>
    public string ResolvedQueue => Validate();

    private string Validate()
    {
        if ((Handler is null) == (Listener is null))
        {
            throw new InvalidOperationException(
                "supply exactly one of Handler (mode: intercept) or Listener (mode: listen)");
        }

        if ((Queue is null) == (ReactorId is null))
        {
            throw new InvalidOperationException("supply exactly one of Queue or ReactorId");
        }

        return Queue ?? ReactorProtocol.QueueName(TenantId, ReactorId!.Value);
    }
}
