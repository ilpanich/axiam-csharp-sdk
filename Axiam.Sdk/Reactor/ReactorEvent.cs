using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text.Json.Nodes;

namespace Axiam.Sdk.Reactor;

/// <summary>
/// One hook firing, delivered to a reactor (<c>sdks/CONTRACT.md</c> &#167;22.3).
///
/// <para>
/// An instance only ever reaches a handler <em>after</em> <see cref="ReactorServer"/> has
/// rejected <c>key_version &lt; 2</c>, verified the MAC, checked freshness and checked the
/// nonce, in that order. A runtime that hands an unverified payload to user code has
/// already lost, so this type has no public constructor.
/// </para>
/// <para>
/// The <see cref="Payload"/> never carries a credential, a token or a signing key: a
/// reactor is told what is being decided, not handed the means to act on it elsewhere. It
/// is not sensitive in the &#167;7 sense and must remain readable — a handler that cannot
/// inspect the event cannot decide anything — but it is tenant business data, so this SDK
/// never logs it, and neither should you at <c>Information</c> level.
/// </para>
/// </summary>
public sealed class ReactorEvent
{
    /// <summary>
    /// Payload key under which the server inserts the accumulated patch from earlier
    /// reactors in the chain (&#167;22.3).
    /// </summary>
    public const string ReactorPatchKey = "_reactor_patch";

    internal ReactorEvent(
        Guid tenantId,
        string eventName,
        Guid correlationId,
        JsonObject payload,
        int timeoutMs,
        int keyVersion,
        Guid nonce,
        DateTimeOffset issuedAt,
        DateTimeOffset deadline)
    {
        TenantId = tenantId;
        Event = eventName;
        CorrelationId = correlationId;
        Payload = payload;
        TimeoutMs = timeoutMs;
        KeyVersion = keyVersion;
        Nonce = nonce;
        IssuedAt = issuedAt;
        Deadline = deadline;
    }

    /// <summary>The tenant this event belongs to; always the tenant this runtime serves.</summary>
    public Guid TenantId { get; }

    /// <summary>
    /// The registry event name, e.g. <c>token.pre_issue</c>. Also the second half of the
    /// routing key.
    /// </summary>
    public string Event { get; }

    /// <summary>
    /// The single-use handle for this dispatch, copied into the reply body by the runtime.
    /// Copying it only into the AMQP property produces a reply the server discards.
    /// </summary>
    public Guid CorrelationId { get; }

    /// <summary>
    /// The event-specific body. Never carries a credential, a token or a signing key.
    /// </summary>
    public JsonObject Payload { get; }

    /// <summary>
    /// How long the server will actually wait for <em>this</em> dispatch, in milliseconds.
    /// It is inside the signed body, so it cannot be widened in transit.
    /// </summary>
    public int TimeoutMs { get; }

    /// <summary>
    /// The &#167;8 envelope version this event was signed under; always at least 2, because
    /// a lower one is refused before anything else about the message is considered.
    /// </summary>
    public int KeyVersion { get; }

    /// <summary>
    /// The per-message nonce, inside the signed bytes. Not a secret, and safe to log for
    /// correlation.
    /// </summary>
    public Guid Nonce { get; }

    /// <summary>
    /// When the server signed this event, already checked to lie within the freshness
    /// window.
    /// </summary>
    public DateTimeOffset IssuedAt { get; }

    /// <summary>
    /// When this dispatch's window closes.
    ///
    /// <para>
    /// Measured from the moment the delivery arrived plus <see cref="TimeoutMs"/>,
    /// <em>not</em> from <see cref="IssuedAt"/>: broker latency and clock skew both sit
    /// between the two, and a deadline derived from a remote clock would read as
    /// already-expired on a reactor whose clock runs slightly fast.
    /// </para>
    /// </summary>
    public DateTimeOffset Deadline { get; }

    /// <summary>The registry spec for <see cref="Event"/>, or <c>null</c> when unknown.</summary>
    /// <returns>
    /// The spec. <c>null</c> cannot happen for a server-dispatched event, since an
    /// unregistered event dispatches to nothing.
    /// </returns>
    public ReactorEventSpec? Spec() => ReactorEvents.Spec(Event);

    /// <summary>How much of the window is left.</summary>
    /// <param name="now">The current instant.</param>
    /// <returns>
    /// The remaining time, or <see cref="TimeSpan.Zero"/> when the window has already
    /// closed. A handler doing expensive work SHOULD consult this and shed load rather than
    /// answer into a closed window.
    /// </returns>
    public TimeSpan Remaining(DateTimeOffset now)
    {
        TimeSpan left = Deadline - now;
        return left < TimeSpan.Zero ? TimeSpan.Zero : left;
    }

    /// <summary>
    /// The accumulated patch from earlier reactors in the chain (&#167;22.3).
    ///
    /// <para>
    /// When an earlier reactor returned a mutation, the server inserts the merged patch
    /// into the payload under <see cref="ReactorPatchKey"/> before dispatching here, so this
    /// reactor decides against the state that will actually be committed.
    /// </para>
    /// <para>
    /// <b>Read-only context.</b> Echoing these keys back inside your own patch is not how a
    /// field is preserved — the server merges, with later priority winning a contested key.
    /// </para>
    /// </summary>
    /// <returns>
    /// The prior patch, or an empty map when this is the first reactor in the chain (or the
    /// only one). Never <c>null</c>.
    /// </returns>
    public IReadOnlyDictionary<string, string> PriorPatch()
    {
        var merged = new Dictionary<string, string>(StringComparer.Ordinal);
        if (Payload[ReactorPatchKey] is JsonObject prior)
        {
            foreach (KeyValuePair<string, JsonNode?> entry in prior)
            {
                if (entry.Value is JsonValue value && value.TryGetValue(out string? text) && text is not null)
                {
                    merged[entry.Key] = text;
                }
            }
        }

        return new ReadOnlyDictionary<string, string>(merged);
    }

    /// <summary>
    /// A short, secret-free description for logs.
    ///
    /// <para>
    /// Deliberately omits <see cref="Payload"/>: the nonce and correlation id are not
    /// secrets and may be logged for correlation, but the payload is tenant business data.
    /// </para>
    /// </summary>
    /// <returns>A one-line summary carrying no payload and no key material.</returns>
    public override string ToString() => string.Create(
        CultureInfo.InvariantCulture,
        $"ReactorEvent[event={Event}, tenant={TenantId}, correlation={CorrelationId}, nonce={Nonce}, timeoutMs={TimeoutMs}]");
}
