namespace Axiam.Sdk.Core;

using System;

/// <summary>Why a request finished (CONTRACT.md &#167;19).</summary>
public enum TelemetryOutcome
{
    /// <summary>The call returned a usable response.</summary>
    Success,

    /// <summary>The call failed, at any layer.</summary>
    Failure,
}

/// <summary>Whether this caller performed a &#167;9 refresh or awaited another's.</summary>
public enum RefreshRole
{
    /// <summary>This caller performed the refresh.</summary>
    Leader,

    /// <summary>This caller awaited another task's refresh.</summary>
    Follower,
}

/// <summary>
/// A telemetry event (CONTRACT.md &#167;19).
/// </summary>
/// <remarks>
/// <para>
/// This is a closed hierarchy: the constructor is <c>private protected</c>, so no
/// type outside this assembly can derive from it. That is what makes &#167;19.2
/// rule 3's "no event payload may carry a secret" checkable rather than
/// aspirational — every record below has a fixed property list and no free-form
/// dictionary, so there is nowhere to put a token in a payload bound for a
/// metrics backend.
/// </para>
/// <para>
/// Hooks are invoked on the calling task, so a sink must not block: &#167;19.2
/// rule 4 makes buffering the caller's job so they can pick the policy. Every
/// mature metrics library already buffers.
/// </para>
/// </remarks>
public abstract record TelemetryEvent
{
    private protected TelemetryEvent()
    {
    }
}

/// <summary>Emitted before an outbound call leaves the SDK (&#167;19).</summary>
/// <param name="Operation">Canonical operation name, e.g. <c>CheckAccess</c>.</param>
/// <param name="Method">HTTP method.</param>
/// <param name="PathTemplate">
/// The route constant — <c>/api/v1/authz/check</c>, never a URL with ids
/// substituted in. A metric label carrying a UUID is a cardinality bomb.
/// </param>
/// <param name="Attempt">1 for the first try, incrementing per &#167;16 retry.</param>
public sealed record RequestStartEvent(
    string Operation,
    string Method,
    string PathTemplate,
    int Attempt) : TelemetryEvent;

/// <summary>Emitted after a call completes, success or failure (&#167;19).</summary>
/// <param name="Operation">Canonical operation name.</param>
/// <param name="Method">HTTP method.</param>
/// <param name="PathTemplate">The route constant; see <see cref="RequestStartEvent"/>.</param>
/// <param name="Attempt">The attempt this event closes.</param>
/// <param name="StatusCode">HTTP status, or <c>null</c> when no response arrived.</param>
/// <param name="Duration">Wall-clock time this attempt took.</param>
/// <param name="Outcome">Success or failure.</param>
public sealed record RequestEndEvent(
    string Operation,
    string Method,
    string PathTemplate,
    int Attempt,
    int? StatusCode,
    TimeSpan Duration,
    TelemetryOutcome Outcome) : TelemetryEvent;

/// <summary>
/// Emitted before each &#167;16 retry wait.
/// </summary>
/// <remarks>
/// &#167;16.5 requires this: a retried-then-succeeded operation is otherwise
/// invisible — the caller sees a slow success and no signal that the server is
/// failing. That silence is the standing objection to automatic retry.
/// </remarks>
/// <param name="Operation">Canonical operation name.</param>
/// <param name="Attempt">The attempt that just failed.</param>
/// <param name="Delay">The wait about to be taken, after jitter and any <c>Retry-After</c>.</param>
/// <param name="Reason">A redacted failure description; never carries a token.</param>
public sealed record RetryEvent(
    string Operation,
    int Attempt,
    TimeSpan Delay,
    string Reason) : TelemetryEvent;

/// <summary>Emitted around a &#167;9 single-flight refresh (&#167;19).</summary>
/// <param name="Role">Whether this caller led or followed.</param>
/// <param name="Duration">How long the refresh, or the wait for one, took.</param>
public sealed record RefreshEvent(
    RefreshRole Role,
    TimeSpan Duration) : TelemetryEvent;

/// <summary>
/// Emitted at construction, once per caller-supplied setting the SDK clamped
/// (CONTRACT.md &#167;19.1, &#167;19.2 rule 6).
/// </summary>
/// <remarks>
/// <para>
/// Two places in the contract require clamping rather than rejecting: &#167;16.1's
/// attempt cap, base delay and delay cap, and &#167;17.1 rule 2's memo TTL. Both
/// clamps are right — rejecting would break a caller whose configuration was merely
/// optimistic, and honoring would let one client become the herd &#167;16 exists to
/// prevent. Doing it <em>silently</em> is the part that is wrong.
/// </para>
/// <para>
/// An operator who set a 60-second memo TTL believes they have one. They have five
/// seconds, and their staleness reasoning is off by a factor of twelve with nothing
/// anywhere to say so. This event is what makes the clamp discoverable at the only
/// moment it can be acted on.
/// </para>
/// <para>
/// It is <strong>not</strong> emitted for a value already within its limit: an event
/// that fires when nothing happened trains its reader to ignore it.
/// </para>
/// </remarks>
/// <param name="Setting">The setting's name, e.g. <c>MaxRetryAttempts</c>.</param>
/// <param name="Requested">The value the caller asked for, rendered.</param>
/// <param name="Effective">The value actually in force, rendered.</param>
/// <param name="ContractReference">The §-reference for the limit, e.g. <c>§16.1</c>.</param>
public sealed record ConfigClampedEvent(
    string Setting,
    string Requested,
    string Effective,
    string ContractReference) : TelemetryEvent;
