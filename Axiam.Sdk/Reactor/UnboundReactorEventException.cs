namespace Axiam.Sdk.Reactor;

/// <summary>
/// Thrown by a <see cref="ReactorHandlers"/>-composed handler for an event no handler
/// was bound for (CONTRACT.md &#167;22.14 rule 4).
/// </summary>
/// <remarks>
/// <para>
/// Throwing is the point. <see cref="ReactorServer"/> publishes <em>no reply</em> for a
/// handler that threw, so the registration's <c>failure_policy</c> resolves this exactly
/// as &#167;22.8 resolves a timeout. The alternative — answering <c>allow</c> — would
/// answer on behalf of code that never ran, which is how an operator's
/// <c>fail_closed</c> setting gets defeated from inside the library (&#167;22.10 rule 2).
/// </para>
/// <para>
/// An event a reactor did not register for should never arrive at all. When one does,
/// the registration and the code have drifted, and letting the operator's policy resolve
/// it is the answer that cannot silently weaken the operator's configuration.
/// </para>
/// </remarks>
public sealed class UnboundReactorEventException : InvalidOperationException
{
    /// <summary>
    /// Creates the exception naming the unbound event.
    /// </summary>
    /// <param name="event">The wire event name no handler was bound for.</param>
    public UnboundReactorEventException(string @event)
        : base($"no reactor handler bound for {@event}")
    {
        Event = @event;
    }

    /// <summary>Creates the exception with a default message.</summary>
    public UnboundReactorEventException()
        : base("no reactor handler bound for this event")
    {
        Event = string.Empty;
    }

    /// <summary>Creates the exception with a custom message.</summary>
    /// <param name="message">The exception message.</param>
    /// <param name="innerException">The cause, if any.</param>
    public UnboundReactorEventException(string message, Exception innerException)
        : base(message, innerException)
    {
        Event = string.Empty;
    }

    /// <summary>The event name no handler was bound for; empty when unknown.</summary>
    public string Event { get; }
}
