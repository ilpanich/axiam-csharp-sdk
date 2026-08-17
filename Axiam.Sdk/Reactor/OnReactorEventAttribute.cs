namespace Axiam.Sdk.Reactor;

/// <summary>
/// Declares that a method handles one reactor hook event (CONTRACT.md &#167;22.14,
/// canonical <c>reactor_handlers</c>).
/// </summary>
/// <remarks>
/// <para>
/// Applying this attribute does not itself dispatch anything — it is metadata read by
/// <see cref="ReactorHandlers.Of(object[])"/>, which builds the single
/// <see cref="ReactorHandler"/> that <see cref="ReactorServer"/> already takes. That is
/// the same shape <c>[AxiamAccess]</c> uses for &#167;11: the attribute carries the
/// declaration, a collector turns it into enforcement.
/// </para>
/// <para>
/// The event name is validated when <see cref="ReactorHandlers"/> reads the attribute,
/// so a typo fails at wiring time rather than becoming an event that silently never
/// fires (&#167;22.14 rule 2). A name outside the &#167;22.5 registry is refused —
/// which is also how &#167;22.7's hot-path operations are refused, since they are in no
/// registry row.
/// </para>
/// <example>
/// <code>
/// public sealed class ClaimsReactor
/// {
///     [OnReactorEvent(ReactorEvents.TokenPreIssue)]
///     public Task&lt;ReactorDecision&gt; EnrichAsync(ReactorEvent e, CancellationToken ct) =&gt;
///         Task.FromResult(ReactorDecision.Mutated(new Dictionary&lt;string, string&gt;
///         {
///             ["ext.department"] = "engineering",
///         }));
/// }
///
/// ReactorHandler handler = ReactorHandlers.Of(new ClaimsReactor()).Handler();
/// </code>
/// </example>
/// </remarks>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class OnReactorEventAttribute : Attribute
{
    /// <summary>
    /// Creates the attribute for one &#167;22.5 registry event.
    /// </summary>
    /// <param name="event">
    /// A &#167;22.5 registry event name, e.g. <see cref="ReactorEvents.TokenPreIssue"/>.
    /// </param>
    public OnReactorEventAttribute(string @event)
    {
        Event = @event;
    }

    /// <summary>The &#167;22.5 registry event this method handles.</summary>
    public string Event { get; }
}
