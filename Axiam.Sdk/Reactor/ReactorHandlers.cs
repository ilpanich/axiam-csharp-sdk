using System.Collections.ObjectModel;
using System.Reflection;

namespace Axiam.Sdk.Reactor;

/// <summary>
/// Declarative reactor handler binding — CONTRACT.md &#167;22.14.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ReactorServer"/> takes <strong>one</strong> <see cref="ReactorHandler"/>
/// from an event to one answer, which is the right shape for the wire and the wrong
/// shape for the code. A reactor registered for three events opens with a
/// <c>switch (e.Event)</c>, and that switch carries two defects.
/// </para>
/// <para>
/// The first is cheap: a misspelled event name is a valid string, matches no case, and
/// is discovered as an event that never fires. The second is not. It is the
/// <c>default</c> arm, which is almost always written <c>ReactorDecision.Allowed()</c>.
/// That answers on behalf of code that never ran — the defect &#167;22.10 rule 2 forbids
/// the <em>runtime</em> from committing, relocated into user code where the rule does
/// not reach it. An operator who set <c>fail_closed</c> on a registration has it
/// defeated by a <c>default</c> arm in a file they never read.
/// </para>
/// <para>
/// This class is the declarative form, in the spirit of &#167;11's
/// <c>[AxiamAccess]</c>: attribute the methods, collect them, hand the result to
/// <see cref="ReactorServer"/>. It is <strong>pure sugar</strong> (&#167;22.14 rule 1):
/// what <see cref="Handler"/> returns is exactly the <see cref="ReactorHandler"/>
/// <see cref="ReactorServer"/> already accepts. It opens nothing, verifies nothing,
/// signs nothing, and does not filter a patch (&#167;22.10 rule 3).
/// </para>
/// <para>
/// Instances are built once at startup and are not thread-safe to mutate; the delegate
/// <see cref="Handler"/> returns snapshots its bindings and is safe for concurrent
/// dispatch.
/// </para>
/// </remarks>
public sealed class ReactorHandlers
{
    private readonly Dictionary<string, ReactorHandler> _handlers = new(StringComparer.Ordinal);
    private readonly List<string> _order = new();

    /// <summary>
    /// Creates an empty binding table. Use <see cref="Bind"/> or <see cref="Of"/>.
    /// </summary>
    public ReactorHandlers()
    {
    }

    /// <summary>
    /// Collects every <see cref="OnReactorEventAttribute"/>-decorated public method on
    /// <paramref name="sources"/>.
    /// </summary>
    /// <param name="sources">Objects whose public methods carry the attribute.</param>
    /// <returns>The collected bindings.</returns>
    /// <remarks>
    /// Methods are invoked against the instance they were found on, so a class-based
    /// reactor keeps its state and its constructor-injected collaborators. Reflection
    /// does not define an order for <c>GetMethods()</c>, so methods are bound in
    /// event-name order and <see cref="Events"/> is reproducible between runs.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="sources"/> or an element
    /// is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">An event name is outside the &#167;22.5
    /// registry (which is also how &#167;22.7's hot-path operations are refused), an
    /// event is already bound, or a decorated method's signature is not
    /// <c>Task&lt;ReactorDecision&gt;(ReactorEvent, CancellationToken)</c>.</exception>
    public static ReactorHandlers Of(params object[] sources)
    {
        ArgumentNullException.ThrowIfNull(sources);

        ReactorHandlers collected = new();
        foreach (object source in sources)
        {
            ArgumentNullException.ThrowIfNull(source);

            List<MethodInfo> decorated = source.GetType()
                .GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .Where(m => m.GetCustomAttribute<OnReactorEventAttribute>() is not null)
                .ToList();
            decorated.Sort((a, b) => string.CompareOrdinal(
                a.GetCustomAttribute<OnReactorEventAttribute>()!.Event,
                b.GetCustomAttribute<OnReactorEventAttribute>()!.Event));

            foreach (MethodInfo method in decorated)
            {
                collected.Bind(
                    method.GetCustomAttribute<OnReactorEventAttribute>()!.Event,
                    Adapt(source, method));
            }
        }

        return collected;
    }

    /// <summary>
    /// Binds <paramref name="handler"/> to <paramref name="event"/> without an attribute.
    /// </summary>
    /// <param name="event">A &#167;22.5 registry event name.</param>
    /// <param name="handler">The decision function for that event.</param>
    /// <returns>This instance, for chaining.</returns>
    /// <remarks>
    /// The lambda-shaped half of the same thing. Governed by every &#167;22.14 rule
    /// identically.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="handler"/> is
    /// <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="event"/> is outside the
    /// &#167;22.5 registry — which is how &#167;22.7's hot-path operations are refused,
    /// since they are in no registry row — or is already bound. A second binding is a
    /// mistake, never a silent overwrite: which of the two runs is not visible from
    /// either one.</exception>
    public ReactorHandlers Bind(string @event, ReactorHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        if (ReactorEvents.Spec(@event) is null)
        {
            // The message names what IS hookable. It deliberately does not name what is
            // excluded: §22.13 requires the three hot-path operations to be absent from
            // every event constant this SDK exposes, and a list of them here — even only
            // to say they are refused — is exactly the constant that would break it
            // (§22.14 rule 2).
            string hookable = string.Join(", ", ReactorEvents.Registry.Select(s => s.Name));
            throw new ArgumentException(
                $"{@event} is not a hookable reactor event; the registry is [{hookable}]",
                nameof(@event));
        }

        if (_handlers.ContainsKey(@event))
        {
            throw new ArgumentException(
                $"reactor event {@event} is already bound", nameof(@event));
        }

        _handlers[@event] = handler;
        _order.Add(@event);
        return this;
    }

    /// <summary>
    /// The bound event names, in binding order.
    /// </summary>
    /// <returns>A read-only list of wire event names.</returns>
    /// <remarks>
    /// Pass them to <see cref="ReactorEvents.DefaultFailurePolicyFor"/> to see what an
    /// unreachable reactor costs — the strictest default among them (&#167;22.8) —
    /// derived from the code that handles the events rather than from a restatement of
    /// the registration.
    /// </remarks>
    public IReadOnlyList<string> Events() => new ReadOnlyCollection<string>(new List<string>(_order));

    /// <summary>
    /// Composes the bindings into the <see cref="ReactorHandler"/>
    /// <see cref="ReactorServer"/> accepts.
    /// </summary>
    /// <returns>The composed handler.</returns>
    /// <exception cref="InvalidOperationException">Nothing is bound. A reactor that
    /// handles nothing would consume its queue and abstain from every event, which looks
    /// exactly like an outage.</exception>
    public ReactorHandler Handler()
    {
        if (_handlers.Count == 0)
        {
            throw new InvalidOperationException(
                "ReactorHandlers has no bindings; bind at least one event");
        }

        Dictionary<string, ReactorHandler> bound = new(_handlers, StringComparer.Ordinal);
        return (reactorEvent, cancellationToken) =>
        {
            if (!bound.TryGetValue(reactorEvent.Event, out ReactorHandler? handler))
            {
                // §22.14 rule 4. NOT Allowed(): throwing publishes NO REPLY, so the
                // registration's failure_policy resolves this exactly as it resolves a
                // timeout (§22.8). This binder does not know what the registration was
                // for; the operator's policy does.
                throw new UnboundReactorEventException(reactorEvent.Event);
            }

            // Invoked without a try/catch on purpose (§22.14 rule 5): a handler's own
            // exception — thrown synchronously or carried on the returned Task — must
            // reach ReactorServer unchanged so it publishes nothing. Catching it here
            // would satisfy the letter of §22.10 rule 2 while defeating it.
            return handler(reactorEvent, cancellationToken);
        };
    }

    /// <summary>Wraps one decorated method as a <see cref="ReactorHandler"/>.</summary>
    private static ReactorHandler Adapt(object source, MethodInfo method)
    {
        ParameterInfo[] parameters = method.GetParameters();
        if (method.ReturnType != typeof(Task<ReactorDecision>)
            || parameters.Length != 2
            || parameters[0].ParameterType != typeof(ReactorEvent)
            || parameters[1].ParameterType != typeof(CancellationToken))
        {
            throw new ArgumentException(
                $"[OnReactorEvent] method {method.DeclaringType?.FullName}.{method.Name} must have "
                + "the signature Task<ReactorDecision>(ReactorEvent, CancellationToken)",
                nameof(method));
        }

        return (ReactorHandler)Delegate.CreateDelegate(typeof(ReactorHandler), source, method);
    }
}
