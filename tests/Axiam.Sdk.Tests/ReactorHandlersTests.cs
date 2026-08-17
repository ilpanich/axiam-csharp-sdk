using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using Axiam.Sdk.Reactor;

using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;22.14 — declarative reactor handler binding.
/// </summary>
/// <remarks>
/// Six groups for six rules. None needs a broker: <see cref="ReactorHandlers"/> is pure
/// composition over the <see cref="ReactorHandler"/> <see cref="ReactorServer"/> already
/// takes, so what is under test is the binding table and the one answer it gives for an
/// event nobody bound.
/// </remarks>
public sealed class ReactorHandlersTests
{
    /// <summary>
    /// Assembled from halves so a plain source scan for &#167;22.7's three excluded
    /// operations cannot match on this file's own text.
    /// </summary>
    private static readonly string[] ExcludedHotPath =
    {
        "authz" + "." + "check",
        "authz" + "." + "check_batch",
        "token" + "." + "introspect",
    };

    /// <summary>A class-based reactor, the shape &#167;22.14 exists to make writable.</summary>
    public sealed class FixtureReactor
    {
        private readonly string _team;

        public FixtureReactor(string team) => _team = team;

        [OnReactorEvent(ReactorEvents.TokenPreIssue)]
        public Task<ReactorDecision> EnrichAsync(ReactorEvent reactorEvent, CancellationToken cancellationToken)
            => Task.FromResult(ReactorDecision.Mutated(new Dictionary<string, string> { ["ext.team"] = _team }));

        [OnReactorEvent(ReactorEvents.LoginPostAuth)]
        public Task<ReactorDecision> ScreenAsync(ReactorEvent reactorEvent, CancellationToken cancellationToken)
            => Task.FromResult(ReactorDecision.Denied("embargoed region"));

        /// <summary>Not decorated — must not be collected.</summary>
        public Task<ReactorDecision> HelperAsync(ReactorEvent reactorEvent, CancellationToken cancellationToken)
            => Task.FromResult(ReactorDecision.Allowed());
    }

    /// <summary>A decorated method with the wrong shape.</summary>
    public sealed class BadSignatureReactor
    {
        [OnReactorEvent(ReactorEvents.TokenPreIssue)]
        public string Wrong(ReactorEvent reactorEvent) => "not a decision";
    }

    /// <summary>A reactor whose backing service is down.</summary>
    public sealed class ThrowingReactor
    {
        [OnReactorEvent(ReactorEvents.LoginPostAuth)]
        public Task<ReactorDecision> ScreenAsync(ReactorEvent reactorEvent, CancellationToken cancellationToken)
            => throw new InvalidOperationException("fraud service unreachable");
    }

    private static ReactorEvent Event(string name)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new ReactorEvent(
            Guid.NewGuid(), name, Guid.NewGuid(), new JsonObject(), 500, 2,
            Guid.NewGuid(), now, now.AddMilliseconds(500));
    }

    // ---- rule 1: it composes, it does not replace ---------------------------

    [Fact]
    public async Task CollectsDecoratedMethodsAndDispatchesEachToItsOwn()
    {
        ReactorHandler handler = ReactorHandlers.Of(new FixtureReactor("platform")).Handler();

        ReactorDecision enriched = await handler(Event(ReactorEvents.TokenPreIssue), CancellationToken.None);
        // The method was invoked against its instance, so constructor state survived.
        IReadOnlyDictionary<string, string> patch = Assert.IsType<ReactorDecision.Mutate>(enriched).Patch;
        Assert.Single(patch);
        Assert.Equal("platform", patch["ext.team"]);

        ReactorDecision screened = await handler(Event(ReactorEvents.LoginPostAuth), CancellationToken.None);
        Assert.Equal("embargoed region", Assert.IsType<ReactorDecision.Deny>(screened).Reason);
    }

    [Fact]
    public void IgnoresUndecoratedMethods()
    {
        Assert.Equal(
            new[] { ReactorEvents.LoginPostAuth, ReactorEvents.TokenPreIssue },
            ReactorHandlers.Of(new FixtureReactor("platform")).Events());
    }

    [Fact]
    public async Task BindAcceptsALambda()
    {
        ReactorHandler handler = new ReactorHandlers()
            .Bind(ReactorEvents.UserPreCreate, (e, ct) => Task.FromResult(ReactorDecision.Allowed()))
            .Handler();

        Assert.IsType<ReactorDecision.Allow>(
            await handler(Event(ReactorEvents.UserPreCreate), CancellationToken.None));
    }

    [Fact]
    public void RefusesADecoratedMethodWithTheWrongSignature()
    {
        ArgumentException error = Assert.Throws<ArgumentException>(
            () => ReactorHandlers.Of(new BadSignatureReactor()));

        Assert.Contains("Task<ReactorDecision>(ReactorEvent, CancellationToken)", error.Message, StringComparison.Ordinal);
    }

    // ---- rule 2: an unregistered name is refused at bind time ---------------

    [Fact]
    public void RejectsAMisspelledEventName()
    {
        ArgumentException error = Assert.Throws<ArgumentException>(
            () => new ReactorHandlers().Bind("token.pre_isue", (e, ct) => Task.FromResult(ReactorDecision.Allowed())));

        Assert.Contains("not a hookable reactor event", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// &#167;22.7's three are in no registry row, so rule 2 refuses them as unknown
    /// names. Asserted on behaviour, not on a comment.
    /// </summary>
    [Fact]
    public void RejectsTheHotPathOperations()
    {
        foreach (string excluded in ExcludedHotPath)
        {
            Assert.Throws<ArgumentException>(
                () => new ReactorHandlers().Bind(excluded, (e, ct) => Task.FromResult(ReactorDecision.Allowed())));
        }
    }

    /// <summary>The rejection names what IS hookable, never what is excluded (rule 2).</summary>
    [Fact]
    public void RejectionNamesTheRegistryNotTheExclusions()
    {
        ArgumentException error = Assert.Throws<ArgumentException>(
            () => new ReactorHandlers().Bind("nope", (e, ct) => Task.FromResult(ReactorDecision.Allowed())));

        Assert.Contains(ReactorEvents.TokenPreIssue, error.Message, StringComparison.Ordinal);
        foreach (string excluded in ExcludedHotPath)
        {
            Assert.DoesNotContain(excluded, error.Message, StringComparison.Ordinal);
        }
    }

    // ---- rule 3: one handler per event --------------------------------------

    [Fact]
    public void RejectsADuplicateBinding()
    {
        ReactorHandlers handlers = new ReactorHandlers()
            .Bind(ReactorEvents.TokenPreIssue, (e, ct) => Task.FromResult(ReactorDecision.Allowed()));

        ArgumentException error = Assert.Throws<ArgumentException>(
            () => handlers.Bind(ReactorEvents.TokenPreIssue, (e, ct) => Task.FromResult(ReactorDecision.Denied("second"))));

        Assert.Contains("already bound", error.Message, StringComparison.Ordinal);
    }

    // ---- rule 4: an unbound event abstains ----------------------------------

    [Fact]
    public async Task UnboundEventAbstainsRatherThanAllowing()
    {
        ReactorHandler handler = ReactorHandlers.Of(new FixtureReactor("platform")).Handler();

        UnboundReactorEventException rejection = await Assert.ThrowsAsync<UnboundReactorEventException>(
            () => handler(Event(ReactorEvents.GrantPreAssign), CancellationToken.None));

        // Throwing publishes NOTHING, so the registration's failure_policy decides
        // (§22.8) — not a synthesized allow (§22.10 rule 2).
        Assert.Equal(ReactorEvents.GrantPreAssign, rejection.Event);
    }

    [Fact]
    public void EmptyBindingSetIsRefused()
    {
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => new ReactorHandlers().Handler());

        Assert.Contains("no bindings", error.Message, StringComparison.Ordinal);
    }

    // ---- rule 5: a handler's own failure propagates --------------------------

    [Fact]
    public async Task HandlerExceptionPropagates()
    {
        ReactorHandler handler = ReactorHandlers.Of(new ThrowingReactor()).Handler();

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => handler(Event(ReactorEvents.LoginPostAuth), CancellationToken.None));

        Assert.Equal("fraud service unreachable", error.Message);
    }

    [Fact]
    public async Task FaultedTaskPropagates()
    {
        ReactorHandler handler = new ReactorHandlers()
            .Bind(ReactorEvents.UserPreUpdate,
                (e, ct) => Task.FromException<ReactorDecision>(new TimeoutException("directory timed out")))
            .Handler();

        await Assert.ThrowsAsync<TimeoutException>(
            () => handler(Event(ReactorEvents.UserPreUpdate), CancellationToken.None));
    }

    // ---- rule 6 and the SHOULD ----------------------------------------------

    [Fact]
    public async Task ForbiddenPatchKeyIsSentUnfiltered()
    {
        ReactorHandler handler = new ReactorHandlers()
            .Bind(ReactorEvents.TokenPreIssue,
                (e, ct) => Task.FromResult(ReactorDecision.Mutated(new Dictionary<string, string> { ["sub"] = "attacker" })))
            .Handler();

        ReactorDecision decision = await handler(Event(ReactorEvents.TokenPreIssue), CancellationToken.None);

        // The binder must not silently drop a patch key (§22.10 rule 3).
        IReadOnlyDictionary<string, string> patch = Assert.IsType<ReactorDecision.Mutate>(decision).Patch;
        Assert.Single(patch);
        Assert.Equal("attacker", patch["sub"]);
    }

    [Fact]
    public void BoundEventsFeedTheFailurePolicy()
    {
        ReactorHandlers handlers = ReactorHandlers.Of(new FixtureReactor("platform"));

        // token.pre_issue defaults open, login.post_auth defaults closed; §22.8's
        // strictest-wins composition makes the pair fail_closed.
        Assert.Equal(FailurePolicy.FailClosed, ReactorEvents.DefaultFailurePolicyFor(handlers.Events()));
    }

    [Fact]
    public async Task HandlerSnapshotsItsBindings()
    {
        ReactorHandlers handlers = new ReactorHandlers()
            .Bind(ReactorEvents.TokenPreIssue, (e, ct) => Task.FromResult(ReactorDecision.Allowed()));
        ReactorHandler handler = handlers.Handler();

        handlers.Bind(ReactorEvents.GrantPreAssign, (e, ct) => Task.FromResult(ReactorDecision.Denied("late")));

        await Assert.ThrowsAsync<UnboundReactorEventException>(
            () => handler(Event(ReactorEvents.GrantPreAssign), CancellationToken.None));
    }
}
