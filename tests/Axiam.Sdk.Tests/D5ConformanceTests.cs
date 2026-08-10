using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Rest;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// D5 conformance — CONTRACT.md §16, §17, §18, §19.
/// </summary>
/// <remarks>
/// <para>
/// These assert through the <strong>public <c>CheckAccessAsync</c> surface</strong>,
/// counting requests that reach the transport, rather than against the helpers in
/// isolation. That distinction is normative as of contract 1.8.1.
/// </para>
/// <para>
/// It matters especially here. Before D5 this SDK had <c>MaxRetryAttempts</c>,
/// <c>RetryBaseDelay</c> and <c>RetryMaxDelay</c> — defaulted, documented, and
/// asserted in <c>CoreValueTypesTests</c> — read by no production code. Every one of
/// those assertions passed while the SDK performed no read-only retries at all. Only
/// a wire count catches that.
/// </para>
/// </remarks>
public class D5ConformanceTests
{
    private static readonly Uri BaseUrl = new("https://axiam-d5.test");
    private static readonly Guid Resource = Guid.Parse("11111111-2222-3333-4444-555555555555");

    private const string AllowBody = """{"allowed":true,"reason_code":"allowed"}""";

    /// <summary>Replays a status script and counts requests reaching the transport.</summary>
    private sealed class ScriptHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode[] _statuses;
        private readonly string _body;
        private int _calls;

        internal ScriptHandler(HttpStatusCode[] statuses, string? body = null)
        {
            _statuses = statuses;
            _body = body ?? AllowBody;
        }

        internal int Calls => Volatile.Read(ref _calls);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int n = Interlocked.Increment(ref _calls);
            HttpStatusCode status = _statuses[Math.Min(n - 1, _statuses.Length - 1)];
            var response = new HttpResponseMessage(status);
            if (status == HttpStatusCode.OK)
            {
                response.Content = new StringContent(_body, Encoding.UTF8, "application/json");
            }

            return Task.FromResult(response);
        }
    }

    private static AuthzRestClient ClientFor(
        ScriptHandler handler,
        AxiamClientOptions? options = null,
        TelemetryHook? hook = null)
    {
        var http = new HttpClient(handler) { BaseAddress = BaseUrl };
        AxiamClientOptions effective = options ?? new AxiamClientOptions
        {
            BaseUrl = BaseUrl,
            TenantId = "acme",
        };
        return new AuthzRestClient(
            http,
            effective,
            new TelemetryDispatcher(hook),
            new DecisionMemo(effective.DecisionMemoTtl),
            // Pin the jitter to 0 so the tests do not really sleep: a test that waits
            // 200ms is a test nobody runs (§16.7). The delay arithmetic is asserted
            // directly below instead.
            jitter: () => 0.0);
    }

    private static AxiamClientOptions Options(
        TimeSpan? memoTtl = null,
        bool retryEnabled = true,
        int? maxAttempts = null,
        TimeSpan? baseDelay = null,
        TimeSpan? maxDelay = null) => new()
        {
            BaseUrl = BaseUrl,
            TenantId = "acme",
            DecisionMemoTtl = memoTtl ?? TimeSpan.Zero,
            RetryEnabled = retryEnabled,
            MaxRetryAttempts = maxAttempts ?? 3,
            RetryBaseDelay = baseDelay ?? TimeSpan.FromMilliseconds(200),
            RetryMaxDelay = maxDelay ?? TimeSpan.FromSeconds(5),
        };

    // -----------------------------------------------------------------------
    // §16 — the policy table
    // -----------------------------------------------------------------------

    [Fact]
    public void BackoffDoublesFromBaseAndStopsAtCap()
    {
        Assert.Equal(RetryPolicy.BaseDelay, RetryPolicy.BackoffFor(1));
        Assert.Equal(TimeSpan.FromMilliseconds(400), RetryPolicy.BackoffFor(2));
        Assert.Equal(RetryPolicy.MaxDelay, RetryPolicy.BackoffFor(20));
    }

    [Fact]
    public void JitterIsFullNotPartial()
    {
        // The range is [0, backoff], not backoff ± something. Pinning the fraction to
        // its endpoints is what distinguishes the two — a random draw would pass
        // under either policy.
        Assert.Equal(TimeSpan.Zero, RetryPolicy.DelayFor(1, TimeSpan.Zero, 0.0));
        Assert.Equal(RetryPolicy.BaseDelay, RetryPolicy.DelayFor(1, TimeSpan.Zero, 1.0));
        Assert.Equal(TimeSpan.FromMilliseconds(200), RetryPolicy.DelayFor(2, TimeSpan.Zero, 0.5));
    }

    [Fact]
    public void RetryAfterIsAFloorNeverACeiling()
    {
        // TypeScript's `retryAfterMs ?? backoff(n)` made the hint REPLACE the backoff,
        // so a zero retried immediately and defeated the policy.
        Assert.Equal(TimeSpan.FromSeconds(2), RetryPolicy.DelayFor(1, TimeSpan.FromSeconds(2), 1.0));
        Assert.Equal(RetryPolicy.BaseDelay, RetryPolicy.DelayFor(1, TimeSpan.Zero, 1.0));
        Assert.Equal(TimeSpan.FromMilliseconds(50), RetryPolicy.DelayFor(1, TimeSpan.FromMilliseconds(50), 0.0));
    }

    [Fact]
    public void JitterFractionOutsideUnitIntervalIsClamped()
    {
        // A caller-supplied source is not trusted to stay in [0, 1]: above 1 would
        // exceed the §16.1 cap, below 0 would produce a negative wait.
        Assert.Equal(RetryPolicy.BaseDelay, RetryPolicy.DelayFor(1, TimeSpan.Zero, 1.5));
        Assert.Equal(TimeSpan.Zero, RetryPolicy.DelayFor(1, TimeSpan.Zero, -0.5));
    }

    [Fact]
    public async Task PersistentServerErrorMakesExactlyThreeAttempts()
    {
        var handler = new ScriptHandler([HttpStatusCode.ServiceUnavailable]);
        AuthzRestClient client = ClientFor(handler, Options());

        await Assert.ThrowsAsync<NetworkError>(() => client.CheckAccessDecisionAsync("read", Resource));

        // Exactly 3 — not 1, which is what this SDK did before D5, when the retry
        // settings existed but nothing read them.
        Assert.Equal(RetryPolicy.MaxAttempts, handler.Calls);
    }

    [Fact]
    public async Task TransientFailureIsRetriedAndTheSuccessReturned()
    {
        var handler = new ScriptHandler([HttpStatusCode.ServiceUnavailable, HttpStatusCode.OK]);
        AuthzRestClient client = ClientFor(handler, Options());

        AccessDecision decision = await client.CheckAccessDecisionAsync("read", Resource);

        Assert.True(decision.Allowed);
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task DecisiveForbiddenIsNotRetried()
    {
        // A 403 is an answer, not a transport failure. Retrying reproduces the
        // identical rejection and spends the caller's latency budget.
        var handler = new ScriptHandler([HttpStatusCode.Forbidden]);
        AuthzRestClient client = ClientFor(handler, Options());

        await Assert.ThrowsAnyAsync<Exception>(() => client.CheckAccessDecisionAsync("read", Resource));

        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task RetryDisabledMakesExactlyOneAttempt()
    {
        var handler = new ScriptHandler([HttpStatusCode.ServiceUnavailable]);
        AuthzRestClient client = ClientFor(handler, Options(retryEnabled: false));

        await Assert.ThrowsAsync<NetworkError>(() => client.CheckAccessDecisionAsync("read", Resource));

        Assert.Equal(1, handler.Calls);
    }

    // -----------------------------------------------------------------------
    // §16.1 — the caller cannot raise the policy above the contract
    // -----------------------------------------------------------------------

    [Fact]
    public void AnAttemptCapAboveTheContractIsClampedDown()
    {
        // §16.1 permits LOWERING the cap or disabling retry, never raising it: a
        // caller who could raise it turns one client into the thundering herd the
        // policy exists to prevent.
        Assert.Equal(3, RetryPolicy.EffectiveMaxAttempts(Options(maxAttempts: 10)));
        Assert.Equal(1, RetryPolicy.EffectiveMaxAttempts(Options(maxAttempts: 1)));
        // Lowering still works — the clamp is one-directional.
        Assert.Equal(2, RetryPolicy.EffectiveMaxAttempts(Options(maxAttempts: 2)));
    }

    [Fact]
    public void DelaysAboveTheContractAreClampedDown()
    {
        Assert.Equal(
            RetryPolicy.BaseDelay,
            RetryPolicy.EffectiveBaseDelay(Options(baseDelay: TimeSpan.FromSeconds(30))));
        Assert.Equal(
            RetryPolicy.MaxDelay,
            RetryPolicy.EffectiveMaxDelay(Options(maxDelay: TimeSpan.FromMinutes(5))));
        // Lowering still works.
        Assert.Equal(
            TimeSpan.FromMilliseconds(50),
            RetryPolicy.EffectiveBaseDelay(Options(baseDelay: TimeSpan.FromMilliseconds(50))));
    }

    [Fact]
    public async Task AnInflatedAttemptCapStillMakesOnlyThreeWireCalls()
    {
        // The clamp asserted end-to-end, not just on the helper.
        var handler = new ScriptHandler([HttpStatusCode.ServiceUnavailable]);
        AuthzRestClient client = ClientFor(handler, Options(maxAttempts: 25));

        await Assert.ThrowsAsync<NetworkError>(() => client.CheckAccessDecisionAsync("read", Resource));

        Assert.Equal(RetryPolicy.MaxAttempts, handler.Calls);
    }

    // -----------------------------------------------------------------------
    // §17 — decision memo
    // -----------------------------------------------------------------------

    [Fact]
    public async Task TheMemoIsOffByDefault()
    {
        // The most important assertion here. §11.2 rule 6's ban on decision caching is
        // still the default; a build that quietly enabled this would change
        // authorization staleness for every existing caller without them asking.
        var handler = new ScriptHandler([HttpStatusCode.OK]);
        AuthzRestClient client = ClientFor(handler, Options());

        await client.CheckAccessDecisionAsync("read", Resource);
        await client.CheckAccessDecisionAsync("read", Resource);

        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task ARepeatInsideTheTtlIsServedWithoutASecondCall()
    {
        var handler = new ScriptHandler([HttpStatusCode.OK]);
        AuthzRestClient client = ClientFor(handler, Options(memoTtl: TimeSpan.FromSeconds(5)));

        AccessDecision first = await client.CheckAccessDecisionAsync("read", Resource);
        AccessDecision second = await client.CheckAccessDecisionAsync("read", Resource);

        Assert.Equal(1, handler.Calls);
        // §17.1 rule 5: the reason code survives the memo.
        Assert.Equal(first.ReasonCode, second.ReasonCode);
        Assert.NotNull(second.ReasonCode);
    }

    [Fact]
    public async Task DeniesAreMemoizedExactlyLikeAllows()
    {
        // §17.1 rule 4 — asymmetric caching leaks the outcome through latency.
        var handler = new ScriptHandler(
            [HttpStatusCode.OK],
            """{"allowed":false,"reason_code":"denied_by_rule"}""");
        AuthzRestClient client = ClientFor(handler, Options(memoTtl: TimeSpan.FromSeconds(5)));

        await client.CheckAccessDecisionAsync("read", Resource);
        AccessDecision second = await client.CheckAccessDecisionAsync("read", Resource);

        Assert.Equal(1, handler.Calls);
        Assert.False(second.Allowed);
        Assert.Equal("denied_by_rule", second.ReasonCode);
    }

    [Fact]
    public async Task AFailureIsNeverMemoized()
    {
        // §17.1 rule 7 — caching a transport error as a deny turns a blip into a
        // TTL-long outage.
        var handler = new ScriptHandler([HttpStatusCode.ServiceUnavailable]);
        AuthzRestClient client = ClientFor(
            handler, Options(memoTtl: TimeSpan.FromSeconds(5), retryEnabled: false));

        await Assert.ThrowsAsync<NetworkError>(() => client.CheckAccessDecisionAsync("read", Resource));
        await Assert.ThrowsAsync<NetworkError>(() => client.CheckAccessDecisionAsync("read", Resource));

        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public void EveryKeyComponentIsDistinguished()
    {
        Guid other = Guid.Parse("99999999-2222-3333-4444-555555555555");
        Guid subject = Guid.Parse("88888888-2222-3333-4444-555555555555");
        var keys = new HashSet<string>(StringComparer.Ordinal)
        {
            DecisionMemo.Key(null, Resource, "read", null),
            DecisionMemo.Key(null, Resource, "write", null),
            DecisionMemo.Key(null, other, "read", null),
            DecisionMemo.Key(null, Resource, "read", "col-a"),
            DecisionMemo.Key(subject, Resource, "read", null),
        };
        Assert.Equal(5, keys.Count);

        // An absent scope must never collide with a present empty one.
        Assert.NotEqual(
            DecisionMemo.Key(null, Resource, "read", null),
            DecisionMemo.Key(null, Resource, "read", string.Empty));
    }

    [Fact]
    public void ATtlAboveTheCeilingIsClampedRatherThanRejected()
    {
        Assert.Equal(DecisionMemo.MaxTtl, new DecisionMemo(TimeSpan.FromHours(1)).EffectiveTtl);
        Assert.Equal(TimeSpan.FromSeconds(2), new DecisionMemo(TimeSpan.FromSeconds(2)).EffectiveTtl);
        Assert.False(new DecisionMemo(TimeSpan.Zero).Enabled);
        Assert.False(new DecisionMemo(TimeSpan.FromSeconds(-1)).Enabled);
    }

    [Fact]
    public void TheMemoEvictsRatherThanGrowingWithoutBound()
    {
        // §17.1 rule 8 — an unbounded per-client cache keyed by (subject, resource,
        // action, scope) is a memory leak in any service that checks many resources.
        var memo = new DecisionMemo(TimeSpan.FromSeconds(5));
        var decision = new AccessDecision(true, null, "allowed");
        for (int i = 0; i < DecisionMemo.MaxEntries + 100; i++)
        {
            memo.Put(DecisionMemo.Key(null, Guid.NewGuid(), "read", null), decision);
        }

        Assert.Equal(DecisionMemo.MaxEntries, memo.Count);
    }

    // -----------------------------------------------------------------------
    // §18 — deterministic shutdown
    // -----------------------------------------------------------------------

    [Fact]
    public void DisposeIsIdempotent()
    {
        var client = new AxiamClient(BaseUrl, "acme");
        client.Dispose();
        client.Dispose();
    }

    [Fact]
    public void UseAfterDisposeThrowsRatherThanReconnecting()
    {
        var handler = new ScriptHandler([HttpStatusCode.OK]);
        AxiamClient client = AxiamClient.CreateForTesting(BaseUrl, "acme", null, handler);
        client.Dispose();

        // ObjectDisposedException rather than NetworkError: this is the .NET-idiomatic
        // answer, and it is what a caller's existing handlers already expect.
        Assert.Throws<ObjectDisposedException>(() => client.LoginAsync("u@example.com", "pw").GetAwaiter().GetResult());
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public void DisposeIssuesNoNetworkRequest()
    {
        // §18.1 rule 5. The server-side session deliberately outlives the client
        // object — that is what lets a process restart and resume — so a Dispose that
        // logged out would silently end every user's session on each deploy. Asserted
        // against the wire, because a logout wired into Dispose succeeds silently.
        var handler = new ScriptHandler([HttpStatusCode.OK]);
        AxiamClient client = AxiamClient.CreateForTesting(BaseUrl, "acme", null, handler);

        client.Dispose();

        Assert.Equal(0, handler.Calls);
    }

    // -----------------------------------------------------------------------
    // §19 — telemetry
    // -----------------------------------------------------------------------

    [Fact]
    public async Task OneRequestPairPerAttemptWithARetryBetween()
    {
        var events = new List<TelemetryEvent>();
        var handler = new ScriptHandler([HttpStatusCode.ServiceUnavailable, HttpStatusCode.OK]);
        AuthzRestClient client = ClientFor(handler, Options(), events.Add);

        await client.CheckAccessDecisionAsync("read", Resource);

        var kinds = new List<string>();
        var attempts = new List<int>();
        foreach (TelemetryEvent e in events)
        {
            switch (e)
            {
                case RequestStartEvent start:
                    kinds.Add("start");
                    attempts.Add(start.Attempt);
                    // The path TEMPLATE, never a substituted URL — a metric label
                    // carrying a UUID is a cardinality bomb.
                    Assert.Equal("/api/v1/authz/check", start.PathTemplate);
                    break;
                case RequestEndEvent:
                    kinds.Add("end");
                    break;
                case RetryEvent:
                    kinds.Add("retry");
                    break;
            }
        }

        Assert.Equal(new[] { "start", "end", "retry", "start", "end" }, kinds);
        // Emitting both pairs as attempt 1 would make a retried call
        // indistinguishable from a single slow one.
        Assert.Equal(new[] { 1, 2 }, attempts);
    }

    [Fact]
    public async Task AThrowingHookCannotFailTheOperation()
    {
        // §19.2 rule 2 — telemetry is not permitted to fail an authorization check.
        var handler = new ScriptHandler([HttpStatusCode.OK]);
        AuthzRestClient client = ClientFor(
            handler, Options(), _ => throw new InvalidOperationException("hook exploded"));

        AccessDecision decision = await client.CheckAccessDecisionAsync("read", Resource);

        Assert.True(decision.Allowed);
    }

    [Fact]
    public async Task NoEventPayloadCarriesAToken()
    {
        // §19.2 rule 3 — this surface exists to be shipped to a metrics backend,
        // which is the last place a bearer token should land.
        var events = new List<TelemetryEvent>();
        var handler = new ScriptHandler([HttpStatusCode.ServiceUnavailable]);
        AuthzRestClient client = ClientFor(handler, Options(), events.Add);

        await Assert.ThrowsAsync<NetworkError>(() => client.CheckAccessDecisionAsync("read", Resource));

        string rendered = string.Join(";", events).ToLowerInvariant();
        Assert.DoesNotContain("eyj", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("authorization:", rendered, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // §19.2 rule 6 — a clamp is reported, not swallowed
    // -----------------------------------------------------------------------

    [Fact]
    public void ClampingAnAttemptCapEmitsAConfigClampedEvent()
    {
        // Clamping is right; clamping SILENTLY is not. Without this event a caller
        // who set 10 has no way to learn they got 3.
        var events = new List<TelemetryEvent>();
        var options = Options(maxAttempts: 10);
        options = options with { TelemetryHook = events.Add };

        using var client = AxiamClient.CreateForTesting(
            BaseUrl, "acme", options, new ScriptHandler([HttpStatusCode.OK]));

        ConfigClampedEvent clamp = Assert.Single(events.OfType<ConfigClampedEvent>());
        Assert.Equal("MaxRetryAttempts", clamp.Setting);
        Assert.Equal("10", clamp.Requested);
        Assert.Equal("3", clamp.Effective);
        Assert.Equal("§16.1", clamp.ContractReference);
    }

    [Fact]
    public void ClampingTheMemoTtlEmitsAConfigClampedEvent()
    {
        // The clamp that matters most: an operator who set 60s believes their
        // staleness bound is 60s. It is 5s, and without this nothing says so.
        var events = new List<TelemetryEvent>();
        var options = Options(memoTtl: TimeSpan.FromSeconds(60));
        options = options with { TelemetryHook = events.Add };

        using var client = AxiamClient.CreateForTesting(
            BaseUrl, "acme", options, new ScriptHandler([HttpStatusCode.OK]));

        ConfigClampedEvent clamp = Assert.Single(
            events.OfType<ConfigClampedEvent>().Where(e => e.Setting == "DecisionMemoTtl"));
        Assert.Equal(TimeSpan.FromSeconds(60).ToString(), clamp.Requested);
        Assert.Equal(DecisionMemo.MaxTtl.ToString(), clamp.Effective);
        Assert.Equal("§17.1 rule 2", clamp.ContractReference);
    }

    [Fact]
    public void AValueAlreadyWithinItsLimitEmitsNothing()
    {
        // §19.2 rule 6: an event that fires when nothing happened trains its reader
        // to ignore it.
        var events = new List<TelemetryEvent>();
        var options = Options(maxAttempts: 3, memoTtl: TimeSpan.FromSeconds(2));
        options = options with { TelemetryHook = events.Add };

        using var client = AxiamClient.CreateForTesting(
            BaseUrl, "acme", options, new ScriptHandler([HttpStatusCode.OK]));

        Assert.Empty(events.OfType<ConfigClampedEvent>());
    }

    [Fact]
    public void LoweringIsNotClampingAndEmitsNothing()
    {
        // The clamp is one-directional. A caller who asked for FEWER attempts gets
        // what they asked for, and no event — nothing was overridden.
        var events = new List<TelemetryEvent>();
        var options = Options(maxAttempts: 2, baseDelay: TimeSpan.FromMilliseconds(50));
        options = options with { TelemetryHook = events.Add };

        using var client = AxiamClient.CreateForTesting(
            BaseUrl, "acme", options, new ScriptHandler([HttpStatusCode.OK]));

        Assert.Empty(events.OfType<ConfigClampedEvent>());
    }

    [Fact]
    public void AnUninstalledDispatcherIsInert()
    {
        var dispatcher = new TelemetryDispatcher(null);
        Assert.False(dispatcher.Installed);
        dispatcher.Emit(new RefreshEvent(RefreshRole.Leader, TimeSpan.FromMilliseconds(1)));
        dispatcher.StartRequest("op", "POST", "/api/v1/authz/check", 1)
            .End(200, TelemetryOutcome.Success);
    }

    // -----------------------------------------------------------------------
    // §16.7 — the SAME assertions through the bare-bool surface
    //
    // Every §16 case above drives CheckAccessDecisionAsync. That is the richer
    // surface, but it is not the one most callers use, and until this section
    // existed the difference was load-bearing: CheckAccessAsync, CanAsync and
    // BatchCheckAsync each posted directly, with no retry budget, no memo and no
    // request pair, while this suite stayed green. A conformance suite that
    // proves the policy on a surface nobody calls proves nothing about the
    // surface they do — which is why §16.7 pins the assertion to the public API
    // and to requests counted on the wire.
    //
    // These cases fail if anyone re-inlines the transport call into a bool method.
    // -----------------------------------------------------------------------

    private const string BatchAllowBody =
        """{"results":[{"allowed":true,"reason_code":"allowed"}]}""";

    private static readonly AuthzRestClient.AccessCheck[] OneCheck =
        [new AuthzRestClient.AccessCheck("read", Resource)];

    [Fact]
    public async Task TheBoolSurfaceRetriesToo()
    {
        var handler = new ScriptHandler([HttpStatusCode.ServiceUnavailable, HttpStatusCode.OK]);
        AuthzRestClient client = ClientFor(handler, Options());

        Assert.True(await client.CheckAccessAsync("read", Resource));
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task TheBoolSurfaceHonoursTheAttemptCap()
    {
        var handler = new ScriptHandler([HttpStatusCode.ServiceUnavailable]);
        AuthzRestClient client = ClientFor(handler, Options(maxAttempts: 25));

        await Assert.ThrowsAsync<NetworkError>(() => client.CheckAccessAsync("read", Resource));

        // 3, not 25 and not 1: the clamp and the retry both reach this surface.
        Assert.Equal(RetryPolicy.MaxAttempts, handler.Calls);
    }

    [Fact]
    public async Task CanInheritsThePolicyFromCheckAccess()
    {
        // CanAsync is the convenience spelling. It must not be a second
        // implementation — that is exactly how one path drifts out of policy.
        var handler = new ScriptHandler([HttpStatusCode.ServiceUnavailable, HttpStatusCode.OK]);
        AuthzRestClient client = ClientFor(handler, Options());

        Assert.True(await client.CanAsync("read", Resource));
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task TheBoolSurfaceEmitsTheFullEventSequence()
    {
        var events = new List<TelemetryEvent>();
        var handler = new ScriptHandler([HttpStatusCode.ServiceUnavailable, HttpStatusCode.OK]);
        AuthzRestClient client = ClientFor(handler, Options(), events.Add);

        await client.CheckAccessAsync("read", Resource);

        Assert.Equal(
            new[] { "start", "end", "retry", "start", "end" },
            events.Select(e => e switch
            {
                RequestStartEvent => "start",
                RequestEndEvent => "end",
                RetryEvent => "retry",
                _ => "other",
            }).ToArray());
    }

    [Fact]
    public async Task TheBoolSurfaceIsServedByTheMemoLikeTheDecisionSurface()
    {
        // §17 is keyed on the check, not on the return type, so the two surfaces
        // must share one memo — otherwise a caller mixing them pays for a second
        // wire call that the TTL says it already answered.
        var handler = new ScriptHandler([HttpStatusCode.OK]);
        AuthzRestClient client = ClientFor(handler, Options(memoTtl: TimeSpan.FromSeconds(5)));

        Assert.True(await client.CheckAccessDecisionAsync("read", Resource).ContinueWith(t => t.Result.Allowed));
        Assert.True(await client.CheckAccessAsync("read", Resource));

        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task BatchCheckRetriesAndCarriesTheBatchPathTemplate()
    {
        var events = new List<TelemetryEvent>();
        var handler = new ScriptHandler(
            [HttpStatusCode.ServiceUnavailable, HttpStatusCode.OK], BatchAllowBody);
        AuthzRestClient client = ClientFor(handler, Options(), events.Add);

        IReadOnlyList<bool> results = await client.BatchCheckAsync(OneCheck);

        Assert.Equal(new[] { true }, results);
        Assert.Equal(2, handler.Calls);
        // The batch path, not the single-check one — a copy-pasted template would
        // silently merge two operations into one metric series.
        Assert.All(
            events.OfType<RequestStartEvent>(),
            e => Assert.Equal("/api/v1/authz/check/batch", e.PathTemplate));
    }
}
