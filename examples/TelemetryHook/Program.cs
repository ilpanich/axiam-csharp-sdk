using System.Collections.Concurrent;
using Axiam.Sdk;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;

// Telemetry hooks (CONTRACT.md §19): wiring metrics to an AXIAM client WITHOUT
// this package depending on any metrics library.
//
// The sink below aggregates in-process so the example runs with no extra
// dependencies; the comment at the bottom shows the exact mapping onto
// OpenTelemetry / prometheus-net, which is a drop-in replacement for the body.
// Uses ONLY the public Axiam.Sdk surface.
//
// Run: AXIAM_BASE_URL=https://your-axiam AXIAM_TENANT_ID=acme \
//          dotnet run --project examples/TelemetryHook

var requests = new ConcurrentDictionary<string, (long Count, long TotalMs)>();
var retries = new ConcurrentDictionary<string, long>();
long refreshes = 0;

void Sink(TelemetryEvent telemetryEvent)
{
    switch (telemetryEvent)
    {
        // One pair per ATTEMPT, not per logical call (§19.2 rule 5), so counting
        // these gives the real number of wire calls — including the ones a retry
        // made on your behalf.
        //
        // RequestStartEvent is deliberately not handled: RequestEndEvent carries
        // the same identity plus the outcome, so counting both double-counts.
        case RequestEndEvent e:
            requests.AddOrUpdate(
                $"{e.Operation}/{e.Outcome}",
                _ => (1, (long)e.Duration.TotalMilliseconds),
                (_, prev) => (prev.Count + 1, prev.TotalMs + (long)e.Duration.TotalMilliseconds));
            break;

        // §16.5 — the reason this event exists. A retried-then-succeeded
        // operation is otherwise invisible: the caller sees a slow success and no
        // signal that the server is failing. Alert on THIS rate, not on the error
        // rate, or a degrading server looks healthy right up until the retries
        // stop being enough.
        case RetryEvent e:
            retries.AddOrUpdate(e.Operation, _ => 1, (_, prev) => prev + 1);
            break;

        case RefreshEvent:
            Interlocked.Increment(ref refreshes);
            break;

        // §19.2 rule 6 — fired at most once per clamped setting, at construction.
        // Worth logging loudly rather than counting: it means a value in your
        // configuration is not the value in force, and the gap is silent
        // everywhere else.
        case ConfigClampedEvent e:
            Console.Error.WriteLine(
                $"WARN: {e.Setting}={e.Requested} was clamped to {e.Effective} ({e.ContractReference})");
            break;
    }
}

Uri baseUrl = new(Environment.GetEnvironmentVariable("AXIAM_BASE_URL") ?? "https://localhost:8443");
string tenantId = Environment.GetEnvironmentVariable("AXIAM_TENANT_ID") ?? "acme";

using AxiamClient client = new(baseUrl, tenantId, new AxiamClientOptions
{
    BaseUrl = baseUrl,
    TenantId = tenantId,
    TelemetryHook = Sink,

    // Deliberately above the §17.1 rule 2 ceiling, so the run demonstrates the
    // ConfigClampedEvent warning above rather than leaving it theoretical.
    DecisionMemoTtl = TimeSpan.FromSeconds(60),

    // Deliberately above the §16.1 cap, for the same reason. This SDK is the one
    // where the clamp matters most: MaxRetryAttempts was publicly settable
    // *upward* before D5, which is what §16.1 forbids — a caller who can raise
    // the cap turns one client into the herd a backoff exists to prevent.
    MaxRetryAttempts = 25,
});

try
{
    Guid documentId = Guid.Parse(
        Environment.GetEnvironmentVariable("AXIAM_RESOURCE_ID") ?? Guid.Empty.ToString());
    AccessDecision decision = await client.Authz.CheckAccessDecisionAsync("documents:read", documentId);
    Console.WriteLine($"allowed={decision.Allowed} reasonCode={decision.ReasonCode ?? "(absent)"}");
}
// The §2 taxonomy is three sealed exception types with no shared base in this
// SDK, so "any AXIAM error" is spelled as the three of them rather than as one
// catch. Worth knowing before you write the same handler in your own code.
catch (Exception ex) when (ex is NetworkError or AuthError or AuthzError)
{
    // Expected when no server is reachable — the point of the example is the
    // telemetry below, which is emitted either way.
    Console.WriteLine($"check failed: {ex.Message}");
}

Console.WriteLine("--- telemetry ---");
foreach ((string key, (long count, long totalMs)) in requests.OrderBy(kv => kv.Key))
{
    Console.WriteLine($"  {key}: count={count} mean={(count == 0 ? 0 : totalMs / count)}ms");
}
if (retries.IsEmpty)
{
    Console.WriteLine("  retries: (none)");
}
foreach ((string op, long n) in retries.OrderBy(kv => kv.Key))
{
    Console.WriteLine($"  retries {op}: {n}");
}
Console.WriteLine($"  refreshes: {Interlocked.Read(ref refreshes)}");

// §18: `using` disposes the client, releasing the HttpClient and its handler
// chain. Dispose issues NO request — it does not log out, because the
// server-side session deliberately outlives the client object. Any call after
// disposal throws rather than silently rebuilding the transport.

/*
 * Mapping onto a real backend — replace Sink's body, nothing else:
 *
 *   RequestEndEvent    → histogram "axiam.request.duration"
 *                        tags: operation, path_template, status_code, outcome, attempt
 *   RetryEvent         → counter   "axiam.request.retries"   tags: operation
 *   RefreshEvent       → counter   "axiam.token.refresh"     tags: role
 *   ConfigClampedEvent → a log line at Warning, not a metric: it fires once at
 *                        construction and its whole value is being READ.
 *
 * Tag with PathTemplate, never with the request URL: a metric tag carrying a
 * UUID is a cardinality bomb. The hook runs on the calling thread, so it must
 * not block — every mature metrics library already buffers, which is why §19.2
 * rule 4 leaves that choice to you rather than making it here.
 */
