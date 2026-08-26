namespace Axiam.Sdk.Core;

using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Options;

/// <summary>
/// Bounded read-only retry policy — CONTRACT.md &#167;16.
/// </summary>
/// <remarks>
/// <para>
/// Before D5 this SDK had a retry <em>configuration surface</em>
/// (<c>MaxRetryAttempts</c>, <c>RetryBaseDelay</c>, <c>RetryMaxDelay</c>) whose
/// own doc comment said it was "not yet wired into any call path". It was
/// defaulted, documented, and asserted in tests — and read by nothing. So this
/// SDK performed <strong>no read-only retries at all</strong> while presenting
/// three knobs that looked like it did.
/// </para>
/// <para>
/// That is worse than having no surface: the settings and their tests are
/// exactly what stop anyone from checking. The &#167;16.7 conformance tests
/// therefore assert the policy through the public <c>CheckAccessAsync</c>
/// surface, counting requests on the wire.
/// </para>
/// </remarks>
internal static class RetryPolicy
{
    /// <summary>Attempt cap: 1 initial + 2 retries (&#167;16.1).</summary>
    internal const int MaxAttempts = 3;

    /// <summary>First backoff step (&#167;16.1).</summary>
    internal static readonly TimeSpan BaseDelay = TimeSpan.FromMilliseconds(200);

    /// <summary>Ceiling on any single computed backoff (&#167;16.1).</summary>
    internal static readonly TimeSpan MaxDelay = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The caller's attempt cap, clamped down to <see cref="MaxAttempts"/>.
    /// </summary>
    /// <remarks>
    /// &#167;16.1 permits an SDK to <em>lower</em> the cap or disable retry, never to
    /// raise it. Clamping rather than throwing keeps an existing caller who set 5
    /// working — they still get retries, just the contract's number of them — while
    /// making it impossible to turn one client into the herd the policy prevents.
    /// </remarks>
    internal static int EffectiveMaxAttempts(AxiamClientOptions options) =>
        Math.Clamp(options.MaxRetryAttempts, 1, MaxAttempts);

    /// <summary>The caller's base delay, clamped down to <see cref="BaseDelay"/>.</summary>
    internal static TimeSpan EffectiveBaseDelay(AxiamClientOptions options) =>
        options.RetryBaseDelay <= TimeSpan.Zero || options.RetryBaseDelay > BaseDelay
            ? BaseDelay
            : options.RetryBaseDelay;

    /// <summary>The caller's delay ceiling, clamped down to <see cref="MaxDelay"/>.</summary>
    internal static TimeSpan EffectiveMaxDelay(AxiamClientOptions options) =>
        options.RetryMaxDelay <= TimeSpan.Zero || options.RetryMaxDelay > MaxDelay
            ? MaxDelay
            : options.RetryMaxDelay;

    /// <summary>
    /// The un-jittered backoff for a 1-based <paramref name="attempt"/>:
    /// <c>min(MaxDelay, BaseDelay * 2^(n-1))</c>. Attempt 1 → 200ms, attempt 2 → 400ms.
    /// </summary>
    internal static TimeSpan BackoffFor(int attempt) => BackoffFor(attempt, BaseDelay, MaxDelay);

    /// <summary>
    /// The un-jittered backoff for a 1-based <paramref name="attempt"/> against an
    /// explicit base and cap (already clamped by the Effective* helpers).
    /// </summary>
    internal static TimeSpan BackoffFor(int attempt, TimeSpan baseDelay, TimeSpan maxDelay)
    {
        // Shift the millisecond count rather than multiplying the TimeSpan, so a
        // large attempt cannot overflow into a negative wait.
        int shift = Math.Min(Math.Max(attempt - 1, 0), 32);
        long ms = (long)baseDelay.TotalMilliseconds << shift;
        return (ms <= 0 || ms > (long)maxDelay.TotalMilliseconds) ? maxDelay : TimeSpan.FromMilliseconds(ms);
    }

    /// <summary>
    /// The actual wait: <strong>full jitter</strong> over <c>[0, backoff]</c>,
    /// raised to any server-supplied <c>Retry-After</c> (&#167;16.1).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Full jitter, not <c>backoff ± 10%</c>. Partial jitter keeps every client's
    /// retries clustered around the same instant, which is the thundering herd
    /// retries are supposed to prevent rather than cause.
    /// </para>
    /// <para>
    /// <c>Retry-After</c> is a <strong>floor, never a ceiling</strong>: the server
    /// is stating when it will be ready, so retrying sooner is not permitted — and
    /// a <c>Retry-After: 0</c> cannot shorten the wait below what jitter chose.
    /// </para>
    /// </remarks>
    /// <param name="attempt">The 1-based attempt that just failed.</param>
    /// <param name="retryAfter">A server-supplied hint, or <see cref="TimeSpan.Zero"/>.</param>
    /// <param name="fraction">The jitter draw in <c>[0, 1]</c>, injected so tests can pin it.</param>
    internal static TimeSpan DelayFor(int attempt, TimeSpan retryAfter, double fraction) =>
        DelayFor(attempt, retryAfter, fraction, BaseDelay, MaxDelay);

    /// <summary>
    /// <see cref="DelayFor(int, TimeSpan, double)"/> against an explicit base and cap.
    /// </summary>
    internal static TimeSpan DelayFor(
        int attempt, TimeSpan retryAfter, double fraction, TimeSpan baseDelay, TimeSpan maxDelay)
    {
        double clamped = Math.Clamp(fraction, 0.0, 1.0);
        var jittered = TimeSpan.FromMilliseconds(
            BackoffFor(attempt, baseDelay, maxDelay).TotalMilliseconds * clamped);
        return retryAfter > jittered ? retryAfter : jittered;
    }

    /// <summary>
    /// Runs <paramref name="operation"/> under the &#167;16 policy.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The callback receives the 1-based attempt number so it can label its &#167;19
    /// request pair — &#167;19.2 rule 5 requires one pair per attempt so a caller can
    /// count real wire calls, and passing 1 every time would make a retried call
    /// indistinguishable from a single slow one.
    /// </para>
    /// <para>
    /// The callback MUST be side-effect-free. This helper — like every retry helper
    /// — cannot tell the difference, so routing a mutation through it would silently
    /// duplicate a side effect, or replay a single-use credential (an authorization
    /// code, a device code at redemption, a rotating refresh token) into a hard
    /// <c>invalid_grant</c>.
    /// </para>
    /// <para>
    /// Only <see cref="NetworkError"/> is retried. The &#167;2 taxonomy folds
    /// <c>408</c>/<c>429</c>/<c>5xx</c>/transport into that one type, so this
    /// implements the whole &#167;16.3 table: auth and authz failures are decisive
    /// answers from the server, not transport failures.
    /// </para>
    /// </remarks>
    /// <summary>
    /// Emits one <see cref="ConfigClampedEvent"/> per setting this policy clamped
    /// (CONTRACT.md &#167;19.2 rule 6).
    /// </summary>
    /// <remarks>
    /// Called once at client construction. Nothing is emitted for a value already
    /// within its limit — an event that fires when nothing happened trains its
    /// reader to ignore it.
    /// </remarks>
    internal static void ReportClamps(AxiamClientOptions options, TelemetryDispatcher telemetry)
    {
        if (!telemetry.Installed)
        {
            return;
        }

        int attempts = EffectiveMaxAttempts(options);
        if (attempts != options.MaxRetryAttempts)
        {
            telemetry.Emit(new ConfigClampedEvent(
                nameof(AxiamClientOptions.MaxRetryAttempts),
                options.MaxRetryAttempts.ToString(CultureInfo.InvariantCulture),
                attempts.ToString(CultureInfo.InvariantCulture),
                "§16.1"));
        }

        TimeSpan baseDelay = EffectiveBaseDelay(options);
        if (baseDelay != options.RetryBaseDelay)
        {
            telemetry.Emit(new ConfigClampedEvent(
                nameof(AxiamClientOptions.RetryBaseDelay),
                options.RetryBaseDelay.ToString(),
                baseDelay.ToString(),
                "§16.1"));
        }

        TimeSpan maxDelay = EffectiveMaxDelay(options);
        if (maxDelay != options.RetryMaxDelay)
        {
            telemetry.Emit(new ConfigClampedEvent(
                nameof(AxiamClientOptions.RetryMaxDelay),
                options.RetryMaxDelay.ToString(),
                maxDelay.ToString(),
                "§16.1"));
        }
    }

    internal static async Task<T> ExecuteAsync<T>(
        string operationName,
        AxiamClientOptions options,
        TelemetryDispatcher telemetry,
        Func<double> jitter,
        Func<int, Task<T>> operation,
        CancellationToken cancellationToken,
        Func<NetworkError, bool>? retryable = null)
    {
        int attempts = options.RetryEnabled ? EffectiveMaxAttempts(options) : 1;

        for (int attempt = 1; ; attempt++)
        {
            try
            {
                return await operation(attempt).ConfigureAwait(false);
            }
            // CONTRACT.md §27.4 rule 7 puts ValidationError under NetworkError, which
            // would otherwise make a rejected request body retry-eligible. The bytes
            // are wrong; sending them again earns the same refusal three times as
            // slowly. Callers that need that distinction pass `retryable`.
            catch (NetworkError ex) when (attempt < attempts && (retryable?.Invoke(ex) ?? true))
            {
                TimeSpan wait = DelayFor(
                    attempt,
                    ex.RetryAfter ?? TimeSpan.Zero,
                    jitter(),
                    EffectiveBaseDelay(options),
                    EffectiveMaxDelay(options));

                // §16.5 — without this event a retried-then-succeeded call is
                // invisible: a slow success with no signal the server is failing.
                telemetry.Emit(new RetryEvent(operationName, attempt, wait, ex.Message));

                // Task.Delay observes the token, so a caller's cancellation wins
                // over a pending backoff rather than being absorbed by it.
                await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
