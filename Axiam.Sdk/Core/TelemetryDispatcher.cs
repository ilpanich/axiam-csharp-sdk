namespace Axiam.Sdk.Core;

using System;
using System.Diagnostics;

/// <summary>
/// A caller-supplied telemetry sink (CONTRACT.md &#167;19).
/// </summary>
/// <remarks>
/// Install one with <c>AxiamClientOptions.TelemetryHook</c>. It receives request
/// start/end, &#167;16 retry and &#167;9 refresh events, so metrics can be wired
/// without this package depending on any metrics library.
/// </remarks>
/// <param name="telemetryEvent">The event; never null.</param>
public delegate void TelemetryHook(TelemetryEvent telemetryEvent);

/// <summary>
/// Internal &#167;19 dispatcher. A null hook is the overwhelmingly common case and
/// costs one null check per request.
/// </summary>
internal sealed class TelemetryDispatcher
{
    private readonly TelemetryHook? _hook;

    internal TelemetryDispatcher(TelemetryHook? hook) => _hook = hook;

    /// <summary>Whether a hook is installed.</summary>
    internal bool Installed => _hook is not null;

    /// <summary>
    /// Delivers <paramref name="telemetryEvent"/>, swallowing anything the caller's
    /// hook throws.
    /// </summary>
    /// <remarks>
    /// <para>
    /// &#167;19.2 rule 2: telemetry is not permitted to fail an authorization check.
    /// A hook that throws is the caller's bug, and letting it propagate here would
    /// turn a metrics problem into an authorization failure.
    /// </para>
    /// <para>
    /// <see cref="OperationCanceledException"/> is deliberately re-thrown: swallowing
    /// it would hide a cancellation the caller asked for, which is a correctness
    /// concern rather than a metrics one.
    /// </para>
    /// </remarks>
    internal void Emit(TelemetryEvent telemetryEvent)
    {
        if (_hook is null)
        {
            return;
        }

        try
        {
            _hook(telemetryEvent);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            // Deliberately swallowed; see above.
        }
    }

    /// <summary>
    /// Opens a &#167;19 request pair around one <strong>attempt</strong>.
    /// </summary>
    /// <remarks>
    /// Per attempt, not per logical call: &#167;19.2 rule 5 requires a caller to be
    /// able to count real wire calls from the events, which one pair per operation
    /// would hide — a retried call would look like a single slow one.
    /// </remarks>
    internal Span StartRequest(string operation, string method, string pathTemplate, int attempt)
    {
        if (Installed)
        {
            Emit(new RequestStartEvent(operation, method, pathTemplate, attempt));
        }

        return new Span(this, operation, method, pathTemplate, attempt);
    }

    /// <summary>Closes a &#167;19 request pair opened by <see cref="StartRequest"/>.</summary>
    internal readonly struct Span
    {
        private readonly TelemetryDispatcher _dispatcher;
        private readonly string _operation;
        private readonly string _method;
        private readonly string _pathTemplate;
        private readonly int _attempt;
        private readonly long _startedTicks;

        internal Span(
            TelemetryDispatcher dispatcher,
            string operation,
            string method,
            string pathTemplate,
            int attempt)
        {
            _dispatcher = dispatcher;
            _operation = operation;
            _method = method;
            _pathTemplate = pathTemplate;
            _attempt = attempt;
            _startedTicks = Stopwatch.GetTimestamp();
        }

        /// <summary>Emits the closing <see cref="RequestEndEvent"/>.</summary>
        internal void End(int? statusCode, TelemetryOutcome outcome)
        {
            if (!_dispatcher.Installed)
            {
                return;
            }

            _dispatcher.Emit(new RequestEndEvent(
                _operation,
                _method,
                _pathTemplate,
                _attempt,
                statusCode,
                Stopwatch.GetElapsedTime(_startedTicks),
                outcome));
        }
    }
}
