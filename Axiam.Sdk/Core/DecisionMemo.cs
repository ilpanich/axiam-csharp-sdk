namespace Axiam.Sdk.Core;

using System;
using System.Collections.Generic;
using System.Diagnostics;

/// <summary>
/// Client-side decision memo — CONTRACT.md &#167;17.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Disabled by default.</strong> &#167;11.2 rule 6's ban on caching
/// allow/deny decisions is still the default behaviour; this is the single opt-in
/// exception that section carves out, and a caller has to switch it on having read
/// the cost.
/// </para>
/// <para>
/// <strong>What it costs.</strong> The staleness bound is the TTL, <strong>in both
/// directions</strong>. A grant revoked on the server can still read as allowed for
/// up to the TTL, and a grant just added can still read as denied for up to the TTL.
/// That second direction is the one that surprises people:
/// <strong>reads-your-own-writes is not guaranteed.</strong> An admin UI that grants
/// a role and immediately re-checks is the case that breaks, and it breaks silently.
/// </para>
/// <para>
/// This mirrors the server's own bound rather than inventing a second staleness
/// story — <c>AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS</c> (default 5s) makes the same
/// trade server-side. One deliberate difference: the server's setting is an unclamped
/// integer, so an operator can configure a multi-hour staleness window.
/// <see cref="MaxTtl"/> clamps this one at 5s, because the client has no reason to
/// repeat that.
/// </para>
/// <para>
/// Thread-safe by lock: a .NET client is routinely registered as a singleton and
/// shared across request-handling threads, and a cache that corrupted under
/// concurrency would be a worse bug than the one it is optimising away.
/// </para>
/// </remarks>
internal sealed class DecisionMemo
{
    /// <summary>
    /// The &#167;17.1 rule 2 ceiling. A configured TTL above this is clamped, not
    /// rejected: a caller who asked for a minute wants caching, and silently giving
    /// them the maximum safe value beats failing construction.
    /// </summary>
    internal static readonly TimeSpan MaxTtl = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Entry cap before FIFO eviction (&#167;17.1 rule 8). The memo is a latency
    /// optimisation, so dropping an entry is always correct — but it must drop rather
    /// than grow without bound.
    /// </summary>
    internal const int MaxEntries = 1024;

    /// <summary>
    /// Joins the key components. U+001F (unit separator) cannot appear in an action,
    /// a UUID or a scope, so no combination of caller-supplied values can forge a
    /// collision.
    /// </summary>
    private const char Separator = '\u001F';

    /// <summary>
    /// Marks an absent optional, which is why an absent scope can never collide with a
    /// present one — a memo that let them collide would answer a narrower question
    /// with a broader answer.
    /// </summary>
    private const char Absent = '\u0000';

    private readonly TimeSpan _ttl;
    private readonly Func<long> _clock;
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly LinkedList<string> _order = new();

    internal DecisionMemo(TimeSpan ttl, Func<long>? clock = null)
    {
        _ttl = ttl <= TimeSpan.Zero ? TimeSpan.Zero : (ttl > MaxTtl ? MaxTtl : ttl);
        _clock = clock ?? Stopwatch.GetTimestamp;
    }

    /// <summary>
    /// Emits a <see cref="ConfigClampedEvent"/> if the requested TTL was clamped
    /// (CONTRACT.md &#167;19.2 rule 6).
    /// </summary>
    /// <remarks>
    /// This is the clamp that matters most to get right: an operator who set a
    /// 60-second TTL believes their staleness bound is 60 seconds. It is five, and
    /// without this event nothing anywhere says so.
    /// </remarks>
    internal void ReportClamp(TimeSpan requested, TelemetryDispatcher telemetry)
    {
        if (!telemetry.Installed || requested <= TimeSpan.Zero || requested == _ttl)
        {
            return;
        }

        telemetry.Emit(new ConfigClampedEvent(
            nameof(Options.AxiamClientOptions.DecisionMemoTtl),
            requested.ToString(),
            _ttl.ToString(),
            "§17.1 rule 2"));
    }

    /// <summary>Whether this memo does anything. <c>false</c> for the default config.</summary>
    internal bool Enabled => _ttl > TimeSpan.Zero;

    /// <summary>The TTL after clamping.</summary>
    internal TimeSpan EffectiveTtl => _ttl;

    /// <summary>Entry count, for tests.</summary>
    internal int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>
    /// Builds the &#167;17.1 rule 3 key: all four components, absent distinguished from
    /// present.
    /// </summary>
    internal static string Key(Guid? subjectId, Guid resourceId, string action, string? scope)
    {
        // Plain concatenation: the separator is what makes this unambiguous, and a
        // hand-rolled span build would trade clarity for nothing on a path that
        // already costs an HTTP round trip when it misses.
        string subject = subjectId?.ToString() ?? Absent.ToString();
        string scopePart = scope ?? Absent.ToString();
        return string.Join(Separator, subject, resourceId.ToString(), action, scopePart);
    }

    /// <summary>A live decision for <paramref name="key"/>, if memoized and unexpired.</summary>
    internal AccessDecision? Get(string key)
    {
        if (!Enabled)
        {
            return null;
        }

        lock (_gate)
        {
            if (!_entries.TryGetValue(key, out Entry entry))
            {
                return null;
            }

            if (Stopwatch.GetElapsedTime(entry.StoredAt, _clock()) >= _ttl)
            {
                _entries.Remove(key);
                _order.Remove(entry.Node);
                return null;
            }

            // Returned whole, including ReasonCode: §17.1 rule 5 forbids returning
            // Allowed while dropping the code, which would make the field
            // intermittently absent — worse than never having had it.
            return entry.Decision;
        }
    }

    /// <summary>
    /// Memoizes a decision the server actually returned.
    /// </summary>
    /// <remarks>
    /// Callers must only reach here on success. &#167;17.1 rule 7 forbids
    /// negative-caching a failure: memoizing a transport error as a deny would turn a
    /// blip into a TTL-long outage, and memoizing it as an allow is unthinkable.
    /// </remarks>
    internal void Put(string key, AccessDecision decision)
    {
        if (!Enabled)
        {
            return;
        }

        lock (_gate)
        {
            if (_entries.TryGetValue(key, out Entry existing))
            {
                _order.Remove(existing.Node);
                _entries.Remove(key);
            }

            LinkedListNode<string> node = _order.AddLast(key);
            _entries[key] = new Entry(decision, _clock(), node);

            while (_entries.Count > MaxEntries)
            {
                LinkedListNode<string>? oldest = _order.First;
                if (oldest is null)
                {
                    break;
                }

                _order.RemoveFirst();
                _entries.Remove(oldest.Value);
            }
        }
    }

    /// <summary>
    /// Drops every entry (&#167;17.1 rule 9).
    /// </summary>
    /// <remarks>
    /// Called on login, verifyMfa, refresh and logout. Entries are keyed by subject,
    /// not by session, so a re-authentication as a <em>different</em> principal would
    /// otherwise read the previous principal's decisions.
    /// </remarks>
    internal void Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
            _order.Clear();
        }
    }

    private readonly struct Entry
    {
        internal Entry(AccessDecision decision, long storedAt, LinkedListNode<string> node)
        {
            Decision = decision;
            StoredAt = storedAt;
            Node = node;
        }

        internal AccessDecision Decision { get; }

        internal long StoredAt { get; }

        internal LinkedListNode<string> Node { get; }
    }
}
