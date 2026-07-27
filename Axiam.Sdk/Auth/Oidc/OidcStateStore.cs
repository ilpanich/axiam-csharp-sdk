using System.Collections.Concurrent;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Auth.Oidc;

// IOidcStateStore + MemoryOidcStateStore (CONTRACT.md §12.3 rule 1).
//
// STRICTLY OPTIONAL. The nine §12 operations never touch a store themselves: OidcBegin and
// OidcExchangeAsync are stateless by contract, and the caller normally keeps
// state/nonce/code_verifier in its own HTTP session. This store exists for the ASP.NET Core
// login/callback glue (Axiam.Sdk.AspNetCore's MapAxiamOidcLogin), where a login and its
// callback are two separate HTTP requests with nothing but a `state` value linking them.
//
// Semantics mirror the server's `federation_login_state` table: 10-minute TTL, single-use
// consume.

/// <summary>
/// The tuple an <see cref="IOidcStateStore"/> holds for one in-flight login.
/// </summary>
/// <remarks>
/// <see cref="CodeVerifier"/> stays <see cref="Sensitive{T}"/> while stored (&#167;12.5: the
/// verifier is secret for its whole lifetime, "including &#8230; in any
/// <see cref="IOidcStateStore"/> entry").
/// </remarks>
public sealed record OidcStateEntry(
    string State,
    string Nonce,
    Sensitive<string> CodeVerifier,
    string RedirectUri,
    string? ReturnTo = null);

/// <summary>
/// An OPTIONAL server-side store for in-flight <c>OidcBegin</c> state (CONTRACT.md &#167;12.3
/// rule 1).
/// </summary>
/// <remarks>
/// Implement this to back the ASP.NET Core login/callback endpoints
/// (<c>MapAxiamOidcLogin</c>) with your own storage (Redis, a database, an encrypted
/// cookie). Two invariants are normative:
/// <list type="number">
/// <item><description>Single-use: <see cref="ConsumeAsync"/> MUST return the entry AND
/// delete it atomically, so a replayed callback cannot reuse a state.</description></item>
/// <item><description>Expiry: an entry older than the store's TTL (10 minutes, at most —
/// <see cref="MemoryOidcStateStore.MaxTtl"/>) MUST NOT be returned.</description></item>
/// </list>
/// </remarks>
public interface IOidcStateStore
{
    /// <summary>Persists <paramref name="entry"/>, keyed by its
    /// <see cref="OidcStateEntry.State"/>, starting its TTL now.</summary>
    Task SaveAsync(OidcStateEntry entry, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically fetches AND REMOVES the entry for <paramref name="state"/>. Returns
    /// <c>null</c> when the state is unknown, already consumed, or expired — three cases a
    /// caller MUST treat identically (as a failed login), because distinguishing them leaks
    /// whether a state ever existed.
    /// </summary>
    Task<OidcStateEntry?> ConsumeAsync(string state, CancellationToken cancellationToken = default);
}

/// <summary>
/// An in-memory reference implementation of <see cref="IOidcStateStore"/> (CONTRACT.md
/// &#167;12.3 rule 1): per-instance (never process-global/static), single-use, TTL-bounded,
/// backed by a <see cref="ConcurrentDictionary{TKey,TValue}"/>.
/// </summary>
/// <remarks>
/// Expired entries are dropped lazily on <see cref="SaveAsync"/>/<see cref="ConsumeAsync"/>
/// — there is NO background timer/thread, since a library must not keep the host process
/// alive on its own. Suitable for a single-process app and for tests. A multi-instance
/// deployment needs a shared store (Redis, a database) — implement
/// <see cref="IOidcStateStore"/> directly for that; nothing in this SDK assumes this type.
/// </remarks>
public sealed class MemoryOidcStateStore : IOidcStateStore
{
    /// <summary>
    /// The CONTRACT.md &#167;12.3 rule 1 MAXIMUM TTL for stored login state: 10 minutes,
    /// matching the server's <c>federation_login_state</c> row lifetime (D-22).
    /// </summary>
    public static readonly TimeSpan MaxTtl = TimeSpan.FromMinutes(10);

    private readonly TimeSpan _ttl;
    private readonly ConcurrentDictionary<string, (OidcStateEntry Entry, DateTimeOffset ExpiresAt)> _entries = new();

    /// <summary>
    /// Constructs a <see cref="MemoryOidcStateStore"/>. <paramref name="ttl"/> is the entry
    /// lifetime; <c>null</c>, zero, negative, or greater than <see cref="MaxTtl"/> is
    /// CLAMPED to <see cref="MaxTtl"/> — CONTRACT.md &#167;12.3 rule 1 fixes that as the
    /// maximum, while a shorter TTL is honored verbatim (useful in tests).
    /// </summary>
    public MemoryOidcStateStore(TimeSpan? ttl = null)
    {
        TimeSpan requested = ttl ?? MaxTtl;
        _ttl = requested <= TimeSpan.Zero || requested > MaxTtl ? MaxTtl : requested;
    }

    /// <inheritdoc />
    public Task SaveAsync(OidcStateEntry entry, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        Sweep();
        _entries[entry.State] = (entry, DateTimeOffset.UtcNow + _ttl);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Removal happens BEFORE the expiry check, so even an expired hit is removed rather
    /// than left to accumulate, and a second call can never return the same entry twice
    /// regardless of timing.
    /// </remarks>
    public Task<OidcStateEntry?> ConsumeAsync(string state, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(state);
        if (!_entries.TryRemove(state, out var held))
        {
            return Task.FromResult<OidcStateEntry?>(null);
        }
        return Task.FromResult(DateTimeOffset.UtcNow > held.ExpiresAt ? null : held.Entry);
    }

    /// <summary>The number of unexpired entries currently held. Intended for tests and
    /// metrics.</summary>
    public int Size
    {
        get
        {
            Sweep();
            return _entries.Count;
        }
    }

    /// <summary>Drops every expired entry. Lazy housekeeping only — no background timer.</summary>
    private void Sweep()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        foreach (var kvp in _entries)
        {
            if (now > kvp.Value.ExpiresAt)
            {
                _entries.TryRemove(kvp.Key, out _);
            }
        }
    }
}
