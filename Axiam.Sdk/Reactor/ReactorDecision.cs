using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Axiam.Sdk.Reactor;

/// <summary>
/// What a handler decided about one event (<c>sdks/CONTRACT.md</c> &#167;22.4).
///
/// <para>
/// A closed hierarchy of three answers — the abstract base has a private
/// protected constructor, so nothing outside this file can add a fourth.
/// Three of &#167;22.4's rules are encoded here <b>structurally</b> rather than by
/// documentation, because each is a rule an implementation gets wrong by being
/// permissive:
/// </para>
/// <list type="number">
/// <item><description><b><c>allow</c> and <c>patch</c> are mutually exclusive.</b>
/// There is no way to attach a patch to <see cref="Allow"/> — a mutation is a
/// <see cref="Mutate"/>, which serializes <c>decision: "mutate"</c>. A patch on an
/// <c>allow</c> is a reply whose author and whose reader disagree about what will
/// happen; the server refuses it rather than resolving it.</description></item>
/// <item><description><b>An empty mutation is malformed.</b> <see cref="Mutate"/>
/// refuses to be constructed with an empty patch, so it cannot be put on the wire and
/// rejected as <c>malformed_mutation</c> at the far end.</description></item>
/// <item><description><b><c>require_mfa</c> rides on <c>allow</c>.</b> It is a flag on
/// <see cref="Allow"/>, not a fourth decision, and it is valid on
/// <c>login.post_auth</c> only.</description></item>
/// </list>
/// <para>
/// What is <em>not</em> encoded here is patch filtering. A patch containing a forbidden
/// key is sent unfiltered and rejected by the server (&#167;22.4 rule 1): dropping the bad
/// key would leave the reactor author believing a field was set when it was silently
/// discarded.
/// </para>
/// </summary>
public abstract class ReactorDecision
{
    private protected ReactorDecision(string wire) => Wire = wire;

    /// <summary>The lowercase <c>decision</c> value this answer serializes as.</summary>
    public string Wire { get; }

    /// <summary>Proceed unchanged.</summary>
    /// <returns>An <see cref="Allow"/> with no step-up demand.</returns>
    public static ReactorDecision Allowed() => new Allow(false);

    /// <summary>
    /// Proceed, but only after step-up authentication (<c>login.post_auth</c> only).
    ///
    /// <para>
    /// Step-up is <b>sticky</b> across the chain: once any reactor demands it, no later
    /// reactor can clear it.
    /// </para>
    /// </summary>
    /// <returns>An <see cref="Allow"/> carrying <c>require_mfa: true</c>.</returns>
    public static ReactorDecision AllowRequiringStepUp() => new Allow(true);

    /// <summary>Refuse, with an audited reason.</summary>
    /// <param name="reason">
    /// Why, for the audit trail; may be <c>null</c>. A deny with no reason still denies —
    /// the server substitutes <c>"denied by reactor"</c> when it is absent.
    /// </param>
    /// <returns>A <see cref="Deny"/>.</returns>
    public static ReactorDecision Denied(string? reason = null) => new Deny(reason);

    /// <summary>Proceed with a mutation.</summary>
    /// <param name="patch">A non-empty flat map of field name to string value.</param>
    /// <returns>A <see cref="Mutate"/>.</returns>
    /// <exception cref="ArgumentException">When <paramref name="patch"/> is empty.</exception>
    /// <exception cref="ArgumentNullException">When <paramref name="patch"/> is <c>null</c>.</exception>
    public static ReactorDecision Mutated(IReadOnlyDictionary<string, string> patch) => new Mutate(patch);

    /// <summary>Proceed unchanged, optionally demanding step-up authentication.</summary>
    public sealed class Allow : ReactorDecision
    {
        internal Allow(bool requireMfa)
            : base("allow") => RequireMfa = requireMfa;

        /// <summary>
        /// When <c>true</c>, proceed only after step-up authentication. Valid on
        /// <c>login.post_auth</c> <b>only</b>; the server rejects it on any other event as
        /// <c>require_mfa_not_supported</c>, before it even looks at the decision.
        /// Serialized only when <c>true</c> — a reply carrying <c>"require_mfa": false</c>
        /// produces different canonical bytes and therefore a different MAC.
        /// </summary>
        public bool RequireMfa { get; }
    }

    /// <summary>Refuse the underlying operation.</summary>
    public sealed class Deny : ReactorDecision
    {
        internal Deny(string? reason)
            : base("deny") => Reason = reason;

        /// <summary>
        /// Audited on the server. <c>null</c> omits the field from the signed bytes — a
        /// deny with no reason still denies, because the reason is for the audit trail,
        /// not for the decision.
        /// </summary>
        public string? Reason { get; }
    }

    /// <summary>
    /// Proceed, applying <see cref="Patch"/>. Valid on a mutable event only; the server
    /// rejects it as <c>not_mutable</c> on a veto-only one.
    /// </summary>
    public sealed class Mutate : ReactorDecision
    {
        internal Mutate(IReadOnlyDictionary<string, string> patch)
            : base("mutate")
        {
            ArgumentNullException.ThrowIfNull(patch);
            if (patch.Count == 0)
            {
                throw new ArgumentException(
                    "a mutate decision needs a non-empty patch (CONTRACT.md §22.4: an empty patch is " +
                    "rejected as malformed_mutation); return ReactorDecision.Allowed() to change nothing",
                    nameof(patch));
            }

            Patch = new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(patch, StringComparer.Ordinal));
        }

        /// <summary>
        /// A flat, non-empty map of string to string. There is no nested or typed patch in
        /// v1. Sent <b>unfiltered</b>: one forbidden key rejects the whole patch, including
        /// the fields that would have been fine.
        /// </summary>
        public IReadOnlyDictionary<string, string> Patch { get; }
    }
}
