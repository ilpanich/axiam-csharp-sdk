using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace Axiam.Sdk.Reactor;

/// <summary>
/// What the server does when an interceptor produces no usable reply
/// (<c>sdks/CONTRACT.md</c> &#167;22.8).
///
/// <para>
/// "No usable reply" is one closed set and every member takes the same path: timeout,
/// transport failure, budget exhausted before this reactor was reached, the per-tenant
/// in-flight cap breached, and <em>every</em> &#167;22.4 rejection — including a valid
/// signature carrying a forbidden patch field.
/// </para>
/// </summary>
public enum FailurePolicy
{
    /// <summary>Proceed as if the reactor had replied <c>allow</c>.</summary>
    FailOpen,

    /// <summary>Deny the underlying operation, with an audited reason naming the failure.</summary>
    FailClosed,
}

/// <summary>Wire-form conversions for <see cref="FailurePolicy"/>.</summary>
public static class FailurePolicyExtensions
{
    /// <summary>Returns the lowercase wire form the AXIAM API uses.</summary>
    /// <param name="policy">The policy.</param>
    /// <returns><c>"fail_open"</c> or <c>"fail_closed"</c>.</returns>
    public static string ToWire(this FailurePolicy policy) =>
        policy == FailurePolicy.FailClosed ? "fail_closed" : "fail_open";

    /// <summary>Parses a wire form back into a policy.</summary>
    /// <param name="raw">The wire string, e.g. <c>"fail_closed"</c>; may be <c>null</c>.</param>
    /// <returns>The matching policy, or <c>null</c> when <paramref name="raw"/> names none.</returns>
    public static FailurePolicy? FromWire(string? raw) => raw?.Trim().ToLowerInvariant() switch
    {
        "fail_open" => FailurePolicy.FailOpen,
        "fail_closed" => FailurePolicy.FailClosed,
        _ => null,
    };
}

/// <summary>
/// One hookable event: its name, what a reactor may change, and what happens when the
/// reactor does not answer (<c>sdks/CONTRACT.md</c> &#167;22.5).
///
/// <para>
/// Mirrors the server's <c>ReactorEventSpec</c> in
/// <c>crates/axiam-core/src/models/reactor.rs</c>, which is the single source of truth.
/// The live copy is served at <c>GET /api/v1/reactors/events</c>; this one is here so a
/// wire contract does not require a network call to be understood.
/// </para>
/// </summary>
public sealed class ReactorEventSpec
{
    internal ReactorEventSpec(
        string name,
        bool interceptable,
        bool mutable,
        IReadOnlyList<string> mutableFields,
        FailurePolicy defaultFailurePolicy,
        string description)
    {
        Name = name;
        Interceptable = interceptable;
        Mutable = mutable;
        MutableFields = new ReadOnlyCollection<string>(mutableFields.ToList());
        DefaultFailurePolicy = defaultFailurePolicy;
        Description = description;
    }

    /// <summary>Wire name, and the second half of the routing key (<c>&lt;tenant_id&gt;.&lt;event&gt;</c>).</summary>
    public string Name { get; }

    /// <summary>
    /// Whether an interceptor may register for this event at all; <c>false</c> means
    /// listen-only.
    /// </summary>
    public bool Interceptable { get; }

    /// <summary>Whether an interceptor's reply may carry a <c>patch</c>.</summary>
    public bool Mutable { get; }

    /// <summary>
    /// The complete allow-list: exact field names, or an entry ending in <c>.</c> denoting a
    /// namespace prefix. See <see cref="PatchFieldAllowed"/>.
    /// </summary>
    public IReadOnlyList<string> MutableFields { get; }

    /// <summary>The policy a registration inherits when it names none.</summary>
    public FailurePolicy DefaultFailurePolicy { get; }

    /// <summary>One line, as the admin UI shows it.</summary>
    public string Description { get; }

    /// <summary>
    /// Whether <paramref name="field"/> may appear in a <c>patch</c> for this event.
    ///
    /// <para>
    /// <b>The namespace-prefix rule.</b> An allow-list entry ending in <c>.</c> is a
    /// namespace prefix, and it matches a field that starts with the entry <em>and has at
    /// least one character after the dot</em>. So <c>ext.</c> admits <c>ext.department</c>
    /// and <c>ext.a.b.c</c>, and refuses <c>ext.</c> itself (it names the namespace, not a
    /// claim), <c>ext</c>, <c>extra</c>, <c>external_id</c> and
    /// <c>evil.ext.department</c>.
    /// </para>
    /// <para>
    /// Everything else follows from that one rule: <c>token.pre_issue</c> cannot reach
    /// <c>iss</c>, <c>sub</c>, <c>aud</c>, <c>exp</c>, <c>iat</c>, <c>nbf</c>, <c>jti</c>,
    /// <c>scope</c>, <c>scp</c>, <c>azp</c>, <c>act</c> or <c>client_id</c>, because none
    /// of them begins with <c>ext.</c>. A hook that can rewrite <c>sub</c> is a hook that
    /// can mint a token for anyone, and a <em>correctly signed</em> reply setting
    /// <c>sub</c> is refused exactly as a forged one is.
    /// </para>
    /// <para>
    /// This is a read-only predicate. It exists so a reactor author can check a key
    /// <em>before</em> writing the handler — it is <b>never</b> used to filter a handler's
    /// patch down to the allowed subset, which &#167;22.4 rule 1 forbids.
    /// </para>
    /// </summary>
    /// <param name="field">The patch key to test.</param>
    /// <returns><c>true</c> when the server would accept <paramref name="field"/> here.</returns>
    public bool PatchFieldAllowed(string? field)
    {
        if (!Mutable || field is null)
        {
            return false;
        }

        foreach (string allowed in MutableFields)
        {
            if (allowed.EndsWith('.'))
            {
                // "at least one character after the dot" — `ext.` itself is not a claim
                // name, and admitting it would let a reactor set a claim literally
                // called `ext.`.
                if (field.Length > allowed.Length && field.StartsWith(allowed, StringComparison.Ordinal))
                {
                    return true;
                }
            }
            else if (string.Equals(field, allowed, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>
/// The v1 reactor event registry (<c>sdks/CONTRACT.md</c> &#167;22.5) — five interceptable
/// events, their mutable-field allow-lists, and their default failure policies.
///
/// <para>
/// The live copy is served at <c>GET /api/v1/reactors/events</c> and is the one an admin
/// UI SHOULD read. This constant list is the same data, restated because a wire contract
/// that requires a network call to be understood is not a contract.
/// </para>
/// <para>
/// <b>&#167;22.7 hot-path exclusion.</b> <c>authz.check</c>, <c>authz.check_batch</c> and
/// <c>token.introspect</c> are not hookable and are absent from <see cref="Registry"/> and
/// from every constant below. That absence is asserted by a test, not documented by a
/// comment. This SDK also offers no client-side interceptor, middleware hook or callback
/// presenting itself as the reactor equivalent for those operations. An application that
/// needs external input on an authorization decision writes a <b>deny grant</b>, which the
/// engine evaluates in the hot path at hot-path cost.
/// </para>
/// </summary>
public static class ReactorEvents
{
    /// <summary>Before an access token is minted. Mutable: the <c>ext.</c> claim namespace.</summary>
    public const string TokenPreIssue = "token.pre_issue";

    /// <summary>
    /// After credentials verify, before a session is issued. Veto, or <c>require_mfa</c>
    /// step-up.
    ///
    /// <para>
    /// Covers <em>every</em> interactive sign-in — password authentication, SAML ACS and
    /// the OIDC callback. MFA completion and the WebAuthn <c>authenticate/finish</c>
    /// ceremony are not separate firings: both continue a login that was already gated at
    /// its first step.
    /// </para>
    /// <para>
    /// The federated paths have no step-up branch, so a <c>require_mfa</c> answer on a SAML
    /// or OIDC sign-in is <b>refused</b> (the sign-in fails) rather than silently dropped.
    /// A reactor that needs step-up there must answer <c>deny</c> and drive enrolment out
    /// of band.
    /// </para>
    /// </summary>
    public const string LoginPostAuth = "login.post_auth";

    /// <summary>Before a user row is written. Mutable: <c>username</c>, <c>email</c>, <c>metadata.</c>.</summary>
    public const string UserPreCreate = "user.pre_create";

    /// <summary>Before a user row is updated. Mutable: <c>username</c>, <c>email</c>, <c>metadata.</c>.</summary>
    public const string UserPreUpdate = "user.pre_update";

    /// <summary>Before a role or permission is assigned (four-eyes workflows). Veto only.</summary>
    public const string GrantPreAssign = "grant.pre_assign";

    /// <summary>
    /// Every hookable event in v1, in registry order. Note what is <em>not</em> here: see
    /// the &#167;22.7 note on this class.
    /// </summary>
    public static readonly IReadOnlyList<ReactorEventSpec> Registry = new ReadOnlyCollection<ReactorEventSpec>(
        new List<ReactorEventSpec>
        {
            new(
                TokenPreIssue, true, true, new[] { "ext." }, FailurePolicy.FailOpen,
                "Enrich or veto token issuance. May add claims under `ext.` only."),
            new(
                LoginPostAuth, true, false, Array.Empty<string>(), FailurePolicy.FailClosed,
                "After credentials verify, before session issuance: veto or require step-up MFA."),
            new(
                UserPreCreate, true, true, new[] { "username", "email", "metadata." }, FailurePolicy.FailClosed,
                "Validate or normalize a new user's profile fields."),
            new(
                UserPreUpdate, true, true, new[] { "username", "email", "metadata." }, FailurePolicy.FailClosed,
                "Validate or normalize a profile update."),
            new(
                GrantPreAssign, true, false, Array.Empty<string>(), FailurePolicy.FailClosed,
                "Veto a role or permission assignment (four-eyes workflows). Veto-only."),
        });

    /// <summary>Looks an event up by wire name.</summary>
    /// <param name="name">The event name, e.g. <c>token.pre_issue</c>; may be <c>null</c>.</param>
    /// <returns>
    /// The spec, or <c>null</c> when <paramref name="name"/> is not in the registry. An
    /// event outside the registry dispatches to nothing and resolves to <c>allow</c>
    /// server-side, which is what makes &#167;22.7's hot-path exclusion structural rather
    /// than advisory.
    /// </returns>
    public static ReactorEventSpec? Spec(string? name) =>
        name is null ? null : Registry.FirstOrDefault(spec => string.Equals(spec.Name, name, StringComparison.Ordinal));

    /// <summary>
    /// The <c>failure_policy</c> a registration should get when it names none: the
    /// <b>strictest</b> default among the events it subscribes to
    /// (<c>sdks/CONTRACT.md</c> &#167;22.8).
    ///
    /// <para>
    /// A reactor registered for both <c>token.pre_issue</c> (open) and
    /// <c>login.post_auth</c> (closed) can veto a login, so it inherits
    /// <c>fail_closed</c> — in either array order. Taking the first event's default would
    /// let the order of a JSON array decide whether an unreachable fraud check passes.
    /// </para>
    /// <para>
    /// Unknown names are ignored here rather than defaulted: the server refuses them at
    /// registration, and guessing a policy for an event that cannot exist would only hide
    /// that refusal.
    /// </para>
    /// </summary>
    /// <param name="events">The registration's event names.</param>
    /// <returns>
    /// <see cref="FailurePolicy.FailClosed"/> when any named event defaults closed,
    /// <see cref="FailurePolicy.FailOpen"/> only when all of them default open.
    /// </returns>
    public static FailurePolicy DefaultFailurePolicyFor(IEnumerable<string> events)
    {
        ArgumentNullException.ThrowIfNull(events);
        foreach (string name in events)
        {
            if (Spec(name) is { DefaultFailurePolicy: FailurePolicy.FailClosed })
            {
                return FailurePolicy.FailClosed;
            }
        }

        return FailurePolicy.FailOpen;
    }
}
