namespace Axiam.Sdk.Core;

/// <summary>
/// The full outcome of an access check, including the CONTRACT.md &#167;11 rule 9
/// <c>reason_code</c>.
/// </summary>
/// <remarks>
/// <see cref="Rest.AuthzRestClient.CheckAccessAsync"/> and <see cref="Rest.AuthzRestClient.BatchCheckAsync"/> return bare
/// <see cref="bool"/>s that predate this field and cannot carry it; use
/// <see cref="Rest.AuthzRestClient.CheckAccessDecisionAsync"/> / <see cref="Rest.AuthzRestClient.BatchCheckDecisionsAsync"/> when the
/// distinction matters.
/// </remarks>
/// <param name="Allowed">
/// Whether the checked action is permitted. <b>This property alone carries the outcome</b> —
/// <paramref name="ReasonCode"/> explains it and never contradicts it.
/// </param>
/// <param name="Reason">The server's human-readable explanation, when it sent one.</param>
/// <param name="ReasonCode">
/// <see cref="AxiamReasonCode.Allowed"/>, <see cref="AxiamReasonCode.NoGrant"/> or
/// <see cref="AxiamReasonCode.DeniedByRule"/>.
/// <para>
/// <b>The two refusals mean opposite things to the person on the other end.</b>
/// <c>no_grant</c> says <i>ask an admin for access</i>; <c>denied_by_rule</c> says <i>an admin
/// has already decided</i>. An application that cannot tell them apart sends users to raise
/// tickets that will be refused — which is why the contract forbids collapsing them into a bare
/// <see langword="false"/>.
/// </para>
/// <para>
/// <see langword="null"/> when the server omits the field, so a newer SDK against an older
/// server degrades rather than failing. An unrecognised value is surfaced verbatim and never
/// changes <paramref name="Allowed"/> — which is why this is a <see cref="string"/> rather than
/// an enum.
/// </para>
/// </param>
public sealed record AccessDecision(bool Allowed, string? Reason, string? ReasonCode);

/// <summary>
/// The three <c>reason_code</c> values CONTRACT.md &#167;11 rule 9 defines.
/// </summary>
/// <remarks>
/// Constants rather than an <c>enum</c>, so an unrecognised server value is still a valid
/// <see cref="AccessDecision.ReasonCode"/> and reaches the caller — an enum would force the SDK to
/// drop what it cannot name.
/// </remarks>
public static class AxiamReasonCode
{
    /// <summary>An allow grant matched and no deny did.</summary>
    public const string Allowed = "allowed";

    /// <summary>Nothing matched — default deny. <i>Ask an admin for access.</i></summary>
    public const string NoGrant = "no_grant";

    /// <summary>
    /// An explicit deny rule matched and overrode any allow. <i>An admin has already decided.</i>
    /// </summary>
    public const string DeniedByRule = "denied_by_rule";
}
