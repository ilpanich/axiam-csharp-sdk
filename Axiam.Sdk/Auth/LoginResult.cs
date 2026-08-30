using Axiam.Sdk.Core;

namespace Axiam.Sdk.Auth;

/// <summary>
/// Outcome of <c>LoginAsync</c>/<c>VerifyMfaAsync</c> (CONTRACT.md &#167;1). MFA-required
/// is an expected outcome represented as a flag — never thrown as an exception: callers
/// MUST check <see cref="MfaRequired"/> before assuming a session was established.
/// Mirrors the Java sibling's <c>LoginResult</c> (20-03) field shape.
/// </summary>
/// <param name="MfaRequired">
/// <c>true</c> when the server responded with an MFA challenge instead of a completed
/// login.
/// </param>
/// <param name="ChallengeToken">
/// The opaque MFA challenge token to pass to <c>VerifyMfaAsync</c>; populated only when
/// <paramref name="MfaRequired"/> is <c>true</c>. Wrapped in <see cref="Sensitive{T}"/>
/// per CONTRACT.md &#167;7's blanket token-field rule — every token-carrying field in the
/// SDK is redacted from <see cref="object.ToString"/>/JSON/logs, with no single field
/// exempted as "not sensitive enough."
/// </param>
/// <param name="MfaSetupRequired">
/// <c>true</c> when the tenant requires MFA and this account has no factor yet — the
/// server answered <c>403</c> carrying <c>mfa_setup_required</c> and a setup token
/// (CONTRACT.md &#167;25.2 rule 1). <b>Not a failure</b>: it is the third login outcome,
/// and a caller that only branches on <paramref name="MfaRequired"/> reports a successful
/// login that has no session the moment a tenant turns required MFA on.
/// </param>
/// <param name="SetupToken">
/// The setup token to pass to <c>MfaSetupEnrollAsync</c> and <c>MfaSetupConfirmAsync</c>;
/// populated only when <paramref name="MfaSetupRequired"/> is <c>true</c>. There is no
/// session yet — this token IS the credential for those two calls.
/// </param>
/// <param name="OrganizationLevel">
/// <c>true</c> when the account that just signed in is an <b>organization-level</b>
/// principal (CONTRACT.md &#167;5.2) — one whose record lives in its organization's
/// reserved tenant, so its global grants apply in every tenant of that organization, and
/// which can act on a different one by sending a different <c>X-Axiam-Tenant</c> on the next
/// request. An ordinary tenant principal is a principal of exactly one tenant and gets a
/// <c>403</c> for the same header change, so check this <i>before</i> offering a tenant
/// switch rather than discovering the answer from a failed request.
/// <c>false</c> against a server older than contract 1.31, and <c>false</c> on the two
/// pending outcomes, where no principal has been established yet.
/// Since contract 1.35 that reach can be narrowed per assignment, so this flag alone no
/// longer decides what to offer: consult <see cref="PrincipalScope.ReachableTenantIds"/>
/// as well (&#167;5.2.3 rule 3).
/// </param>
/// <param name="Scope">
/// Where this principal lives and how far its roles reach (CONTRACT.md &#167;5.2.2,
/// &#167;5.2.3). <c>null</c> on the two pending outcomes and against a server older than
/// contract 1.34, which reports none of it.
/// </param>
public sealed record LoginResult(
    bool MfaRequired,
    Sensitive<string>? ChallengeToken = null,
    bool MfaSetupRequired = false,
    Sensitive<string>? SetupToken = null,
    bool OrganizationLevel = false,
    PrincipalScope? Scope = null);
