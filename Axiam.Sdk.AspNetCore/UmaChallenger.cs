using System;
using Axiam.Sdk;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// A configured <c>WWW-Authenticate: UMA</c> challenge emitter (CONTRACT.md
/// &#167;20.3, emit half).
/// </summary>
/// <remarks>
/// <para>Register one with
/// <see cref="ServiceCollectionExtensions.AddAxiamUmaChallenge"/> and a
/// <c>[Authorize(Policy=…)]</c> denial stops being a bare 403:
/// <see cref="AxiamPolicyHandler"/> mints a fresh permission ticket for the
/// action the caller lacked and
/// <see cref="AxiamAuthorizationMiddlewareResultHandler"/> returns it in the
/// header, so a UMA-aware client knows where to go for authority instead of only
/// being told "no".</para>
///
/// <para><b>Opt-in, and deliberately so.</b> Emitting a challenge means minting
/// a credential — a wire call to the Protection API, and a live ticket, produced
/// on a path the caller did not explicitly request. A handler that did that on
/// every denial by default would turn each unauthorized request into a
/// Protection API call, which is a denial-of-service amplifier pointed at your
/// own authorization server. So it happens only where an application registered
/// one.</para>
///
/// <para><b>Failure is not escalation.</b> If minting fails — the PAT expired,
/// the Protection API is down, the resource declares none of the requested
/// scopes — the denial still surfaces as an ordinary 403 without a challenge. A
/// caller who was going to be refused is refused either way; letting a
/// Protection API outage turn a deny into a 503 would hand the outage a second
/// consequence, and letting it turn into an allow would be a security bug.</para>
/// </remarks>
public sealed class UmaChallenger
{
    /// <summary>Constructs a challenger.</summary>
    /// <param name="realm">The protection realm to name in the header.</param>
    /// <param name="asUri">
    /// The authorization server to send the caller to — normally this
    /// deployment's issuer, read from discovery rather than concatenated by hand
    /// (&#167;12.3 rule 6).
    /// </param>
    /// <param name="pat">
    /// A Protection API Token: a <i>client-credentials</i> token carrying the
    /// <c>uma_protection</c> scope (&#167;20.2 rule 1). A user token cannot stand
    /// in — a minted ticket is bound to the <c>client_id</c> that minted it.
    /// </param>
    public UmaChallenger(string realm, string asUri, Sensitive<string> pat)
    {
        Realm = realm ?? throw new ArgumentNullException(nameof(realm));
        AsUri = asUri ?? throw new ArgumentNullException(nameof(asUri));
        Pat = pat;
    }

    /// <summary>The protection realm named in the header.</summary>
    public string Realm { get; }

    /// <summary>The authorization server the header nominates.</summary>
    public string AsUri { get; }

    /// <summary>The Protection API Token used to mint tickets.</summary>
    public Sensitive<string> Pat { get; }

    /// <summary>
    /// Renders without the PAT (&#167;7): a challenger is configuration an
    /// application may reasonably log, and the credential inside it is not.
    /// </summary>
    /// <returns>A redacted description.</returns>
    public override string ToString() => $"UmaChallenger(Realm={Realm}, AsUri={AsUri}, Pat={Pat})";
}
