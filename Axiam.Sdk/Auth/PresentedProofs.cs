namespace Axiam.Sdk.Auth;

/// <summary>
/// What the caller proved about <b>this</b> connection and <b>this</b> request, for
/// <see cref="JwksVerifier.VerifyTokenBinding"/>.
/// </summary>
/// <remarks>
/// A record rather than two string parameters on purpose: two same-typed nullable
/// thumbprints are exactly the pair a positional call transposes silently, and transposing
/// them would check each proof against the wrong confirmation.
/// </remarks>
/// <param name="CertificateThumbprint">
/// The peer certificate's RFC 8705 &#167;3.1 <c>x5t#S256</c>, taken from the TLS connection
/// or from a <i>trusted</i> terminating proxy over a channel your application controls.
/// <b>Never</b> from a caller-settable request header: a forgeable input makes the whole
/// mechanism decorative.
/// </param>
/// <param name="DpopThumbprint">
/// The <c>jkt</c> of an <b>already verified</b> DPoP proof. Supply it only after checking
/// the proof's signature, <c>htm</c>, <c>htu</c>, <c>iat</c> and <c>jti</c> for this
/// request — <see cref="DpopVerifier.VerifyProof"/> does all ten &#167;21.7.2 checks and
/// returns exactly this value. A thumbprint lifted off an unverified proof would let a
/// proof captured from any other endpoint authorize this one.
/// </param>
public readonly record struct PresentedProofs(
    string? CertificateThumbprint = null,
    string? DpopThumbprint = null)
{
    /// <summary>Neither proof — the ordinary bearer case.</summary>
    /// <returns>A pair with both thumbprints absent.</returns>
    public static PresentedProofs None() => new();

    /// <summary>Only a client certificate was presented.</summary>
    /// <param name="thumbprint">The peer certificate's <c>x5t#S256</c>.</param>
    /// <returns>A pair carrying only the certificate thumbprint.</returns>
    public static PresentedProofs Certificate(string thumbprint) => new(thumbprint);

    /// <summary>Only a verified DPoP proof was presented.</summary>
    /// <param name="thumbprint">The <c>jkt</c> of an already verified proof.</param>
    /// <returns>A pair carrying only the DPoP thumbprint.</returns>
    public static PresentedProofs Dpop(string thumbprint) => new(null, thumbprint);
}
