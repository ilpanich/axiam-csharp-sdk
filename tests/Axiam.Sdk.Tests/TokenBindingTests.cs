using System.Text.Json;
using Axiam.Sdk.Auth;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>CONTRACT.md &#167;10.1 rule 9 extended for DPoP (contract 1.16).</summary>
public class TokenBindingTests
{
    private const string Thumb = "bwcK0esC3yEWCTuAFrDPBqZ_hvIn0UbmJKlSjMbGZKM";
    private const string Jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    private const string OtherJkt = "sBjflhaR2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static JsonElement Claims(string? json) =>
        JsonDocument.Parse(json is null ? """{"sub":"u"}""" : $$"""{"sub":"u","cnf":{{json}}}""")
            .RootElement.Clone();

    /// <summary>
    /// THE POSITIVE REGRESSION TEST, and the one this change is most likely to break: an
    /// unbound token must still pass with no certificate and no proof. The likeliest wrong
    /// implementation of rule 9 is one that starts demanding evidence from every caller.
    /// </summary>
    [Fact]
    public void UnboundTokenIsAcceptedWithNoProofsAtAll()
    {
        Assert.True(JwksVerifier.VerifyTokenBinding(Claims(null), PresentedProofs.None()));
        // ...and proofs it never asked for do not make it invalid.
        Assert.True(JwksVerifier.VerifyTokenBinding(Claims(null), new PresentedProofs(Thumb, Jkt)));
    }

    /// <summary>A DPoP-bound token accepts the matching key.</summary>
    [Fact]
    public void DpopBoundTokenAcceptsTheMatchingKey()
    {
        Assert.True(JwksVerifier.VerifyTokenBinding(
            Claims($$"""{"jkt":"{{Jkt}}"}"""), PresentedProofs.Dpop(Jkt)));
    }

    /// <summary>A DPoP-bound token is refused with no proof, or a proof by another key.</summary>
    [Fact]
    public void DpopBoundTokenIsRejectedWithoutAProofOrWithTheWrongKey()
    {
        Assert.False(JwksVerifier.VerifyTokenBinding(
            Claims($$"""{"jkt":"{{Jkt}}"}"""), PresentedProofs.None()));
        Assert.False(JwksVerifier.VerifyTokenBinding(
            Claims($$"""{"jkt":"{{Jkt}}"}"""), PresentedProofs.Dpop(OtherJkt)));
    }

    /// <summary>A certificate-bound token behaves exactly as it did before contract 1.16.</summary>
    [Fact]
    public void CertificateBoundTokenIsUnchanged()
    {
        JsonElement claims = Claims($$"""{"x5t#S256":"{{Thumb}}"}""");

        Assert.True(JwksVerifier.VerifyTokenBinding(claims, PresentedProofs.Certificate(Thumb)));
        Assert.False(JwksVerifier.VerifyTokenBinding(claims, PresentedProofs.None()));
        Assert.False(JwksVerifier.VerifyTokenBinding(claims, PresentedProofs.Certificate(OtherJkt)));
    }

    /// <summary>
    /// BOTH NAMED IS A CONJUNCTION. An operator who turned on two constraints asked for
    /// two; satisfying the more convenient one is not compliance. Each half is asserted to
    /// fail alone, because "check whichever we can" is the likeliest wrong implementation.
    /// </summary>
    [Fact]
    public void CnfNamingBothMethodsRequiresBoth()
    {
        JsonElement both = Claims($$"""{"x5t#S256":"{{Thumb}}","jkt":"{{Jkt}}"}""");

        Assert.True(JwksVerifier.VerifyTokenBinding(both, new PresentedProofs(Thumb, Jkt)));

        Assert.False(JwksVerifier.VerifyTokenBinding(both, PresentedProofs.Certificate(Thumb)));
        Assert.False(JwksVerifier.VerifyTokenBinding(both, PresentedProofs.Dpop(Jkt)));
    }

    /// <summary>
    /// An empty <c>cnf</c> names nothing checkable and is refused, not read as unbound.
    /// Over gRPC this is also how proto3 delivers an empty <c>CnfClaim</c> message, which is
    /// why &#167;10.3 rule 3 spells it out separately.
    /// </summary>
    [Fact]
    public void EmptyCnfIsRefusedRatherThanReadAsUnbound()
    {
        Assert.False(JwksVerifier.VerifyTokenBinding(Claims("{}"), PresentedProofs.None()));
    }

    /// <summary>
    /// The narrow entry point refuses a DPoP-bound token rather than ignoring the <c>jkt</c>
    /// it cannot check. That refusal is what lets it stay in the API without becoming a
    /// downgrade path.
    /// </summary>
    [Fact]
    public void CertificateOnlyEntryPointRefusesDpopAndBothBoundTokens()
    {
        foreach (string? presented in new string?[] { null, Thumb })
        {
            Assert.False(JwksVerifier.VerifyCertificateBinding(
                Claims($$"""{"jkt":"{{Jkt}}"}"""), presented));
        }

        Assert.False(JwksVerifier.VerifyCertificateBinding(
            Claims($$"""{"x5t#S256":"{{Thumb}}","jkt":"{{Jkt}}"}"""), Thumb));
    }
}
