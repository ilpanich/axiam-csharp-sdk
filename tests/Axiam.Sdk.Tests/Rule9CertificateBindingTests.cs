using System;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Auth;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens
/// (contract 1.15, RFC 8705 §3 / RFC 7800).
/// </summary>
/// <remarks>
/// A token carrying <c>cnf</c> is not a bearer token and must not be accepted as one.
/// Three negatives and one positive — and the POSITIVE is the one that matters most:
/// rule 9 must not become "every caller must present a certificate", which would break
/// every deployment that does not use mTLS at all.
/// </remarks>
[Trait("Category", "Fast")]
public class Rule9CertificateBindingTests
{
    /// A real 43-character base64url x5t#S256, and a different one.
    private const string Thumbprint = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string OtherThumbprint = "bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18";

    private static JsonElement Claims(string json) =>
        JsonDocument.Parse(json).RootElement.Clone();

    private static JsonElement Unbound() =>
        Claims("""{"sub":"u","tenant_id":"t","exp":9999999999}""");

    /// <remarks>
    /// A raw literal plus <c>Replace</c> rather than an interpolated raw literal: the
    /// JSON's own trailing <c>}}</c> collides with <c>$$</c>'s interpolation braces
    /// (CS9007), and escalating to <c>$$$</c> would make the next brace in the fixture
    /// the same trap again. There is no interpolation here to get wrong.
    /// </remarks>
    private const string BoundTemplate =
        """{"sub":"u","tenant_id":"t","exp":9999999999,"cnf":{"x5t#S256":"THUMBPRINT"}}""";

    private static JsonElement Bound(string thumbprint) =>
        Claims(BoundTemplate.Replace("THUMBPRINT", thumbprint, StringComparison.Ordinal));

    /// The regression test that keeps rule 9 from becoming a certificate mandate.
    [Fact]
    public void UnboundTokenIsAcceptedWithOrWithoutACertificate()
    {
        Assert.True(JwksVerifier.VerifyCertificateBinding(Unbound(), null));
        Assert.True(JwksVerifier.VerifyCertificateBinding(Unbound(), Thumbprint));
    }

    [Fact]
    public void BoundTokenIsAcceptedWithItsOwnCertificate()
    {
        Assert.True(JwksVerifier.VerifyCertificateBinding(Bound(Thumbprint), Thumbprint));
    }

    [Fact]
    public void BoundTokenIsRejectedWithNoCertificate()
    {
        Assert.False(JwksVerifier.VerifyCertificateBinding(Bound(Thumbprint), null));
        Assert.False(JwksVerifier.VerifyCertificateBinding(Bound(Thumbprint), string.Empty));
    }

    [Fact]
    public void BoundTokenIsRejectedWithADifferentCertificate()
    {
        Assert.False(JwksVerifier.VerifyCertificateBinding(Bound(Thumbprint), OtherThumbprint));
    }

    /// <summary>
    /// The subtle one. A <c>cnf</c> naming a confirmation method this SDK cannot check is
    /// an unverifiable constraint, never <i>no</i> constraint — read the other way, a
    /// sender-constrained token silently degrades to a bearer token the day a newer AXIAM
    /// issues a confirmation this SDK predates.
    /// </summary>
    [Fact]
    public void UnverifiableConfirmationIsRejectedNotIgnored()
    {
        JsonElement dpopish = Claims(
            """{"sub":"u","tenant_id":"t","exp":9999999999,"cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}}""");

        Assert.False(JwksVerifier.VerifyCertificateBinding(dpopish, null));
        Assert.False(JwksVerifier.VerifyCertificateBinding(dpopish, Thumbprint));
    }

    [Fact]
    public void MalformedCnfFailsClosed()
    {
        Assert.False(JwksVerifier.VerifyCertificateBinding(
            Claims("""{"cnf":"a string, not an object"}"""), Thumbprint));
        Assert.False(JwksVerifier.VerifyCertificateBinding(
            Claims("""{"cnf":{"x5t#S256":42}}"""), Thumbprint));
        Assert.False(JwksVerifier.VerifyCertificateBinding(
            Claims("""{"cnf":{"x5t#S256":""}}"""), Thumbprint));
    }

    /// <summary>
    /// A JSON <c>null</c> cnf reads as absent, not as an unverifiable constraint: a
    /// serializer that emits nulls for missing fields must not turn every token into a
    /// rejection.
    /// </summary>
    [Fact]
    public void NullCnfReadsAsUnbound()
    {
        Assert.True(JwksVerifier.VerifyCertificateBinding(Claims("""{"cnf":null}"""), null));
    }

    /// <summary>
    /// RFC 7515 §2 base64url: unpadded, <c>-</c>/<c>_</c> rather than <c>+</c>/<c>/</c>.
    /// A padded or standard-base64 value will not compare equal to what AXIAM put in the
    /// token.
    /// </summary>
    [Fact]
    public void ThumbprintHelperProducesUnpaddedBase64Url()
    {
        byte[] der = new byte[512];
        Array.Fill(der, (byte)0x42);

        string tp = JwksVerifier.CertificateThumbprintS256(der);

        Assert.Equal(43, tp.Length);
        Assert.DoesNotContain("=", tp);
        Assert.DoesNotContain("+", tp);
        Assert.DoesNotContain("/", tp);
        Assert.Equal(tp, JwksVerifier.CertificateThumbprintS256(der));

        // A different certificate must produce a different thumbprint.
        der[0] = 0x43;
        Assert.NotEqual(tp, JwksVerifier.CertificateThumbprintS256(der));
    }
}
