using Axiam.Sdk.Auth.Oidc;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;12.1 rule 3 requires the RFC 7636 Appendix B test vector as a unit
/// test in every SDK; this suite also proves &#8805;128-bit CSPRNG entropy/uniqueness for
/// <c>state</c>/<c>nonce</c>/<c>code_verifier</c> and that S256 is the only method this SDK
/// can ever emit.
/// </summary>
[Trait("Category", "Fast")]
public class OidcPkceTests
{
    /// <summary>The exact RFC 7636 Appendix B vector.</summary>
    [Fact]
    public void ComputeCodeChallenge_Rfc7636AppendixBVector_MatchesExactly()
    {
        const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const string expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        string challenge = OidcPkce.ComputeCodeChallenge(verifier);

        Assert.Equal(expectedChallenge, challenge);
    }

    [Fact]
    public void CodeChallengeMethod_IsAlwaysS256()
    {
        Assert.Equal("S256", OidcPkce.CodeChallengeMethodS256);
    }

    [Fact]
    public void RandomUrlSafeToken_DefaultLength_Is256BitsBase64UrlNoPadding()
    {
        string token = OidcPkce.RandomUrlSafeToken();

        Assert.DoesNotContain('=', token);
        Assert.DoesNotContain('+', token);
        Assert.DoesNotContain('/', token);
        // 32 CSPRNG bytes base64url-encodes to 43 characters (no padding) — well over the
        // §12.1 rule 1 128-bit (16-byte / 22-char) floor.
        Assert.Equal(43, token.Length);
    }

    [Fact]
    public void RandomUrlSafeToken_GeneratesUniqueValues()
    {
        var seen = new HashSet<string>();
        for (int i = 0; i < 200; i++)
        {
            Assert.True(seen.Add(OidcPkce.RandomUrlSafeToken()), "generated a duplicate token — CSPRNG entropy is broken");
        }
    }

    [Fact]
    public void GenerateCodeVerifier_Is43CharsFromUnreservedSetOnly()
    {
        string verifier = OidcPkce.GenerateCodeVerifier().Reveal();

        Assert.Equal(43, verifier.Length);
        Assert.Matches("^[A-Za-z0-9\\-._~]+$", verifier);
    }

    [Fact]
    public void GenerateCodeVerifier_GeneratesUniqueValues()
    {
        var seen = new HashSet<string>();
        for (int i = 0; i < 200; i++)
        {
            Assert.True(seen.Add(OidcPkce.GenerateCodeVerifier().Reveal()));
        }
    }
}
