using System.Security.Cryptography;
using System.Text;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Auth.Oidc;

/// <summary>
/// PKCE + CSPRNG primitives for the OIDC relying-party flow (CONTRACT.md &#167;12.1
/// "<c>oidc_begin</c> inputs and construction", RFC 7636).
/// </summary>
/// <remarks>
/// <see cref="RandomNumberGenerator"/> + <see cref="SHA256"/> + <see cref="Convert"/>'s
/// base64 cover everything needed, so &#167;12 adds NO new runtime dependency (BCL only).
/// This class is deliberately tiny, pure, and synchronous: <c>OidcBegin</c> performs no
/// network I/O, and every value here is derived locally.
/// <para>
/// S256 ONLY. <c>"plain"</c> is not implemented, not reachable, and not configurable: there
/// is no code path in this SDK that can emit <c>code_challenge_method=plain</c>.
/// </para>
/// </remarks>
internal static class OidcPkce
{
    /// <summary>The only PKCE code-challenge method this SDK emits (RFC 7636 &#167;4.2,
    /// CONTRACT.md &#167;12.1 rule 3).</summary>
    internal const string CodeChallengeMethodS256 = "S256";

    /// <summary>
    /// The entropy, in bytes, of a generated <c>state</c>/<c>nonce</c>/<c>code_verifier</c>.
    /// &#167;12.1 rule 1 requires at least 16 bytes (128 bits) and RECOMMENDS 32; rule 2
    /// RECOMMENDS 32 bytes for the verifier, which base64url-encodes to exactly 43
    /// characters — the RFC 7636 &#167;4.1 minimum length, drawn only from the unreserved set
    /// <c>[A-Za-z0-9-._~]</c>.
    /// </summary>
    private const int CsprngBytes = 32;

    /// <summary>
    /// Returns <paramref name="byteCount"/> CSPRNG bytes, base64url-encoded WITHOUT padding
    /// (RFC 4648 &#167;5 — never emits <c>=</c>).
    /// </summary>
    /// <remarks>
    /// Used for both <c>state</c> and <c>nonce</c>, which &#167;12.3 rule 2 classes as
    /// NON-SECRET: they are returned as plain strings, are echoed through the browser's
    /// address bar by construction, and are safe to log.
    /// </remarks>
    internal static string RandomUrlSafeToken(int byteCount = CsprngBytes)
    {
        byte[] buffer = RandomNumberGenerator.GetBytes(byteCount);
        return Base64UrlEncode(buffer);
    }

    /// <summary>
    /// Returns a fresh PKCE <c>code_verifier</c> (RFC 7636 &#167;4.1): 32 CSPRNG bytes,
    /// base64url-encoded without padding (43 characters, drawn only from the unreserved
    /// set). Returned already wrapped in <see cref="Sensitive{T}"/> — &#167;12.5 makes the
    /// verifier secret for its WHOLE lifetime, including while it sits in the
    /// <see cref="AuthorizationRequest"/> handed back to the caller and in any
    /// <see cref="IOidcStateStore"/> entry.
    /// </summary>
    internal static Sensitive<string> GenerateCodeVerifier() => Sensitive.Of(RandomUrlSafeToken());

    /// <summary>
    /// Derives the PKCE <c>code_challenge</c> from a verifier:
    /// <c>BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))</c>, unpadded (RFC 7636 &#167;4.2,
    /// CONTRACT.md &#167;12.1 rule 3). Verified against the RFC 7636 Appendix B test vector
    /// in the test suite, which every SDK must carry (&#167;12.1 rule 3). The challenge is a
    /// one-way digest and is NOT secret — it travels in the authorization URL — so it is
    /// returned as a plain string.
    /// </summary>
    internal static string ComputeCodeChallenge(string codeVerifier)
    {
        byte[] hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        return Base64UrlEncode(hash);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
