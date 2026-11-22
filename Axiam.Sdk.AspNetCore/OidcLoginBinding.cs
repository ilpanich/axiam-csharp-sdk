using System.Security.Cryptography;
using System.Text;
using Axiam.Sdk.Auth.Oidc;
using Microsoft.AspNetCore.Http;

namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// The decisions of CONTRACT.md &#167;12.8 (contract 1.68; audit findings C7 and C6) for the
/// "Login with AXIAM" glue, kept in one place so the cookie's name, attributes and comparison,
/// and the <c>return_to</c> rule, cannot drift between the login route and the callback route.
/// </summary>
internal static class OidcLoginBinding
{
    /// <summary>The binding cookie's name wherever the browser will store a <c>Secure</c> cookie.</summary>
    internal const string HostCookieName = "__Host-axiam_oidc_bind";

    /// <summary>The binding cookie's name on a plain-HTTP loopback <c>redirect_uri</c> only (&#167;12.8 rule 1b).</summary>
    internal const string LoopbackCookieName = "axiam_oidc_bind";

    /// <summary>The longest the cookie lives: the state store's own maximum TTL (ten minutes).</summary>
    internal static readonly TimeSpan CookieLifetime = MemoryOidcStateStore.MaxTtl;

    /// <summary>
    /// The cookie name the glue's <paramref name="redirectUri"/> selects: the fallback name only for
    /// <c>http:</c> on <c>localhost</c>, <c>127.0.0.1</c> or <c>[::1]</c>, and <c>__Host-</c> for everything
    /// else, so the fallback can never be selected off loopback (a browser drops the <c>__Host-</c>
    /// cookie on plain HTTP to another host, and the callback then fails closed).
    /// </summary>
    internal static string CookieName(string redirectUri) => IsHttpLoopback(redirectUri) ? LoopbackCookieName : HostCookieName;

    internal static bool IsHttpLoopback(string redirectUri)
    {
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out Uri? uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        string host = uri.Host;
        return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
               host == "127.0.0.1" ||
               host == "[::1]" ||
               host == "::1";
    }

    /// <summary>
    /// 32 bytes from a CSPRNG, base64url without padding (43 characters). A new value for every login;
    /// the glue never reuses a cookie the login request presented.
    /// </summary>
    internal static string NewValue() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Lower-case hex SHA-256 of the ASCII bytes of the cookie value: what the entry stores.</summary>
    internal static string Digest(string cookieValue) =>
        Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(cookieValue))).ToLowerInvariant();

    /// <summary>
    /// Whether <paramref name="presented"/> is the cookie whose digest <paramref name="entry"/> holds. A missing
    /// cookie, an entry with no digest and a different digest are all <c>false</c>; the comparison of two
    /// equal-length digests is constant-time.
    /// </summary>
    internal static bool Matches(OidcStateEntry entry, string? presented)
    {
        if (string.IsNullOrEmpty(presented) || string.IsNullOrEmpty(entry.BindingDigest))
        {
            return false;
        }
        byte[] expected = Encoding.ASCII.GetBytes(entry.BindingDigest);
        byte[] actual = Encoding.ASCII.GetBytes(Digest(presented));
        return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    /// <summary>The attributes every Set-Cookie of the binding cookie carries, the clearing one included.</summary>
    private static CookieOptions Options(string redirectUri, TimeSpan maxAge) => new()
    {
        HttpOnly = true,
        Secure = !IsHttpLoopback(redirectUri),
        SameSite = SameSiteMode.Lax,
        Path = "/",
        MaxAge = maxAge,
    };

    internal static void Set(HttpResponse response, string redirectUri, string value) =>
        response.Cookies.Append(CookieName(redirectUri), value, Options(redirectUri, CookieLifetime));

    internal static void Clear(HttpResponse response, string redirectUri) =>
        response.Cookies.Append(CookieName(redirectUri), string.Empty, Options(redirectUri, TimeSpan.Zero));

    /// <summary>The cookie value the request presents under the one name this glue selects; any other name is no cookie.</summary>
    internal static string? Presented(HttpRequest request, string redirectUri) =>
        request.Cookies.TryGetValue(CookieName(redirectUri), out string? value) ? value : null;

    // ---- return_to (§12.8 rule 3; audit C6) ---------------------------------------------

    /// <summary>
    /// The default <c>return_to</c> rule: a same-origin relative path. It starts with a single <c>/</c>, does not
    /// start with <c>//</c> or <c>/\</c>, and contains no <c>\</c> and no control character (U+0000&#8211;U+001F,
    /// U+007F). The semantics of <c>Url.IsLocalUrl</c> for a path, made stricter: a backslash is refused anywhere
    /// and the <c>~/</c> app-relative form is not a path.
    /// </summary>
    internal static bool IsLocalPath(string? value)
    {
        if (string.IsNullOrEmpty(value) || value[0] != '/')
        {
            return false;
        }
        if (value.Length > 1 && (value[1] == '/' || value[1] == '\\'))
        {
            return false;
        }
        foreach (char c in value)
        {
            if (c == '\\' || c < 0x20 || c == 0x7f)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Whether <paramref name="value"/> may be honoured as a <c>return_to</c>: the default rule, or, only for a
    /// value the default rule refuses, the integrator's <paramref name="allow"/> predicate. A predicate that throws
    /// accepts nothing. There is no default predicate that accepts absolute URLs.
    /// </summary>
    internal static bool IsAcceptableReturnTo(string? value, Func<string, bool>? allow)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }
        if (IsLocalPath(value))
        {
            return true;
        }
        if (allow is null)
        {
            return false;
        }
        try
        {
            return allow(value);
        }
        catch (Exception)
        {
            return false;
        }
    }
}
