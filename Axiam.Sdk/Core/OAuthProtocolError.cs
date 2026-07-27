namespace Axiam.Sdk.Core;

/// <summary>
/// An RFC 6749 protocol error returned by an <c>/oauth2/*</c> endpoint as an
/// <c>OAuth2ErrorResponse</c> body (<c>invalid_grant</c>, <c>invalid_client</c>,
/// <c>invalid_request</c>, <c>unsupported_grant_type</c>, &#8230;) &#8212; CONTRACT.md
/// &#167;2 sub-type table, &#167;12.3 rule 3.
/// </summary>
/// <remarks>
/// A language-idiomatic <b>sub-type of <see cref="AuthError"/></b> (&#167;12 port addendum
/// item 17), not a fourth peer error type: every pre-existing
/// <c>catch (AuthError ex)</c> block keeps matching an <see cref="OAuthProtocolError"/>
/// unchanged, because it IS an <see cref="AuthError"/> &#8212; this is precisely what makes
/// contract 1.4 "non-breaking, additive" for C#. <see cref="Exception.Message"/> is always
/// exactly <c>"&lt;error&gt;: &lt;error_description&gt;"</c>, built from the two
/// <c>OAuth2ErrorResponse</c> wire fields, which are also exposed individually below.
/// <see cref="AuthError.Reason"/> is always <c>null</c> on an <see cref="OAuthProtocolError"/>
/// &#8212; that property is reserved for &#167;12.4 ID-token validation failures, a distinct
/// failure family.
/// </remarks>
public sealed class OAuthProtocolError : AuthError
{
    /// <summary>The RFC 6749 <c>error</c> code (e.g. <c>"invalid_grant"</c>, <c>"invalid_client"</c>,
    /// <c>"unsupported_grant_type"</c>).</summary>
    public string Error { get; }

    /// <summary>The server's human-readable <c>error_description</c>. Never contains token
    /// material (CONTRACT.md &#167;2 construction rules).</summary>
    public string ErrorDescription { get; }

    /// <summary>
    /// Constructs an <see cref="OAuthProtocolError"/> from the two <c>OAuth2ErrorResponse</c>
    /// wire fields. <see cref="Exception.Message"/> is built as exactly
    /// <c>"&lt;error&gt;: &lt;error_description&gt;"</c> (CONTRACT.md &#167;2 construction rules,
    /// &#167;12 port addendum item 17).
    /// </summary>
    public OAuthProtocolError(string error, string errorDescription)
        : base($"{error}: {errorDescription}")
    {
        Error = error;
        ErrorDescription = errorDescription;
    }
}
