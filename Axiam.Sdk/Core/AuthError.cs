namespace Axiam.Sdk.Core;

/// <summary>
/// Authentication failure: wrong credentials, expired session, MFA failure, a 401 on
/// refresh, an RFC 6749 OAuth2 protocol error (CONTRACT.md &#167;12.3 rule 3 &#8212; see
/// <see cref="OAuthProtocolError"/>), or a &#167;12.4 ID-token validation failure
/// (CONTRACT.md &#167;2, D-12). Always constructed via <see cref="ErrorMapper"/> for the
/// pre-existing REST/gRPC taxonomy, or directly for the &#167;12 additions, so no code path
/// drifts from the error taxonomy.
/// </summary>
/// <remarks>
/// Deliberately NOT <c>sealed</c> (CONTRACT.md &#167;2 permits "language-idiomatic
/// sub-types" of the three top-level error types, which MUST NOT replace them; &#167;12's
/// port addendum item 17 requires <see cref="OAuthProtocolError"/> specifically to be a
/// sub-type of this class so existing <c>catch (AuthError)</c> call sites keep matching
/// it unchanged &#8212; that backward compatibility is what makes contract 1.4 additive
/// rather than breaking). Every OTHER pre-existing construction site
/// (<c>new AuthError(message)</c>) is untouched and keeps compiling exactly as before.
/// </remarks>
public class AuthError : Exception
{
    /// <summary>
    /// An OPTIONAL, stable, machine-readable failure code. Populated only for a
    /// CONTRACT.md &#167;12.4 ID-token validation failure, with one of the seven
    /// contract-fixed reason strings in <see cref="Auth.Oidc.IdTokenFailureReasons"/>
    /// (&#167;12 T1 reference judgment call 2: the reason code rides on this EXISTING
    /// <see cref="AuthError"/> type via this additive property, rather than a second
    /// error class). <c>null</c> for every other <see cref="AuthError"/> &#8212; including
    /// every pre-existing construction site and every <see cref="OAuthProtocolError"/>,
    /// which carries its own structured <see cref="OAuthProtocolError.Error"/>/
    /// <see cref="OAuthProtocolError.ErrorDescription"/> pair instead.
    /// </summary>
    public string? Reason { get; }

    /// <summary>Constructs an <see cref="AuthError"/> with the given diagnostic message.</summary>
    /// <param name="message">Describes the authentication failure (CONTRACT.md &#167;2 MUST).</param>
    public AuthError(string message) : base(message)
    {
    }

    /// <summary>
    /// Constructs an <see cref="AuthError"/> carrying a stable &#167;12.4 ID-token
    /// validation failure reason code.
    /// </summary>
    /// <param name="message">Describes the authentication failure (CONTRACT.md &#167;2 MUST).</param>
    /// <param name="reason">
    /// One of the seven CONTRACT.md &#167;12.4 reason codes, or <c>null</c> for a
    /// non-ID-token <see cref="AuthError"/>.
    /// </param>
    public AuthError(string message, string? reason) : base(message)
    {
        Reason = reason;
    }
}
