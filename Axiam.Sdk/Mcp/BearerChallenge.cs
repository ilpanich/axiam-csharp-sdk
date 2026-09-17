namespace Axiam.Sdk.Mcp;

/// <summary>
/// The three RFC 6750 &#167;3.1 error codes a &#167;28 challenge may name &#8212; the
/// complete vocabulary <see cref="AxiamMcp.BearerChallenge"/> accepts for
/// <see cref="BearerChallengeOptions.Error"/>.
/// </summary>
/// <remarks>
/// Constants rather than an <c>enum</c>: &#167;28.9 test 2 requires
/// <see cref="AxiamMcp.BearerChallenge"/> to refuse a well-formed-looking but
/// out-of-vocabulary value such as <c>"invalid_grant"</c>, which a caller can only
/// attempt to pass when the parameter accepts an arbitrary string.
/// </remarks>
public static class AxiamBearerChallengeError
{
    /// <summary>RFC 6750 &#167;3.1 &#8212; status 400. Available to a caller building its
    /// own challenge by hand; no guard in this SDK emits it automatically.</summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>RFC 6750 &#167;3.1 &#8212; status 401. Emitted when a credential was
    /// presented and rejected.</summary>
    public const string InvalidToken = "invalid_token";

    /// <summary>RFC 6750 &#167;3.1 &#8212; status 403. Emitted only under CONTRACT.md
    /// &#167;28.5 rule 5.</summary>
    public const string InsufficientScope = "insufficient_scope";
}

/// <summary>
/// Arguments to <see cref="AxiamMcp.BearerChallenge"/> (CONTRACT.md &#167;28.1), in the
/// contract's canonical order.
/// </summary>
public sealed class BearerChallengeOptions
{
    /// <summary>The document's URL &#8212; the one parameter that is always present. May
    /// carry a query and a fragment.</summary>
    public required string ResourceMetadataUrl { get; init; }

    /// <summary>One of <see cref="AxiamBearerChallengeError"/>'s three values, or absent
    /// when the request carried no authentication information at all.</summary>
    public string? Error { get; init; }

    /// <summary>
    /// A human-readable description, for an application building <b>its own</b>
    /// challenge for its own 400.
    /// </summary>
    /// <remarks>
    /// This SDK's own guards never set it: expired, not yet valid, wrong tenant, wrong
    /// audience, bad signature, <c>alg</c> confusion, an unsatisfiable <c>cnf</c>, a
    /// revoked <c>sid</c> &#8212; &#167;28.4 makes all of them <c>invalid_token</c>,
    /// indistinguishably. Every distinction a 401 draws for an unauthenticated stranger
    /// is an oracle.
    /// </remarks>
    public string? ErrorDescription { get; init; }

    /// <summary>The scope the route asked for, verbatim &#8212; one or more tokens joined
    /// by a single space.</summary>
    public string? Scope { get; init; }
}
