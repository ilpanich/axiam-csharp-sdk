using Axiam.Sdk.Core;

namespace Axiam.Sdk.Management;

/// <summary>
/// One field-level complaint from a server that rejected a request body
/// (CONTRACT.md &#167;27.4 rule 7).
/// </summary>
/// <param name="Field">The offending field's name, as the server spelled it.</param>
/// <param name="Message">What the server said about it.</param>
/// <remarks>
/// Present on a <see cref="ValidationError"/> only when the server actually reported
/// per-field detail; a server that says nothing more than "400" yields an empty list
/// rather than a fabricated entry.
/// </remarks>
public sealed record FieldError(string Field, string Message);

/// <summary>
/// A &#167;27 management operation addressed something that does not exist (HTTP 404).
/// </summary>
/// <remarks>
/// A SUB-TYPE of <see cref="AuthzError"/>, not a peer of it: CONTRACT.md &#167;27.4
/// rule 7 is explicit that the three &#167;27 classifications live <em>inside</em> the
/// &#167;2 taxonomy.
/// <para>
/// Why <see cref="AuthzError"/> rather than <see cref="NetworkError"/>: on an
/// access-controlled surface, "no such object" and "no such object <em>that you may
/// see</em>" are the same response by design. A server that distinguished them would
/// let a probing caller enumerate another tenant's objects, so 404 is an authorization
/// answer and is sorted as one.
/// </para>
/// </remarks>
public sealed class NotFoundError : AuthzError
{
    /// <summary>Constructs a <see cref="NotFoundError"/>.</summary>
    /// <param name="message">Names the operation and what the server said.</param>
    public NotFoundError(string message) : base(message)
    {
    }
}

/// <summary>
/// A &#167;27 management operation collided with the state already there (HTTP 409):
/// a name already taken, a certificate already revoked, a role that already holds the
/// grant.
/// </summary>
/// <remarks>
/// A SUB-TYPE of <see cref="AuthzError"/>. &#167;2 already maps 409 there as
/// "resource-level access denied", and CONTRACT.md &#167;27.4 rule 7 keeps that mapping
/// rather than re-deciding it — the sub-type exists to give the caller something to act
/// on, not to move the status.
/// <para>
/// Never retried: a 409 is the server telling the truth, not a transient fault, and
/// repeating the request cannot change it (&#167;27.4 rule 8).
/// </para>
/// </remarks>
public sealed class ConflictError : AuthzError
{
    /// <summary>Constructs a <see cref="ConflictError"/>.</summary>
    /// <param name="message">Names the operation and what the server said.</param>
    /// <param name="reasonCode">
    /// The body's <c>reason_code</c> (CONTRACT.md &#167;36.4), or <c>null</c> when it carried none.
    /// </param>
    public ConflictError(string message, string? reasonCode = null) : base(message)
    {
        ReasonCode = reasonCode;
    }

    /// <summary>
    /// The <c>reason_code</c> the server's <c>409</c> body carried, verbatim; <c>null</c> when it
    /// carried none (a server predating it, or an operation that does not send one).
    /// </summary>
    /// <remarks>
    /// <para>
    /// CONTRACT.md &#167;36.4 (contract 1.62): every <c>409</c> of the twelve <c>network</c>
    /// operations says which in <c>reason_code</c> &#8212; <c>stale_version</c>, <c>strands_profile</c>,
    /// <c>has_children</c>, <c>site_gone</c>, <c>duplicate_name</c>, <c>duplicate_vlan</c>,
    /// <c>duplicate_rank</c>, <c>profile_exists</c> or <c>other</c> (&#167;36.3 rule 2). The
    /// vocabulary is <b>open</b>: a value this SDK has never seen is surfaced as the string the
    /// server sent, and a caller treats it as a conflict whose <see cref="Exception.Message"/> is for a
    /// human. Branch on this member, <b>never on the message</b>, which an SDK must not parse.
    /// </para>
    /// <para>
    /// It is not the <c>reason</c> of an authorization decision (&#167;3), which is a human
    /// string. The <c>error</c> slug (<c>conflict</c> or <c>already_exists</c>) maps to
    /// <see cref="ConflictError"/> either way and is not exposed.
    /// </para>
    /// </remarks>
    public string? ReasonCode { get; }
}

/// <summary>
/// A &#167;27 management request body the server refused (HTTP 400 or 422).
/// </summary>
/// <remarks>
/// A SUB-TYPE of <see cref="NetworkError"/> (CONTRACT.md &#167;27.4 rule 7), inheriting
/// the parent &#167;2 already gives a 400 rather than choosing a new one. Never retried:
/// the body is wrong, and sending the same bytes again produces the same refusal.
/// </remarks>
public sealed class ValidationError : NetworkError
{
    /// <summary>Constructs a <see cref="ValidationError"/>.</summary>
    /// <param name="message">Names the operation and what the server said.</param>
    /// <param name="fields">The server's per-field detail, or empty when it sent none.</param>
    public ValidationError(string message, IReadOnlyList<FieldError> fields)
        : base(message, null)
    {
        Fields = fields;
    }

    /// <summary>
    /// The server's per-field detail when it sent any, otherwise empty.
    /// </summary>
    /// <remarks>
    /// Empty is not the same as invented: a server that reports only "400" yields no
    /// entries rather than one guessed from the request.
    /// </remarks>
    public IReadOnlyList<FieldError> Fields { get; }
}
