using Axiam.Sdk.Core;
using Axiam.Sdk.Management.Models;

namespace Axiam.Sdk.Management;

/// <summary>
/// The changes to make to an <see cref="SsfStream"/> that was read, for the change-taking
/// read-modify-write form <see cref="ManagementReplacements.ToInput(SsfStream, SsfStreamChanges)"/>
/// (CONTRACT.md &#167;32.2, contract 1.62).
/// </summary>
/// <remarks>
/// <para>
/// Every member is optional and <c>null</c> means <b>unchanged</b>: the member keeps the value
/// the stream was read with. The five members the wire lets a caller clear
/// (<see cref="Description"/>, <see cref="EndpointUrl"/>, <see cref="StatusReason"/>,
/// <see cref="ExpectedUpdatedAt"/> and, by their own rules, the authorization header through
/// <see cref="ClearAuthorizationHeader"/>) are <see cref="JsonNullable{T}"/>: assign
/// <c>JsonNullable&lt;string&gt;.Null</c> to say "none".
/// </para>
/// <para>
/// <b>An assigned null is "none" (CONTRACT.md &#167;27.11 rule 5):</b>
/// <c>ExpectedUpdatedAt = JsonNullable&lt;string&gt;.Null</c> leaves the
/// <c>expected_updated_at</c> key out of the body and <c>null</c> is never sent; the update
/// then replaces whatever is stored instead of landing only on the version that was read.
/// </para>
/// </remarks>
public sealed record SsfStreamChanges
{
    /// <summary>A new <c>receiver_client_id</c>, or <c>null</c> to keep the read one.</summary>
    public string? ReceiverClientId { get; init; }

    /// <summary>A new <c>audience</c>, or <c>null</c> to keep the read one.</summary>
    public string? Audience { get; init; }

    /// <summary>A new <c>delivery_method</c>, or <c>null</c> to keep the read one.</summary>
    public SsfDeliveryMethod? DeliveryMethod { get; init; }

    /// <summary>
    /// A new <c>description</c>, <see cref="JsonNullable{T}.Null"/> to clear it, or
    /// <c>null</c> to keep the read one.
    /// </summary>
    public JsonNullable<string>? Description { get; init; }

    /// <summary>
    /// A new <c>endpoint_url</c>, <see cref="JsonNullable{T}.Null"/> to clear it, or
    /// <c>null</c> to keep the read one.
    /// </summary>
    public JsonNullable<string>? EndpointUrl { get; init; }

    /// <summary>
    /// A new ceiling, or <c>null</c> to keep the read one. When it is set and
    /// <see cref="EventsRequested"/> is not, the body's <c>events_requested</c> is the read
    /// list cut to this ceiling (the entries that are in it, in their order).
    /// </summary>
    public IReadOnlyList<SsfEventType>? EventsAllowed { get; init; }

    /// <summary>
    /// What the receiver is to be sent, <b>sent as given</b> (the server judges it: a list
    /// outside the ceiling is <c>400</c>; an empty list is the receiver's "none" and goes as
    /// <c>[]</c>). <c>null</c> keeps the read list, cut to <see cref="EventsAllowed"/> when
    /// that is changed.
    /// </summary>
    public IReadOnlyList<SsfEventType>? EventsRequested { get; init; }

    /// <summary>A new <c>subject_format</c>, or <c>null</c> to keep the read one.</summary>
    public SsfSubjectFormat? SubjectFormat { get; init; }

    /// <summary>A new <c>status</c>, or <c>null</c> to keep the read one.</summary>
    public SsfStreamStatus? Status { get; init; }

    /// <summary>
    /// A new <c>status_reason</c>, <see cref="JsonNullable{T}.Null"/> to clear it, or
    /// <c>null</c> to keep the read one.
    /// </summary>
    public JsonNullable<string>? StatusReason { get; init; }

    /// <summary>
    /// A push <c>Authorization</c> header to store. The read stream carries none (the value is
    /// never returned), so unset means "keep the stored one" on the wire; a write that moves
    /// <c>endpoint_url</c> to another scheme, host or port while a header is stored must carry
    /// one again (&#167;32.3 rule 5).
    /// </summary>
    public Sensitive<string>? AuthorizationHeader { get; init; }

    /// <summary><c>true</c> to remove the stored header; refused together with <see cref="AuthorizationHeader"/>.</summary>
    public bool? ClearAuthorizationHeader { get; init; }

    /// <summary>
    /// The <c>expected_updated_at</c> to send instead of the read stream's own string, or
    /// <see cref="JsonNullable{T}.Null"/> for "none" (the key is left out; <c>null</c> is never
    /// sent), or <c>null</c> to send the read stream's <c>updated_at</c> as the server wrote it.
    /// </summary>
    public JsonNullable<string>? ExpectedUpdatedAt { get; init; }
}
