namespace Axiam.Sdk.Webhooks;

/// <summary>
/// A webhook delivery whose <c>X-Axiam-Signature</c> has already been verified by
/// <see cref="AxiamWebhooks.Verify"/> (CONTRACT.md &#167;13). <see cref="EventType"/> and
/// <see cref="DeliveryId"/> are a best-effort parse of the verified body's <c>event</c>/<c>id</c>
/// JSON fields — a non-JSON or differently-shaped body still verifies successfully (the MAC only
/// covers the raw bytes, not their JSON shape), it simply leaves those two properties
/// <c>null</c>. Callers that need the delivery id for at-least-once dedup (&#167;13.3 rule 7)
/// should prefer the still-available raw <see cref="Body"/>/<c>X-Axiam-Delivery</c> header over
/// relying solely on this parse.
/// </summary>
/// <param name="Timestamp">
/// The unix-seconds timestamp from the signature header's <c>t=</c> field (already checked
/// against the freshness tolerance).
/// </param>
/// <param name="Body">
/// The exact raw body bytes that were verified — a defensive copy, safe to retain past the
/// call.
/// </param>
/// <param name="EventType">The verified body's <c>"event"</c> field, or <c>null</c> if absent/not a string.</param>
/// <param name="DeliveryId">The verified body's <c>"id"</c> field, or <c>null</c> if absent/not a string.</param>
public sealed record WebhookEvent(
    long Timestamp,
    byte[] Body,
    string? EventType,
    string? DeliveryId);
