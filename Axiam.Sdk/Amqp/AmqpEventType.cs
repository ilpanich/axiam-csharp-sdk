namespace Axiam.Sdk.Amqp;

/// <summary>
/// The ONE signed event type an <see cref="AxiamAmqpConsumer"/> consumes (CONTRACT.md &#167;8 step 2c, "Typed: one
/// configured type", contract 1.69, owner decision D-9). <c>AuthzRequest</c>, <c>AuditEventMessage</c> and
/// <c>AuthzResponse</c> are signed with the same scheme under the same tenant subkey, so a genuine message of one
/// type replayed onto a queue that carries another passes the signature check; only its layout tells it apart. A
/// consumer therefore checks the canonical bytes against its configured type's layout and no other, and refuses
/// every other body as <c>malformed</c> before the HMAC is computed. An application that consumes both types runs
/// two consumers, each typed.
/// </summary>
public enum AmqpEventType
{
    /// <summary>An <c>AuthzRequest</c> (queue <c>axiam.authz.request</c>).</summary>
    AuthzRequest,

    /// <summary>An <c>AuditEventMessage</c> (queue <c>axiam.audit.events</c>).</summary>
    AuditEvent,
}
