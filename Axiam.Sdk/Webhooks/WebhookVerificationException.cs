namespace Axiam.Sdk.Webhooks;

/// <summary>
/// Thrown by <see cref="AxiamWebhooks.Verify"/> when a webhook delivery fails signature
/// verification (CONTRACT.md &#167;13.3 rule 6: "fail closed and quiet").
/// </summary>
/// <remarks>
/// <see cref="Exception.Message"/> is always a fixed, generic, reason-category string (e.g.
/// "malformed header", "signature mismatch", "timestamp outside tolerance") — it NEVER
/// includes the expected/computed signature, the raw secret, or any other value that could
/// help an attacker forge a signature or that could leak the secret into a log sink further
/// up the call stack. Callers that need to distinguish failure reasons programmatically
/// should not parse <see cref="Exception.Message"/>; none is currently exposed structurally,
/// mirroring &#167;13.3 rule 6's "typed error / false, nothing more" requirement.
/// </remarks>
public sealed class WebhookVerificationException : Exception
{
    /// <summary>Constructs a <see cref="WebhookVerificationException"/> with a generic, non-leaking reason.</summary>
    /// <param name="message">A fixed, generic failure-category description (never the expected signature or the secret).</param>
    public WebhookVerificationException(string message) : base(message)
    {
    }
}
