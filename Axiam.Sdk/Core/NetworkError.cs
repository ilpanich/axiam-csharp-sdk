using System.Net.Http;

namespace Axiam.Sdk.Core;

/// <summary>
/// Transport-level failure: connection refused, timeout, TLS error, DNS failure, or a
/// server-side 5xx (CONTRACT.md &#167;2).
/// </summary>
/// <remarks>
/// <para>
/// Unsealed so CONTRACT.md &#167;27.4 rule 7 can classify a 400/422 as
/// <see cref="Management.ValidationError"/> inside this type — the parent &#167;2 already
/// gives a 400. <c>catch (NetworkError)</c> still catches it.
/// </para>
/// </remarks>
/// <remarks>
/// <para>
/// <b>Redact-before-wrap (D-12, CR-04 carry-forward):</b> this is the ONLY error class
/// that may be constructed from an HTTP response, and there is exactly ONE construction
/// path that accepts a live <see cref="HttpResponseMessage"/> — the static
/// <see cref="FromResponse"/> factory. There is no public or internal constructor that
/// accepts an <see cref="HttpResponseMessage"/> directly; the live response object is
/// NEVER stored as the <see cref="Exception.InnerException"/> or in
/// <see cref="Exception.Data"/> — only a pre-sanitized message string survives. This
/// structurally prevents the token-leak-via-error class of bug first found in the
/// TypeScript sibling SDK (Phase 17 CR-04, <c>sdks/typescript/src/core/errorMapper.ts</c>
/// <c>sanitizeAxiosError</c>) and mirrored across every later sibling SDK.
/// </para>
/// </remarks>
public class NetworkError : Exception
{
    /// <summary>
    /// X-3: ALLOWLIST of response headers whose <em>values</em> are known to be safe to
    /// surface in an error/diagnostic message. Anything NOT on this list is redacted to
    /// <c>[REDACTED]</c>. A denylist (Set-Cookie/Authorization/Cookie only) previously let
    /// a custom sensitive header such as <c>X-Auth-Token</c> survive verbatim into an
    /// exception message/log; an allowlist is fail-closed — a header we have not vetted is
    /// never leaked. Kept deliberately small: only non-secret transport/caching/diagnostic
    /// headers. HTTP header lookups in .NET are case-insensitive, so casing variants need
    /// not be enumerated.
    /// </summary>
    private static readonly HashSet<string> SafeResponseHeaders =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "Content-Type", "Content-Length", "Content-Language", "Content-Encoding",
            "Date", "Server", "Cache-Control", "ETag", "Last-Modified", "Expires",
            "Age", "Vary", "Retry-After", "Accept-Ranges",
            // Non-secret diagnostic correlation IDs — useful for tracing, never carry credentials.
            "X-Request-Id", "X-Correlation-Id",
        };

    /// <summary>
    /// The single construction path a subclass may use — a message this SDK authored
    /// plus an optional already-sanitized cause.
    /// </summary>
    /// <remarks>
    /// <c>protected</c> rather than <c>private</c> so CONTRACT.md &#167;27.4 rule 7 can
    /// classify a 400/422 as <see cref="Management.ValidationError"/> inside this type.
    /// The redact-before-wrap invariant this class exists to enforce is untouched: this
    /// constructor takes a <see cref="string"/> and an <see cref="Exception"/>, never an
    /// <see cref="HttpResponseMessage"/>, so a subclass has no more access to a live
    /// response than any other caller does. <see cref="FromResponse"/> remains the only
    /// path from a response into this type.
    /// </remarks>
    /// <param name="message">An already-sanitized description of the failure.</param>
    /// <param name="inner">An already-sanitized cause, or <c>null</c>.</param>
    protected NetworkError(string message, Exception? inner) : base(message, inner)
    {
    }

    /// <summary>
    /// CONTRACT.md &#167;2 MUST: "NetworkError MUST carry the underlying OS/transport
    /// error as a `cause` (or equivalent chained exception)" — <see cref="Exception.InnerException"/>
    /// must never be null. This sanitized carrier is the ONLY exception type ever placed
    /// there: it holds nothing but a redacted summary string, so chaining a cause can
    /// never reintroduce the token/header leak this file's class-level remarks describe
    /// (no live <see cref="HttpResponseMessage"/>, no unredacted caught-exception message,
    /// ever reaches it).
    /// </summary>
    private sealed class SanitizedCause : Exception
    {
        public SanitizedCause(string sanitizedSummary) : base(sanitizedSummary)
        {
        }
    }

    /// <summary>
    /// Builds a <see cref="NetworkError"/> from a live <see cref="HttpResponseMessage"/>.
    /// This is the ONLY construction path that accepts a live response — every other
    /// code path in the SDK MUST go through this factory (or <see cref="FromException"/>)
    /// rather than constructing a <see cref="NetworkError"/> directly from a raw
    /// response/exception.
    /// </summary>
    public static NetworkError FromResponse(HttpResponseMessage response, string context)
    {
        ArgumentNullException.ThrowIfNull(response);
        // X-3: fail-closed allowlist — a header whose name is not vetted as safe has its
        // value replaced with [REDACTED]; only the name is kept for diagnostic context.
        var sanitizedHeaders = response.Headers
            .Select(h => SafeResponseHeaders.Contains(h.Key)
                ? $"{h.Key}: {string.Join(",", h.Value)}"
                : $"{h.Key}: [REDACTED]");
        var message =
            $"{context}: HTTP {(int)response.StatusCode} — headers: [{string.Join("; ", sanitizedHeaders)}]";
        // The raw `response` object itself is NEVER stored as InnerException/Data —
        // only a sanitized status-code summary (no header values, safe or otherwise)
        // survives past this method, satisfying the §2 MUST for a non-null cause chain.
        var inner = new SanitizedCause($"HTTP {(int)response.StatusCode}");
        return new NetworkError(message, inner) { RetryAfter = ParseRetryAfter(response) };
    }

    /// <summary>
    /// A server-supplied <c>Retry-After</c> hint (CONTRACT.md &#167;16.1), <c>null</c>
    /// when the response carried none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A parsed <see cref="TimeSpan"/>, never the raw header text, so the fail-closed
    /// redaction discipline this class exists to enforce is untouched: a duration
    /// cannot carry a token, a URL, or anything else a header might. (<c>Retry-After</c>
    /// happens to be on the safe allowlist above, but storing the parsed value keeps
    /// that an incidental fact rather than a dependency.)
    /// </para>
    /// <para>
    /// &#167;16 honors it as a <strong>floor</strong> on the backoff — the server is
    /// stating when it will be ready, so retrying sooner is not permitted.
    /// </para>
    /// </remarks>
    public TimeSpan? RetryAfter { get; init; }

    /// <summary>
    /// Reads <c>Retry-After</c> as a duration, <c>null</c> when absent or unusable.
    /// </summary>
    /// <remarks>
    /// Both RFC 7231 forms are accepted: delta-seconds and an HTTP-date. The date form
    /// is not hypothetical — CDNs and proxies commonly send it on <c>429</c>/<c>503</c>,
    /// and treating it as unparseable would silently discard the server's own statement
    /// about when it will be ready. A non-positive value collapses to <c>null</c> rather
    /// than becoming a floor, since a negative minimum wait is meaningless.
    /// </remarks>
    private static TimeSpan? ParseRetryAfter(HttpResponseMessage response)
    {
        var header = response.Headers.RetryAfter;
        if (header is null)
        {
            return null;
        }

        if (header.Delta is { } delta)
        {
            return delta > TimeSpan.Zero ? delta : null;
        }

        if (header.Date is { } date)
        {
            TimeSpan until = date - DateTimeOffset.UtcNow;
            return until > TimeSpan.Zero ? until : null;
        }

        return null;
    }

    /// <summary>
    /// Builds a <see cref="NetworkError"/> from a message this SDK authored, with no wire
    /// response and no caught exception behind it.
    /// </summary>
    /// <remarks>
    /// For client-side capability gaps — a key-stretching function this build cannot perform
    /// (CONTRACT.md &#167;23.4), an absent <c>libaxiam_opaque_ffi</c>, or a tenant whose
    /// OPAQUE is switched off.
    /// &#167;2 assigns those to <see cref="NetworkError"/> rather than
    /// <see cref="AuthError"/>: they are facts about the client or the tenant, not about the
    /// credentials, and reporting one as a credential failure would send a user off to reset
    /// a password that works.
    /// <para>
    /// The message is this SDK's own literal text and never echoes a response or a header,
    /// so the redaction discipline the rest of this class enforces has nothing to strip.
    /// </para>
    /// </remarks>
    /// <param name="message">The SDK-authored explanation.</param>
    /// <returns>The error, ready to throw.</returns>
    public static NetworkError FromMessage(string message) => new(message, inner: null);

    /// <summary>
    /// Builds a <see cref="NetworkError"/> from a caught exception (e.g. a socket/TLS/DNS
    /// failure). The exception's own <see cref="Exception.Message"/> is defensively
    /// regex-sanitized before being folded into the resulting message, in case a
    /// lower-level exception echoed a request header verbatim.
    /// </summary>
    public static NetworkError FromException(Exception ex, string context)
    {
        ArgumentNullException.ThrowIfNull(ex);
        string sanitizedDetail = SanitizeMessage(ex.Message);
        var message = $"{context}: {ex.GetType().Name} — {sanitizedDetail}";
        // Chain a cause per §2 MUST — never the caught exception itself (it may carry an
        // unsanitized message/stack referencing request internals); only its type name
        // plus the already-redacted detail above.
        var inner = new SanitizedCause($"{ex.GetType().Name}: {sanitizedDetail}");
        return new NetworkError(message, inner);
    }

    /// <summary>
    /// Defense-in-depth regex redaction: strips any <c>set-cookie</c>/<c>authorization</c>/
    /// <c>cookie</c>-shaped fragment from an arbitrary string, in case a leaked header
    /// fragment reaches a message via a path other than <see cref="FromResponse"/>
    /// (e.g. embedded in a lower-level transport exception's own message text).
    /// </summary>
    internal static string SanitizeMessage(string raw) =>
        System.Text.RegularExpressions.Regex.Replace(
            raw,
            @"(?i)(set-cookie|authorization|cookie)\s*:\s*[^\r\n]+",
            "$1: [SENSITIVE]");
}
