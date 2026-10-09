using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Axiam.Sdk.Tests.Fixtures;

/// <summary>
/// A fake transport that records every request as it is sent — method, absolute URI, every
/// header and the body text — so a test can assert what went on the wire, including the
/// headers <see cref="RoutingHandler"/> and the management test base do not keep.
/// </summary>
/// <remarks>
/// Routes are keyed on <c>"METHOD /path"</c>. A responder may throw an
/// <see cref="HttpRequestException"/> to simulate a dropped connection. An unrouted request
/// is answered <c>501</c> and recorded, so a test asserting "no request" sees it.
/// </remarks>
public sealed class CapturingHandler : HttpMessageHandler
{
    private readonly Dictionary<string, Func<Captured, HttpResponseMessage>> _routes = new(StringComparer.Ordinal);
    private readonly object _lock = new();

    /// <summary>Every request, in the order sent.</summary>
    public List<Captured> Requests { get; } = new();

    /// <summary>One recorded request.</summary>
    /// <param name="Method">The HTTP method.</param>
    /// <param name="Uri">The absolute request URI.</param>
    /// <param name="Headers">Every request and content header, name to values.</param>
    /// <param name="Body">The body text, or <c>null</c> when there was no content.</param>
    public sealed record Captured(
        string Method, Uri Uri, IReadOnlyDictionary<string, IReadOnlyList<string>> Headers, string? Body)
    {
        /// <summary>The values of <paramref name="name"/>, case-insensitively, or empty.</summary>
        public IReadOnlyList<string> Header(string name) =>
            Headers.Where(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
                .SelectMany(h => h.Value).ToList();

        /// <summary>The form body as a dictionary (application/x-www-form-urlencoded).</summary>
        public Dictionary<string, string> Form()
        {
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string pair in (Body ?? string.Empty).Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                string[] kv = pair.Split('=', 2);
                result[Uri.UnescapeDataString(kv[0].Replace('+', ' '))] =
                    kv.Length > 1 ? Uri.UnescapeDataString(kv[1].Replace('+', ' ')) : string.Empty;
            }

            return result;
        }

        /// <summary>The query parameters, decoded.</summary>
        public Dictionary<string, string> Query()
        {
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string pair in Uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                string[] kv = pair.Split('=', 2);
                result[Uri.UnescapeDataString(kv[0])] = kv.Length > 1 ? Uri.UnescapeDataString(kv[1]) : string.Empty;
            }

            return result;
        }
    }

    /// <summary>Routes <paramref name="method"/> <paramref name="path"/> to <paramref name="responder"/>.</summary>
    public void Map(string method, string path, Func<Captured, HttpResponseMessage> responder) =>
        _routes[$"{method} {path}"] = responder;

    /// <summary>The requests sent to <paramref name="path"/>.</summary>
    public IReadOnlyList<Captured> To(string path)
    {
        lock (_lock)
        {
            return Requests.Where(r => r.Uri.AbsolutePath == path).ToList();
        }
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers)
        {
            headers[header.Key] = header.Value.ToList();
        }

        string? body = null;
        if (request.Content is not null)
        {
            foreach (KeyValuePair<string, IEnumerable<string>> header in request.Content.Headers)
            {
                headers[header.Key] = header.Value.ToList();
            }

            body = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        }

        var captured = new Captured(request.Method.Method, request.RequestUri!, headers, body);
        lock (_lock)
        {
            Requests.Add(captured);
        }

        return _routes.TryGetValue($"{request.Method.Method} {request.RequestUri!.AbsolutePath}", out var responder)
            ? responder(captured)
            : new HttpResponseMessage(HttpStatusCode.NotImplemented);
    }

    /// <summary>A JSON response.</summary>
    public static HttpResponseMessage Json(int status, string json) =>
        new((HttpStatusCode)status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    /// <summary>A bodiless response.</summary>
    public static HttpResponseMessage Status(int status) => new((HttpStatusCode)status);
}

/// <summary>Run-time secrets and the redaction assertion (no literal credential in any test).</summary>
public static class Secrets
{
    /// <summary>A fresh 256-bit base64url value — a token, a secret, an <c>auth_req_id</c>.</summary>
    public static string Fresh() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// Fails when any 8-character substring of <paramref name="secret"/> occurs in
    /// <paramref name="rendering"/>. The failure message names the label and an offset only —
    /// never the secret, a fragment of it, or the rendering.
    /// </summary>
    public static void AssertAbsent(string rendering, string secret, string label)
    {
        for (int i = 0; i + 8 <= secret.Length; i++)
        {
            if (rendering.Contains(secret.Substring(i, 8), StringComparison.Ordinal))
            {
                Assert.Fail($"{label}: a fragment of the secret (offset {i}) appears in the rendering");
            }
        }
    }
}
