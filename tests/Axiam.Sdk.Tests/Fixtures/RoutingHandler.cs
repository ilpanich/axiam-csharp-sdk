using System.Net;
using System.Net.Http;

namespace Axiam.Sdk.Tests.Fixtures;

/// <summary>
/// A tiny fake <see cref="HttpMessageHandler"/> that dispatches by request path to a
/// caller-registered responder, recording every request it saw. Shared by the &#167;12 OIDC
/// test suites (mirrors the equivalent private helper in
/// <c>AxiamClientAuthFlowTests</c>, promoted here so multiple OIDC test files can reuse it).
/// </summary>
public sealed class RoutingHandler : HttpMessageHandler
{
    private readonly Dictionary<string, Func<HttpRequestMessage, HttpResponseMessage>> _routes = new();
    private readonly object _lock = new();

    /// <summary>Every request this handler has dispatched, in arrival order. Thread-safe
    /// for concurrency tests.</summary>
    public List<HttpRequestMessage> Requests { get; } = new();

    /// <summary>Registers <paramref name="responder"/> for requests whose absolute path is
    /// exactly <paramref name="path"/> (query string ignored).</summary>
    public void Map(string path, Func<HttpRequestMessage, HttpResponseMessage> responder) => _routes[path] = responder;

    /// <inheritdoc />
    /// <remarks>
    /// Dispatches the registered responder via <see cref="Task.Run(Func{HttpResponseMessage},CancellationToken)"/>
    /// — deliberately NOT a synchronous <c>Task.FromResult(responder(request))</c> — so a
    /// responder that blocks (e.g. a concurrency test's <c>SemaphoreSlim.Wait</c> gate)
    /// cannot also block the CALLER's thread. Without this, a synchronous
    /// <see cref="HttpMessageHandler.SendAsync"/> override blocks all the way up the
    /// synchronous prefix of every async caller in the chain (this SDK's own
    /// <c>AxiamHttpMessageHandler.SendAsync</c> included), which would silently serialize
    /// what a concurrency test intends to be genuinely-overlapping concurrent calls —
    /// exactly the kind of false-pass this handler must not produce.
    /// </remarks>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        lock (_lock)
        {
            Requests.Add(request);
        }

        string path = request.RequestUri!.AbsolutePath;
        if (_routes.TryGetValue(path, out Func<HttpRequestMessage, HttpResponseMessage>? responder))
        {
            return await Task.Run(() => responder(request), cancellationToken).ConfigureAwait(false);
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    /// <summary>Number of requests dispatched to <paramref name="path"/> so far.</summary>
    public int CountFor(string path)
    {
        lock (_lock)
        {
            return Requests.Count(r => r.RequestUri!.AbsolutePath == path);
        }
    }
}
