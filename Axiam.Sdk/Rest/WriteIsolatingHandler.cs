using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Axiam.Sdk.Rest;

/// <summary>
/// CONTRACT.md &#167;34.2 P11 (contract 1.60, row A6): a write the SDK never retries is also never
/// re-sent by the HTTP library underneath it.
/// </summary>
/// <remarks>
/// <para>
/// <b>The mechanism.</b> <see cref="SocketsHttpHandler"/> re-sends a request without telling the caller
/// when the connection ends before a single byte of the response arrives. For a read that is harmless.
/// For a <c>POST</c>, <c>PUT</c>, <c>PATCH</c> or <c>DELETE</c> the SDK refuses to retry (&#167;28.12.2 rule
/// 5, &#167;29.7, &#167;30.7, &#167;31.7, &#167;32's writes, &#167;33.7 rule 1) it is a second request nobody asked
/// for. .NET offers no switch to turn the re-send off. Measured against a server that reads a request
/// and closes the connection unanswered, on .NET 8:
/// </para>
/// <list type="bullet">
///   <item>a request <b>with no content</b> (a <c>DELETE</c>, or a <c>POST</c>/<c>PUT</c>/<c>PATCH</c> built
///     without a body) arrives <b>four times</b> &#8212; the original and three re-sends &#8212; on a fresh
///     connection as much as on a pooled one;</item>
///   <item>the same request given an <b>empty content</b> arrives once;</item>
///   <item>a request with a body arrives once in this exchange, but is exposed to the other half of the
///     library's behaviour &#8212; a pooled connection the server closed while it was idle is retried on
///     another &#8212; which is what the fresh connection removes.</item>
/// </list>
/// <para>
/// So a write gets <b>both</b> remedies &#167;34.2 P11 allows for: it carries content (an empty
/// <see cref="ByteArrayContent"/> when the caller built none, which puts <c>Content-Length: 0</c> on the
/// wire, as .NET already does for a body-less <c>POST</c>), and it goes on a <b>fresh connection that is
/// not reused afterwards</b>, so there is no pooled connection to be re-sent from and none left behind
/// for the next write.
/// </para>
/// <para>
/// <b>What is a "write".</b> Every request whose method is not <c>GET</c>, <c>HEAD</c>, <c>OPTIONS</c> or
/// <c>TRACE</c>, except one marked with <see cref="ConnectionPolicy.MarkRetryEligible"/>: the
/// side-effect-free <c>POST</c>s that &#167;16 itself retries (<c>authz/check</c>, <c>authz/check/batch</c>,
/// <c>ciba_poll</c>, <c>ssf.poll</c>). Those stay on the shared pool &#8212; a re-send of a request the SDK
/// would retry anyway costs nothing and a connection per authorization check would. The default is the
/// safe one: a new write the marker was never added to gets the fresh connection.
/// </para>
/// <para>
/// <b>How.</b> Writes are sent through a second, private <see cref="SocketsHttpHandler"/> whose
/// <see cref="SocketsHttpHandler.PooledConnectionLifetime"/> is <see cref="TimeSpan.Zero"/>: a
/// connection is expired from the moment it is made, so it is closed when its exchange ends and never
/// returned to a pool another write could take it from. Every write also carries
/// <c>Connection: close</c> (<see cref="System.Net.Http.Headers.HttpRequestHeaders.ConnectionClose"/>),
/// which makes the same promise to the server and to any proxy in between. The private handler shares
/// this handler's cookie jar, redirect policy, proxy settings, client certificate and additive
/// custom-CA chain trust &#8212; the TLS policy is built once, by <see cref="AxiamHttpClientFactory"/>, and
/// is neither widened nor duplicated here.
/// </para>
/// <para>
/// <b>Not covered.</b> An application that supplies its own handler through
/// <c>IHttpClientFactory</c> (<see cref="AxiamHttpClientFactory.ConfigureFactoryHandler"/>) owns that
/// handler's pool; this class cannot reach it. The gRPC channel is a different transport and is not
/// routed through here.
/// </para>
/// </remarks>
internal sealed class WriteIsolatingHandler : HttpClientHandler
{
    private readonly X509Certificate2? _customCa;
    private readonly X509Certificate2? _clientCertificate;
    private readonly object _gate = new();
    private HttpMessageInvoker? _writes;
    private bool _disposed;

    /// <summary>Builds the handler; the TLS inputs are the ones <see cref="AxiamHttpClientFactory.CreatePrimaryHandler"/> parsed.</summary>
    /// <param name="customCa">The additive custom CA (&#167;6), or <c>null</c>.</param>
    /// <param name="clientCertificate">The &#167;6.1 mTLS identity, or <c>null</c>.</param>
    internal WriteIsolatingHandler(X509Certificate2? customCa, X509Certificate2? clientCertificate)
    {
        _customCa = customCa;
        _clientCertificate = clientCertificate;
    }

    /// <inheritdoc />
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!ConnectionPolicy.NeedsFreshConnection(request))
        {
            return base.SendAsync(request, cancellationToken);
        }

        // A request with no content is re-sent by the library on a dropped connection, up to three
        // times and on a fresh connection too; one with (even empty) content is not. See the remarks.
        request.Content ??= new ByteArrayContent(Array.Empty<byte>());

        // The server is told too: this connection carries one request and is then closed.
        request.Headers.ConnectionClose = true;
        return WriteInvoker().SendAsync(request, cancellationToken);
    }

    private HttpMessageInvoker WriteInvoker()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _writes ??= new HttpMessageInvoker(BuildWriteHandler(), disposeHandler: true);
        }
    }

    // Built on the first write rather than in the constructor so it mirrors the handler's state at
    // that moment: UseCookies and CookieContainer are changed after construction by the sessionless
    // client (UseCookies = false), and a SocketsHttpHandler refuses to change once it has sent.
    private SocketsHttpHandler BuildWriteHandler()
    {
        var handler = new SocketsHttpHandler
        {
            UseCookies = UseCookies,
            CookieContainer = CookieContainer,
            AllowAutoRedirect = false, // SDK-17: never follow a redirect with the SDK's headers
            // The point of this handler: a connection is already past its lifetime when it is made,
            // so it is closed after its exchange and never offered to a later request.
            PooledConnectionLifetime = TimeSpan.Zero,
            UseProxy = UseProxy,
        };

        if (UseProxy && Proxy is not null)
        {
            handler.Proxy = Proxy;
        }

        if (_clientCertificate is not null)
        {
            // §6.1: what the client OFFERS; server verification is untouched.
            handler.SslOptions.ClientCertificates = new X509CertificateCollection { _clientCertificate };
        }

        if (_customCa is not null)
        {
            X509Certificate2 customCa = _customCa;
            // The same additive CustomTrustStore trust the primary handler installs, through the
            // same function (AxiamHttpClientFactory.TrustThroughCustomCa) -- never `=> true`.
            handler.SslOptions.RemoteCertificateValidationCallback = (_, cert, chain, sslPolicyErrors) =>
                AxiamHttpClientFactory.TrustThroughCustomCa(
                    customCa,
                    cert is null ? null : cert as X509Certificate2 ?? new X509Certificate2(cert),
                    chain,
                    sslPolicyErrors);
        }

        return handler;
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            lock (_gate)
            {
                _disposed = true;
                _writes?.Dispose();
                _writes = null;
            }
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// Which requests need the fresh connection of <see cref="WriteIsolatingHandler"/> (CONTRACT.md
/// &#167;34.2 P11).
/// </summary>
internal static class ConnectionPolicy
{
    private static readonly HttpRequestOptionsKey<bool> RetryEligibleKey = new("axiam-sdk-retry-eligible");

    /// <summary>
    /// Marks <paramref name="request"/> as a request the SDK itself retries under &#167;16 although its
    /// method is not a read (<c>authz/check</c>, <c>ciba_poll</c>, <c>ssf.poll</c>): it may share the
    /// pool. Never call this for a request that must reach the server at most once.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>The same request, for chaining.</returns>
    internal static HttpRequestMessage MarkRetryEligible(HttpRequestMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Options.Set(RetryEligibleKey, true);
        return request;
    }

    /// <summary>Whether <paramref name="request"/> was marked by <see cref="MarkRetryEligible"/>.</summary>
    /// <param name="request">The request.</param>
    /// <returns><c>true</c> when it was.</returns>
    internal static bool IsRetryEligible(HttpRequestMessage request) =>
        request.Options.TryGetValue(RetryEligibleKey, out bool eligible) && eligible;

    /// <summary>
    /// <c>true</c> for a request that must go on a fresh connection that is not reused: a method that
    /// is not safe, and not marked retry-eligible.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <returns>Whether the write handler must carry it.</returns>
    internal static bool NeedsFreshConnection(HttpRequestMessage request)
    {
        HttpMethod method = request.Method;
        bool safe = method == HttpMethod.Get || method == HttpMethod.Head
            || method == HttpMethod.Options || method == HttpMethod.Trace;
        return !safe && !IsRetryEligible(request);
    }
}
