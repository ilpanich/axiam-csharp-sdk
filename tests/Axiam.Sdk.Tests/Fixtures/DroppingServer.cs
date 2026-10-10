using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Axiam.Sdk.Tests.Fixtures;

/// <summary>One request as the <see cref="DroppingServer"/> read it off a socket.</summary>
/// <param name="ConnectionId">Which accepted connection it arrived on (1-based).</param>
/// <param name="Method">The request method.</param>
/// <param name="Path">The request target.</param>
/// <param name="Headers">Header name (lower-cased) to value.</param>
/// <param name="Body">The request body.</param>
public sealed record WireRequest(int ConnectionId, string Method, string Path, IReadOnlyDictionary<string, string> Headers, string Body);

/// <summary>
/// A real TCP server for CONTRACT.md &#167;34.2 P11's test: it reads a request and <b>drops the connection
/// without answering</b> when the target starts with <c>/drop</c>, answers <c>200</c> on a kept-alive
/// connection otherwise, and records every request it read &#8212; so a test can count how many times a
/// write arrived. A mock HTTP handler cannot do this: the re-send under test happens inside the HTTP
/// library, below any handler a test could mount.
/// </summary>
public sealed class DroppingServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly X509Certificate2? _tlsCertificate;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentQueue<WireRequest> _requests = new();
    private readonly object _gate = new();
    private int _connections;

    /// <summary>Starts the server; with <paramref name="tlsCertificate"/> it speaks TLS.</summary>
    /// <param name="tlsCertificate">The server certificate (with private key), or <c>null</c> for plain HTTP.</param>
    public DroppingServer(X509Certificate2? tlsCertificate = null)
    {
        _tlsCertificate = tlsCertificate;
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = Task.Run(AcceptLoopAsync);
    }

    /// <summary>
    /// Which request targets the server reads and then drops unanswered; <c>/drop…</c> by default. A
    /// target that starts with <c>/drop-after-headers</c> is dropped as soon as the headers are read,
    /// with the body unread.
    /// </summary>
    public Func<string, bool> Drops { get; set; } = path => path.StartsWith("/drop", StringComparison.Ordinal);

    /// <summary>The listening port.</summary>
    public int Port { get; }

    /// <summary>The server's base address.</summary>
    public Uri BaseUri => new($"{(_tlsCertificate is null ? "http" : "https")}://127.0.0.1:{Port}");

    /// <summary>How many connections have been accepted.</summary>
    public int Connections => Volatile.Read(ref _connections);

    /// <summary>Every request read so far, in arrival order.</summary>
    public IReadOnlyList<WireRequest> Requests => _requests.ToArray();

    /// <summary>The requests that arrived for <paramref name="path"/>.</summary>
    /// <param name="path">The request target.</param>
    /// <returns>The matching requests.</returns>
    public IReadOnlyList<WireRequest> For(string path) => _requests.Where(r => r.Path == path).ToArray();

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient client = await _listener.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false);
                int id = Interlocked.Increment(ref _connections);
                _ = Task.Run(() => ServeAsync(client, id));
            }
        }
        catch (Exception)
        {
            // listener stopped
        }
    }

    private async Task ServeAsync(TcpClient client, int id)
    {
        using (client)
        {
            try
            {
                Stream stream = client.GetStream();
                if (_tlsCertificate is not null)
                {
                    var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                    await ssl.AuthenticateAsServerAsync(_tlsCertificate).ConfigureAwait(false);
                    stream = ssl;
                }

                while (!_stop.IsCancellationRequested)
                {
                    WireRequest? request = await ReadRequestAsync(stream, id).ConfigureAwait(false);
                    if (request is null)
                    {
                        return;
                    }

                    _requests.Enqueue(request);
                    if (Drops(request.Path))
                    {
                        // Read the request, answer nothing, close: the case P11 is about.
                        return;
                    }

                    bool close = request.Headers.TryGetValue("connection", out string? c) &&
                                 c.Contains("close", StringComparison.OrdinalIgnoreCase);
                    string extra = request.Path == "/set-cookie" ? "Set-Cookie: axiam_access=issued; Path=/\r\n" : string.Empty;
                    byte[] reply = Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n{extra}" +
                        $"{(close ? "Connection: close\r\n" : string.Empty)}\r\n{{}}");
                    await stream.WriteAsync(reply).ConfigureAwait(false);
                    await stream.FlushAsync().ConfigureAwait(false);
                    if (close)
                    {
                        return;
                    }
                }
            }
            catch (Exception)
            {
                // a client that hung up or failed its handshake
            }
        }
    }

    private static async Task<WireRequest?> ReadRequestAsync(Stream stream, int id)
    {
        var head = new List<byte>();
        var one = new byte[1];
        while (true)
        {
            int n = await stream.ReadAsync(one).ConfigureAwait(false);
            if (n == 0)
            {
                return null;
            }

            head.Add(one[0]);
            int count = head.Count;
            if (count >= 4 && head[count - 4] == '\r' && head[count - 3] == '\n' && head[count - 2] == '\r' && head[count - 1] == '\n')
            {
                break;
            }
        }

        string[] lines = Encoding.ASCII.GetString(head.ToArray()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        string[] first = lines[0].Split(' ');
        var headers = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in lines.Skip(1))
        {
            int colon = line.IndexOf(':');
            headers[line[..colon].Trim().ToLowerInvariant()] = line[(colon + 1)..].Trim();
        }

        string body = string.Empty;
        if (first[1].StartsWith("/drop-after-headers", StringComparison.Ordinal))
        {
            return new WireRequest(id, first[0], first[1], headers, body);
        }

        if (headers.TryGetValue("content-length", out string? length) && int.TryParse(length, out int bytes) && bytes > 0)
        {
            var buffer = new byte[bytes];
            int read = 0;
            while (read < bytes)
            {
                int n = await stream.ReadAsync(buffer.AsMemory(read)).ConfigureAwait(false);
                if (n == 0)
                {
                    return null;
                }

                read += n;
            }

            body = Encoding.UTF8.GetString(buffer);
        }

        return new WireRequest(id, first[0], first[1], headers, body);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_gate)
        {
            _stop.Cancel();
            _listener.Stop();
        }
    }
}
