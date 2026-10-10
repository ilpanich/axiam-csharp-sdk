using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Rest;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;34.2 P11 (contract 1.60, row A6): a write the SDK never retries is not re-sent by
/// the HTTP library either. The test the contract names &#8212; "a server that reads a write and drops the
/// connection unanswered receives that write exactly once" &#8212; against a real TCP server, because the
/// re-send happens inside <see cref="SocketsHttpHandler"/>, below any handler a test could mount.
/// </summary>
/// <remarks>
/// The interesting case is a write that would have been put on a <i>pooled</i> connection: .NET re-sends
/// a request whose pooled connection ends before the first response byte. Each test therefore first
/// warms the pool with a read, then sends the write. (With the isolation removed, the same tests see the
/// dropped write arrive twice.)
/// </remarks>
[Trait("Category", "Fast")]
public sealed class WriteConnectionTests
{
    private static HttpClient Client(DroppingServer server, out HttpClientHandler handler, byte[]? customCaPem = null)
    {
        handler = AxiamHttpClientFactory.CreatePrimaryHandler(customCaPem);
        return new HttpClient(handler, disposeHandler: false) { BaseAddress = server.BaseUri, Timeout = TimeSpan.FromSeconds(20) };
    }

    private static HttpRequestMessage Write(string method, string path, bool body = true) => new(new HttpMethod(method), path)
    {
        Content = body ? new StringContent("{\"x\":1}", Encoding.UTF8, "application/json") : null,
    };

    /// <summary>
    /// &#167;34.2 P11 test: a server that reads a write and drops the connection unanswered receives it
    /// <b>exactly once</b> &#8212; every verb, with and without a body, whether the server drops after the whole
    /// request or after the headers, and with a pooled keep-alive connection available or not.
    /// </summary>
    [Theory]
    [InlineData("POST", true, "/drop", true)]
    [InlineData("POST", false, "/drop", true)]
    [InlineData("PUT", true, "/drop", true)]
    [InlineData("PUT", false, "/drop", true)]
    [InlineData("PATCH", true, "/drop", true)]
    [InlineData("PATCH", false, "/drop", true)]
    [InlineData("DELETE", false, "/drop", true)]
    [InlineData("DELETE", true, "/drop", true)]
    [InlineData("POST", true, "/drop", false)]
    [InlineData("POST", false, "/drop", false)]
    [InlineData("DELETE", false, "/drop", false)]
    [InlineData("POST", true, "/drop-after-headers", true)]
    [InlineData("POST", false, "/drop-after-headers", true)]
    [InlineData("DELETE", false, "/drop-after-headers", true)]
    [InlineData("PUT", false, "/drop-after-headers", false)]
    public async Task AWriteTheServerDropsUnansweredArrivesExactlyOnce(string method, bool body, string path, bool warmThePool)
    {
        using var server = new DroppingServer();
        using HttpClient client = Client(server, out HttpClientHandler handler);
        using (handler)
        {
            if (warmThePool)
            {
                // Pool a keep-alive connection first: the write must not be put on it.
                using HttpResponseMessage warm = await client.GetAsync("/warm");
                Assert.Equal(HttpStatusCode.OK, warm.StatusCode);
            }

            await Assert.ThrowsAsync<HttpRequestException>(() => client.SendAsync(Write(method, path, body)));

            string seen = string.Join(" | ", server.Requests.Select(r => $"{r.ConnectionId}:{r.Method} {r.Path}"));
            Assert.True(server.For(path).Count == 1, $"the dropped write arrived {server.For(path).Count} times: {seen}");
            WireRequest only = server.For(path)[0];
            Assert.Equal(method, only.Method);
            Assert.Equal("close", only.Headers["connection"]);
            if (warmThePool)
            {
                // A fresh connection, not the pooled one the read warmed.
                Assert.NotEqual(Assert.Single(server.For("/warm")).ConnectionId, only.ConnectionId);
            }
        }
    }

    /// <summary>The same through the public client: a write the server drops is received once, and is the SDK's NetworkError.</summary>
    [Fact]
    public async Task AWriteThroughAxiamClientIsReceivedOnceAfterAPooledConnectionExists()
    {
        using var server = new DroppingServer { Drops = path => path.EndsWith("/resend-verification", StringComparison.Ordinal) };
        using var client = new AxiamClient(
            server.BaseUri,
            "7c1e0a52-52a4-4b2c-9d50-0d0a8f3c1b11",
            new AxiamClientOptions { BaseUrl = server.BaseUri, TenantId = "7c1e0a52-52a4-4b2c-9d50-0d0a8f3c1b11", MaxRetryAttempts = 1 });

        // A retry-eligible POST (authz/check) shares the pool and leaves a keep-alive connection in it.
        await client.Authz.CheckAccessAsync("documents:read", Guid.NewGuid());
        Assert.Single(server.For("/api/v1/authz/check"));

        // A write: the server reads it and drops the connection unanswered.
        await Assert.ThrowsAsync<NetworkError>(
            () => client.ResendVerificationAsync("someone@example.test", Guid.Parse("7c1e0a52-52a4-4b2c-9d50-0d0a8f3c1b11")));
        WireRequest only = Assert.Single(server.For("/api/v1/auth/resend-verification"));
        Assert.Equal("POST", only.Method);
        Assert.Equal("close", only.Headers["connection"]);
    }

    /// <summary>Each write gets its own connection and tells the server it is the last on it; a read keeps the pool.</summary>
    [Fact]
    public async Task EveryWriteGetsItsOwnConnectionAndReadsKeepThePool()
    {
        using var server = new DroppingServer();
        using HttpClient client = Client(server, out HttpClientHandler handler);
        using (handler)
        {
            for (int i = 0; i < 3; i++)
            {
                using HttpResponseMessage r = await client.SendAsync(Write("POST", "/w"));
                Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            }

            IReadOnlyList<WireRequest> writes = server.For("/w");
            Assert.Equal(3, writes.Count);
            Assert.Equal(3, writes.Select(w => w.ConnectionId).Distinct().Count());
            Assert.All(writes, w => Assert.Equal("close", w.Headers["connection"]));
            Assert.All(writes, w => Assert.Equal("{\"x\":1}", w.Body));

            // Reads are unchanged: two reads share one connection.
            (await client.GetAsync("/r")).Dispose();
            (await client.GetAsync("/r")).Dispose();
            IReadOnlyList<WireRequest> reads = server.For("/r");
            Assert.Equal(2, reads.Count);
            Assert.Equal(reads[0].ConnectionId, reads[1].ConnectionId);
            Assert.DoesNotContain("connection", reads[0].Headers.Keys.Where(k => reads[0].Headers[k] == "close"));
        }
    }

    /// <summary>A request &#167;16 retries anyway (authz/check, ciba_poll, ssf.poll) may share the pool; nothing else does.</summary>
    [Fact]
    public async Task OnlyAMarkedRetryEligiblePostSharesThePool()
    {
        using var server = new DroppingServer();
        using HttpClient client = Client(server, out HttpClientHandler handler);
        using (handler)
        {
            for (int i = 0; i < 2; i++)
            {
                var marked = new HttpRequestMessage(HttpMethod.Post, "/check") { Content = new StringContent("{}") };
                using HttpResponseMessage r = await client.SendAsync(ConnectionPolicy.MarkRetryEligible(marked));
            }

            IReadOnlyList<WireRequest> checks = server.For("/check");
            Assert.Equal(checks[0].ConnectionId, checks[1].ConnectionId);
            Assert.DoesNotContain("close", checks.Select(c => c.Headers.GetValueOrDefault("connection", string.Empty)));

            using HttpResponseMessage unmarked = await client.SendAsync(Write("POST", "/check-unmarked"));
            Assert.NotEqual(checks[0].ConnectionId, Assert.Single(server.For("/check-unmarked")).ConnectionId);
        }
    }

    [Theory]
    [InlineData("GET", false, false)]
    [InlineData("HEAD", false, false)]
    [InlineData("OPTIONS", false, false)]
    [InlineData("POST", false, true)]
    [InlineData("PUT", false, true)]
    [InlineData("PATCH", false, true)]
    [InlineData("DELETE", false, true)]
    [InlineData("POST", true, false)]
    public void TheRoutingRuleIsSafeMethodsAndMarkedRequestsShareThePool(string method, bool marked, bool fresh)
    {
        var request = new HttpRequestMessage(new HttpMethod(method), "/x");
        if (marked)
        {
            ConnectionPolicy.MarkRetryEligible(request);
        }

        Assert.Equal(fresh, ConnectionPolicy.NeedsFreshConnection(request));
    }

    /// <summary>The write path shares the primary handler's cookie jar: a cookie a write sets is sent on the next read.</summary>
    [Fact]
    public async Task TheWritePathSharesTheCookieJar()
    {
        using var server = new DroppingServer();
        using HttpClient client = Client(server, out HttpClientHandler handler);
        using (handler)
        {
            using (HttpResponseMessage r = await client.SendAsync(Write("POST", "/set-cookie")))
            {
                Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            }

            Assert.Equal("issued", handler.CookieContainer.GetCookies(server.BaseUri)["axiam_access"]?.Value);
            using HttpResponseMessage read = await client.GetAsync("/after");
            Assert.Equal("axiam_access=issued", Assert.Single(server.For("/after")).Headers["cookie"]);

            // And the other way round: the next write carries the cookie.
            using HttpResponseMessage write = await client.SendAsync(Write("PUT", "/after-write"));
            Assert.Equal("axiam_access=issued", Assert.Single(server.For("/after-write")).Headers["cookie"]);
        }
    }

    /// <summary>The write path keeps &#167;6: the additive custom CA is trusted on it, and an untrusted server is refused on it.</summary>
    [Fact]
    public async Task TheWritePathKeepsStrictTlsAndTheAdditiveCustomCa()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using X509Certificate2 created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var serverCertificate = new X509Certificate2(created.Export(X509ContentType.Pfx));
        byte[] caPem = Encoding.ASCII.GetBytes(created.ExportCertificatePem());

        using var server = new DroppingServer(serverCertificate);

        // Trusted through the custom CA: a read and a write both succeed.
        using (HttpClient trusting = Client(server, out HttpClientHandler trustingHandler, caPem))
        using (trustingHandler)
        {
            using HttpResponseMessage read = await trusting.GetAsync("/tls");
            Assert.Equal(HttpStatusCode.OK, read.StatusCode);
            using HttpResponseMessage write = await trusting.SendAsync(Write("POST", "/tls-write"));
            Assert.Equal(HttpStatusCode.OK, write.StatusCode);
        }

        // No custom CA: the system store does not trust it, and the write path refuses it too -- no bypass.
        using (HttpClient strict = Client(server, out HttpClientHandler strictHandler))
        using (strictHandler)
        {
            await Assert.ThrowsAsync<HttpRequestException>(() => strict.SendAsync(Write("POST", "/tls-untrusted")));
            await Assert.ThrowsAsync<HttpRequestException>(() => strict.GetAsync("/tls-untrusted"));
            Assert.Empty(server.For("/tls-untrusted"));
        }
    }

    /// <summary>Disposing the handler disposes the write path; a write afterwards is refused, not sent.</summary>
    [Fact]
    public async Task DisposeReleasesTheWriteHandler()
    {
        using var server = new DroppingServer();
        HttpClient client = Client(server, out HttpClientHandler handler);
        (await client.SendAsync(Write("POST", "/before"))).Dispose();
        handler.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.SendAsync(Write("POST", "/after")));
        Assert.Empty(server.For("/after"));
    }
}
