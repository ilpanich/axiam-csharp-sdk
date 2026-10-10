using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Axiam.Sdk.Rest;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;6: a custom CA is <i>additive trust in who may sign</i>; it does not waive the check that
/// the certificate names the host. Over a real TLS server, on reads and on writes (the write path has its
/// own handler, &#167;34.2 P11).
/// </summary>
[Trait("Category", "Fast")]
public sealed class CustomCaHostnameTests
{
    private static (byte[] CaPem, X509Certificate2 Leaf) CaAndLeaf(Action<SubjectAlternativeNameBuilder> names)
    {
        using ECDsa caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest("CN=Axiam Test CA", caKey, HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using X509Certificate2 ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));

        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN=leaf", leafKey, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        names(san);
        leafRequest.CertificateExtensions.Add(san.Build());
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        byte[] serial = RandomNumberGenerator.GetBytes(8);
        using X509Certificate2 signed = leafRequest.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), serial);
        using X509Certificate2 withKey = signed.CopyWithPrivateKey(leafKey);
        return (Encoding.ASCII.GetBytes(ca.ExportCertificatePem()), new X509Certificate2(withKey.Export(X509ContentType.Pfx)));
    }

    private static HttpClient Client(DroppingServer server, byte[] caPem, out HttpClientHandler handler)
    {
        handler = AxiamHttpClientFactory.CreatePrimaryHandler(caPem);
        return new HttpClient(handler, disposeHandler: false) { BaseAddress = server.BaseUri, Timeout = TimeSpan.FromSeconds(20) };
    }

    private static HttpRequestMessage Post(string path) => new(HttpMethod.Post, path) { Content = new StringContent("{}") };

    [Fact]
    public async Task ACertificateFromTheCustomCaForTheRightHostIsAcceptedOnReadsAndWrites()
    {
        (byte[] caPem, X509Certificate2 leaf) = CaAndLeaf(s => s.AddIpAddress(IPAddress.Loopback));
        using (leaf)
        using (var server = new DroppingServer(leaf))
        using (HttpClient client = Client(server, caPem, out HttpClientHandler handler))
        using (handler)
        {
            using HttpResponseMessage read = await client.GetAsync("/ok");
            Assert.Equal(HttpStatusCode.OK, read.StatusCode);
            using HttpResponseMessage write = await client.SendAsync(Post("/ok-write"));
            Assert.Equal(HttpStatusCode.OK, write.StatusCode);
        }
    }

    [Fact]
    public async Task ACertificateFromTheCustomCaForTheWrongHostIsRefusedOnReadsAndWrites()
    {
        // Signed by the configured CA, but it names another host than the one connected to (127.0.0.1).
        (byte[] caPem, X509Certificate2 leaf) = CaAndLeaf(s => s.AddDnsName("elsewhere.example"));
        using (leaf)
        using (var server = new DroppingServer(leaf))
        using (HttpClient client = Client(server, caPem, out HttpClientHandler handler))
        using (handler)
        {
            await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync("/wrong-host"));
            await Assert.ThrowsAsync<HttpRequestException>(() => client.SendAsync(Post("/wrong-host-write")));
            Assert.Empty(server.Requests);
        }
    }

    [Fact]
    public void NoCertificateAndANameMismatchAreRefusedWhateverTheChainSays()
    {
        (byte[] caPem, X509Certificate2 leaf) = CaAndLeaf(s => s.AddIpAddress(IPAddress.Loopback));
        using (leaf)
        using (var ca = new X509Certificate2(caPem))
        using (var chain = new X509Chain { ChainPolicy = { RevocationMode = X509RevocationMode.NoCheck } }) // as SslStream's own chain
        {
            // The chain really does build to the custom CA...
            Assert.True(AxiamHttpClientFactory.TrustThroughCustomCa(ca, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));

            // ...and still: only the chain error may be resolved by it.
            Assert.False(AxiamHttpClientFactory.TrustThroughCustomCa(
                ca, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch));
            Assert.False(AxiamHttpClientFactory.TrustThroughCustomCa(ca, leaf, chain, SslPolicyErrors.RemoteCertificateNameMismatch));
            Assert.False(AxiamHttpClientFactory.TrustThroughCustomCa(ca, leaf, chain, SslPolicyErrors.RemoteCertificateNotAvailable));
            Assert.False(AxiamHttpClientFactory.TrustThroughCustomCa(ca, null, chain, SslPolicyErrors.RemoteCertificateNotAvailable));

            // The same through the callback the primary handler installs.
            HttpClientHandler handler = AxiamHttpClientFactory.CreatePrimaryHandler(caPem);
            using (handler)
            {
                var callback = handler.ServerCertificateCustomValidationCallback!;
                using var request = new HttpRequestMessage();
                Assert.False(callback(request, null, chain, SslPolicyErrors.RemoteCertificateNotAvailable));
                Assert.False(callback(request, leaf, chain, SslPolicyErrors.RemoteCertificateNameMismatch));
            }
        }
    }
}
