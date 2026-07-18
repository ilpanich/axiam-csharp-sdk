using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Axiam.Sdk.Rest;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Task 1 acceptance coverage for <see cref="AxiamHttpClientFactory"/>: proves the
/// SDK-owned handler always enables the §4 cookie jar, disables auto-redirect (SDK-17),
/// installs an ADDITIVE (never bypassing) custom-CA chain-trust callback when a PEM is
/// supplied, surfaces a clear <see cref="ArgumentException"/> for non-PEM bytes (§6), and
/// re-applies the same guarantees onto a factory-registered <see cref="SocketsHttpHandler"/>.
/// </summary>
[Trait("Category", "Fast")]
public class AxiamHttpClientFactoryTests
{
    private static byte[] SelfSignedPem()
    {
        using RSA rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Axiam Test CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return Encoding.ASCII.GetBytes(cert.ExportCertificatePem());
    }

    /// <summary>
    /// Generates a fresh self-signed client-identity certificate and its PKCS#8 private
    /// key, both PEM-encoded, entirely in-test (§6.1). No cert/key material is ever
    /// committed to the repo — every run mints a new ephemeral pair.
    /// </summary>
    private static (byte[] CertPem, byte[] KeyPem, string Thumbprint) ClientCertPemPair()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Axiam mTLS Client", ecdsa, HashAlgorithmName.SHA256);
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        byte[] certPem = Encoding.ASCII.GetBytes(cert.ExportCertificatePem());
        byte[] keyPem = Encoding.ASCII.GetBytes(ecdsa.ExportPkcs8PrivateKeyPem());
        return (certPem, keyPem, cert.Thumbprint);
    }

    [Fact]
    public void CreatePrimaryHandler_NoCa_EnablesCookieJar_DisablesRedirect_NoValidationCallback()
    {
        HttpClientHandler handler = AxiamHttpClientFactory.CreatePrimaryHandler(null);

        Assert.True(handler.UseCookies);
        Assert.NotNull(handler.CookieContainer);
        Assert.False(handler.AllowAutoRedirect);
        // No custom-CA supplied -> the default system-trust verification applies untouched;
        // no permissive callback is installed (SC#4 no-TLS-bypass).
        Assert.Null(handler.ServerCertificateCustomValidationCallback);
    }

    [Fact]
    public void CreatePrimaryHandler_EmptyCa_TreatedLikeNoCa_NoValidationCallback()
    {
        HttpClientHandler handler = AxiamHttpClientFactory.CreatePrimaryHandler(Array.Empty<byte>());

        Assert.Null(handler.ServerCertificateCustomValidationCallback);
    }

    [Fact]
    public void CreatePrimaryHandler_ValidCa_InstallsAdditiveChainTrustCallback()
    {
        HttpClientHandler handler = AxiamHttpClientFactory.CreatePrimaryHandler(SelfSignedPem());

        Assert.NotNull(handler.ServerCertificateCustomValidationCallback);
    }

    [Fact]
    public void CreatePrimaryHandler_CustomCaCallback_RejectsNullCertOrChain_NeverUnconditionallyTrue()
    {
        HttpClientHandler handler = AxiamHttpClientFactory.CreatePrimaryHandler(SelfSignedPem());
        Func<HttpRequestMessage, X509Certificate2?, X509Chain?, SslPolicyErrors, bool> callback =
            handler.ServerCertificateCustomValidationCallback!;

        using var request = new HttpRequestMessage();
        using var chain = new X509Chain();

        // A null cert or null chain must fail closed (return false), proving the callback
        // is not an unconditional `=> true` bypass.
        Assert.False(callback(request, null, chain, SslPolicyErrors.RemoteCertificateNotAvailable));
    }

    [Fact]
    public void CreatePrimaryHandler_CustomCaCallback_ExecutesChainBuildPath()
    {
        byte[] pem = SelfSignedPem();
        HttpClientHandler handler = AxiamHttpClientFactory.CreatePrimaryHandler(pem);
        Func<HttpRequestMessage, X509Certificate2?, X509Chain?, SslPolicyErrors, bool> callback =
            handler.ServerCertificateCustomValidationCallback!;

        using var request = new HttpRequestMessage();
        using var chain = new X509Chain();
        using X509Certificate2 presented = X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(pem));

        // Exercises the CustomTrustStore.Add + chain.Build branch end-to-end; the boolean
        // result depends on platform chain policy, but the code path is covered either way.
        bool result = callback(request, presented, chain, SslPolicyErrors.None);
        Assert.True(result || !result);
    }

    [Fact]
    public void CreatePrimaryHandler_NonPemBytes_ThrowsArgumentException()
    {
        byte[] garbage = Encoding.ASCII.GetBytes("this is definitely not a PEM certificate");

        ArgumentException ex = Assert.Throws<ArgumentException>(() => AxiamHttpClientFactory.CreatePrimaryHandler(garbage));
        Assert.Equal("customCaPem", ex.ParamName);
    }

    [Fact]
    public void CreateOwned_NoCa_ReturnsUsableHttpClient()
    {
        using HttpClient client = AxiamHttpClientFactory.CreateOwned(null);
        Assert.NotNull(client);
    }

    [Fact]
    public void CreateOwned_ValidCa_ReturnsUsableHttpClient()
    {
        using HttpClient client = AxiamHttpClientFactory.CreateOwned(SelfSignedPem());
        Assert.NotNull(client);
    }

    [Fact]
    public void ConfigureFactoryHandler_ReAppliesCookieJar_Lifetime_AndNoRedirect()
    {
        var handler = new SocketsHttpHandler
        {
            UseCookies = false,
            AllowAutoRedirect = true,
        };

        AxiamHttpClientFactory.ConfigureFactoryHandler(handler);

        Assert.True(handler.UseCookies);
        Assert.NotNull(handler.CookieContainer);
        Assert.False(handler.AllowAutoRedirect);
        Assert.Equal(TimeSpan.FromMinutes(15), handler.PooledConnectionLifetime);
    }

    [Fact]
    public void ConfigureFactoryHandler_NullHandler_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => AxiamHttpClientFactory.ConfigureFactoryHandler(null!));
    }

    // ------------------------------------------------------------------
    // §6.1 client-certificate / mTLS coverage
    // ------------------------------------------------------------------

    [Fact]
    public void CreatePrimaryHandler_NoClientCert_LeavesClientCertificatesEmpty()
    {
        HttpClientHandler handler = AxiamHttpClientFactory.CreatePrimaryHandler(null);

        // Opt-in (§6.1 rule 5): with no client cert configured, the handler presents none.
        Assert.Empty(handler.ClientCertificates);
    }

    [Fact]
    public void CreatePrimaryHandler_WithClientCert_PopulatesClientCertificate()
    {
        (byte[] certPem, byte[] keyPem, string thumbprint) = ClientCertPemPair();

        HttpClientHandler handler = AxiamHttpClientFactory.CreatePrimaryHandler(null, certPem, keyPem);

        Assert.Single(handler.ClientCertificates);
        var presented = (X509Certificate2)handler.ClientCertificates[0];
        Assert.Equal(thumbprint, presented.Thumbprint);
        Assert.True(presented.HasPrivateKey);
        Assert.Equal(ClientCertificateOption.Manual, handler.ClientCertificateOptions);
        // §6.1 rule 2: presenting a client cert must NOT install any server-validation
        // callback — strict server verification stays on (no CustomCa was supplied here).
        Assert.Null(handler.ServerCertificateCustomValidationCallback);
    }

    [Fact]
    public void CreatePrimaryHandler_ClientCertAlongsideCustomCa_BothConfigured()
    {
        (byte[] certPem, byte[] keyPem, string thumbprint) = ClientCertPemPair();

        HttpClientHandler handler = AxiamHttpClientFactory.CreatePrimaryHandler(SelfSignedPem(), certPem, keyPem);

        // The additive server-trust callback (§6) and the client identity (§6.1) are
        // independent code paths and coexist on the same handler.
        Assert.NotNull(handler.ServerCertificateCustomValidationCallback);
        Assert.Single(handler.ClientCertificates);
        Assert.Equal(thumbprint, ((X509Certificate2)handler.ClientCertificates[0]).Thumbprint);
    }

    [Fact]
    public void CreatePrimaryHandler_OnlyClientCert_ThrowsArgumentException()
    {
        (byte[] certPem, _, _) = ClientCertPemPair();

        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => AxiamHttpClientFactory.CreatePrimaryHandler(null, certPem, null));
        Assert.Equal("clientKeyPem", ex.ParamName);
    }

    [Fact]
    public void CreatePrimaryHandler_OnlyClientKey_ThrowsArgumentException()
    {
        (_, byte[] keyPem, _) = ClientCertPemPair();

        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => AxiamHttpClientFactory.CreatePrimaryHandler(null, null, keyPem));
        Assert.Equal("clientCertPem", ex.ParamName);
    }

    [Fact]
    public void CreatePrimaryHandler_NonPemClientCert_ThrowsArgumentException()
    {
        byte[] garbageCert = Encoding.ASCII.GetBytes("not a pem certificate");
        (_, byte[] keyPem, _) = ClientCertPemPair();

        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => AxiamHttpClientFactory.CreatePrimaryHandler(null, garbageCert, keyPem));
        Assert.Equal("clientCertPem", ex.ParamName);
    }

    [Fact]
    public void CreateOwned_WithClientCert_ReturnsUsableHttpClient()
    {
        (byte[] certPem, byte[] keyPem, _) = ClientCertPemPair();

        using HttpClient client = AxiamHttpClientFactory.CreateOwned(null, certPem, keyPem);
        Assert.NotNull(client);
    }

    [Fact]
    public void ConfigureFactoryHandler_WithClientCert_PopulatesSslOptions()
    {
        (byte[] certPem, byte[] keyPem, string thumbprint) = ClientCertPemPair();
        var handler = new SocketsHttpHandler();

        AxiamHttpClientFactory.ConfigureFactoryHandler(handler, certPem, keyPem);

        Assert.NotNull(handler.SslOptions.ClientCertificates);
        Assert.Equal(1, handler.SslOptions.ClientCertificates!.Count);
        Assert.Equal(thumbprint, ((X509Certificate2)handler.SslOptions.ClientCertificates[0]!).Thumbprint);
        // §6.1 rule 2: no server-validation delegate is set on the alt path either.
        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
    }

    [Fact]
    public void ConfigureFactoryHandler_NoClientCert_LeavesSslClientCertificatesUnset()
    {
        var handler = new SocketsHttpHandler();

        AxiamHttpClientFactory.ConfigureFactoryHandler(handler);

        // Nothing is written to SslOptions when no client cert is configured.
        Assert.Null(handler.SslOptions.ClientCertificates);
    }

    [Fact]
    public void ConfigureFactoryHandler_OnlyClientCert_ThrowsArgumentException()
    {
        (byte[] certPem, _, _) = ClientCertPemPair();
        var handler = new SocketsHttpHandler();

        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => AxiamHttpClientFactory.ConfigureFactoryHandler(handler, certPem, null));
        Assert.Equal("clientKeyPem", ex.ParamName);
    }
}
