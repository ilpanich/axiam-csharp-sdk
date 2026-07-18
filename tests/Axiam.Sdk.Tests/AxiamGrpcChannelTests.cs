using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Axiam.Sdk.Grpc;
using Grpc.Net.Client;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Proves <see cref="AxiamGrpcChannel.Create"/> builds a single long-lived
/// <see cref="GrpcChannel"/> over the REST factory's strict-TLS handler (D-10, §6),
/// honors the additive custom-CA escape hatch, and guards its required <c>target</c>.
/// No RPC is issued, so no network is touched.
/// </summary>
[Trait("Category", "Fast")]
public class AxiamGrpcChannelTests
{
    private static readonly Uri Target = new("https://axiam.test:443");

    private static byte[] SelfSignedPem()
    {
        using RSA rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Axiam Test CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return Encoding.ASCII.GetBytes(cert.ExportCertificatePem());
    }

    [Fact]
    public void Create_NoCa_ReturnsChannelTargetingTheAddress()
    {
        using GrpcChannel channel = AxiamGrpcChannel.Create(Target, null);

        Assert.NotNull(channel);
        Assert.Equal(Target.Authority, channel.Target);
    }

    [Fact]
    public void Create_WithCustomCa_ReturnsChannel()
    {
        using GrpcChannel channel = AxiamGrpcChannel.Create(Target, SelfSignedPem());

        Assert.NotNull(channel);
    }

    [Fact]
    public void Create_NullTarget_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => AxiamGrpcChannel.Create(null!, null));
    }

    [Fact]
    public void Create_WithClientCert_ReturnsChannel()
    {
        (byte[] certPem, byte[] keyPem) = ClientCertPemPair();

        // §6.1: the gRPC channel threads the mTLS client identity through the same
        // CreatePrimaryHandler the REST transport uses, so both transports present it.
        using GrpcChannel channel = AxiamGrpcChannel.Create(Target, null, certPem, keyPem);

        Assert.NotNull(channel);
        Assert.Equal(Target.Authority, channel.Target);
    }

    [Fact]
    public void Create_WithMismatchedClientCert_Throws()
    {
        (byte[] certPem, _) = ClientCertPemPair();

        Assert.Throws<ArgumentException>(() => AxiamGrpcChannel.Create(Target, null, certPem, null));
    }

    private static (byte[] CertPem, byte[] KeyPem) ClientCertPemPair()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Axiam mTLS Client", ecdsa, HashAlgorithmName.SHA256);
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return (Encoding.ASCII.GetBytes(cert.ExportCertificatePem()), Encoding.ASCII.GetBytes(ecdsa.ExportPkcs8PrivateKeyPem()));
    }
}
