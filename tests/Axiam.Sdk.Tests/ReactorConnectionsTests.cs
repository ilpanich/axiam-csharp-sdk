using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Axiam.Sdk.Reactor;
using RabbitMQ.Client;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;8b for the C# reactor transport.
/// </summary>
/// <remarks>
/// &#167;22.2 closes with "Reactors connect across a trust boundary: <c>amqps://</c>, a supplied
/// CA bundle, no verification-skip switch, no plaintext fallback." Until
/// <see cref="ReactorConnections"/> existed, this SDK stated that in one XML doc sentence on
/// <c>ReactorServeOptions.Channel</c> and enforced none of it — a caller who built a
/// <see cref="ConnectionFactory"/> from an <c>amqp://</c> URI got a working reactor and no
/// warning. These tests are the enforcement.
/// </remarks>
public class ReactorConnectionsTests
{
    private const string Amqps = "amqps://reactor:secret@broker.internal:5671/%2f";

    // ------------------------------------------------------------------
    // Rules 1 and 5 — amqps:// only, no plaintext fallback
    // ------------------------------------------------------------------

    [Fact]
    public void PlaintextAmqpIsRefused()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => ReactorConnections.CreateConnectionFactory("amqp://broker.internal:5672"));
        Assert.Contains("amqps://", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Loopback earns no exception. &#167;8b rules 1 and 5 carry no host carve-out, and the AXIAM
    /// server is TLS-only with no plaintext listener for one to reach.
    /// </summary>
    [Theory]
    [InlineData("amqp://localhost:5672")]
    [InlineData("amqp://127.0.0.1:5672")]
    public void PlaintextIsRefusedOnLoopbackToo(string uri)
    {
        Assert.Throws<ArgumentException>(() => ReactorConnections.CreateConnectionFactory(uri));
    }

    [Theory]
    [InlineData("https://broker.internal")]
    [InlineData("amqpsomething://broker.internal:5671")]
    [InlineData("broker.internal:5671")]
    public void EveryOtherSchemeIsRefused(string uri)
    {
        Assert.Throws<ArgumentException>(() => ReactorConnections.CreateConnectionFactory(uri));
    }

    /// <summary>
    /// A URI that will not parse is refused rather than passed through: a security check must fail
    /// closed on an input it cannot read.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a uri at all")]
    public void AnUnparseableUriIsRefusedRatherThanWavedThrough(string uri)
    {
        Assert.Throws<ArgumentException>(() => ReactorConnections.CreateConnectionFactory(uri));
    }

    [Fact]
    public void AmqpsIsAcceptedCaseInsensitively()
    {
        // An operator who wrote AMQPS:// meant TLS.
        ReactorConnections.RequireAmqps("AMQPS://broker.internal:5671");
        ReactorConnections.RequireAmqps(Amqps);
    }

    // ------------------------------------------------------------------
    // What the factory actually carries
    // ------------------------------------------------------------------

    [Fact]
    public void TlsIsEnabledAndTheServerNameComesFromTheUri()
    {
        ConnectionFactory factory = ReactorConnections.CreateConnectionFactory(Amqps);

        Assert.True(factory.Ssl.Enabled);
        // A blank ServerName is how hostname verification quietly becomes nothing.
        Assert.Equal("broker.internal", factory.Ssl.ServerName);
    }

    /// <summary>
    /// &#167;8b rule 4 is an assertion about what is <em>absent</em>: no policy error is tolerated,
    /// and no argument to this class can change that. A future edit relaxing it has to change this
    /// test, which is the point.
    /// </summary>
    [Fact]
    public void NoTlsPolicyErrorIsTolerated()
    {
        ConnectionFactory factory = ReactorConnections.CreateConnectionFactory(Amqps);
        Assert.Equal(System.Net.Security.SslPolicyErrors.None, factory.Ssl.AcceptablePolicyErrors);
    }

    [Fact]
    public void OnlyTls12AndTls13AreOffered()
    {
        ConnectionFactory factory = ReactorConnections.CreateConnectionFactory(Amqps);
        Assert.Equal(SslProtocols.Tls12 | SslProtocols.Tls13, factory.Ssl.Version);
        // Nothing older may sneak in through the flags.
#pragma warning disable SYSLIB0039, CS0618 // deliberately naming obsolete protocols to assert absence
        Assert.False(factory.Ssl.Version.HasFlag(SslProtocols.Tls));
        Assert.False(factory.Ssl.Version.HasFlag(SslProtocols.Tls11));
#pragma warning restore SYSLIB0039, CS0618
    }

    [Fact]
    public void WithoutABrokerCaThereIsNoValidationCallbackToOverride()
    {
        ConnectionFactory factory = ReactorConnections.CreateConnectionFactory(Amqps);
        Assert.Null(factory.Ssl.CertificateValidationCallback);
    }

    // ------------------------------------------------------------------
    // Rule 2 — a private broker CA
    // ------------------------------------------------------------------

    [Fact]
    public void APrivateBrokerCaInstallsAValidationCallback()
    {
        using X509Certificate2 ca = SelfSigned("CN=Test Broker CA");
        ConnectionFactory factory = ReactorConnections.CreateConnectionFactory(Amqps, ca);
        Assert.NotNull(factory.Ssl.CertificateValidationCallback);
    }

    /// <summary>
    /// The callback is the one place in this SDK where returning <c>true</c> unconditionally would
    /// disable verification. These assertions pin that it does not: a name mismatch is refused
    /// whoever signed the certificate, and a chain that reaches neither the OS roots nor the
    /// supplied CA is refused too.
    /// </summary>
    [Fact]
    public void TheValidationCallbackStillRefusesWhatItShould()
    {
        using X509Certificate2 ca = SelfSigned("CN=Test Broker CA 2");
        using X509Certificate2 stranger = SelfSigned("CN=Some Other Host");
        ConnectionFactory factory = ReactorConnections.CreateConnectionFactory(Amqps, ca);
        var callback = factory.Ssl.CertificateValidationCallback!;

        // A name mismatch is never something a custom CA can excuse.
        Assert.False(callback(
            this, stranger, null,
            System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch));

        // No certificate at all.
        Assert.False(callback(
            this, null, null,
            System.Net.Security.SslPolicyErrors.RemoteCertificateNotAvailable));

        // A chain error, on a certificate that chains to neither the OS roots
        // nor the supplied CA.
        Assert.False(callback(
            this, stranger, null,
            System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors));

        // …and an OS-trusted chain still passes, unchanged.
        Assert.True(callback(this, stranger, null, System.Net.Security.SslPolicyErrors.None));
    }

    // ------------------------------------------------------------------
    // Rule 3 — a client identity needs its key
    // ------------------------------------------------------------------

    [Fact]
    public void AClientCertificateWithoutItsPrivateKeyIsRefused()
    {
        using X509Certificate2 withKey = SelfSigned("CN=Test Client");
        // Re-import the public half only — the shape someone gets from loading a
        // .crt/.pem without the matching key.
        // net8.0: X509CertificateLoader is .NET 9+, so the constructor is the
        // available path here.
#pragma warning disable SYSLIB0057 // obsolete only from .NET 9; this project targets net8.0
        using var publicOnly = new X509Certificate2(withKey.Export(X509ContentType.Cert));
#pragma warning restore SYSLIB0057
        Assert.False(publicOnly.HasPrivateKey);

        var ex = Assert.Throws<ArgumentException>(
            () => { _ = ReactorConnections.CreateConnectionFactory(Amqps, null, publicOnly); });
        Assert.Contains("private key", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ACompleteClientIdentityIsCarriedOntoTheFactory()
    {
        using X509Certificate2 client = SelfSigned("CN=Test Client 2");
        ConnectionFactory factory = ReactorConnections.CreateConnectionFactory(Amqps, null, client);
        Assert.NotNull(factory.Ssl.Certs);
        Assert.Single(factory.Ssl.Certs!);
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /// <summary>
    /// A self-signed certificate with its private key, generated per test run so this file carries
    /// no expiry date. Nothing here is used for a live handshake — these tests build factories and
    /// invoke a callback directly; they never dial a broker.
    /// </summary>
    private static X509Certificate2 SelfSigned(string subject)
    {
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, false, 0, true));
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
    }
}
