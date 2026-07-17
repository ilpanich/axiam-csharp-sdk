using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Axiam.Sdk;
using Axiam.Sdk.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Axiam.Sdk.AspNetCore.Tests;

/// <summary>
/// D-07 DI-extension coverage: <see cref="ServiceCollectionExtensions.AddAxiam"/> registers
/// the typed options + a shared <see cref="AxiamClient"/>, and
/// <see cref="ServiceCollectionExtensions.AddAxiamAspNetCore"/> additionally wires the
/// policy-based authorization surface (custom <see cref="IAuthorizationPolicyProvider"/> and
/// <see cref="IAuthorizationMiddlewareResultHandler"/>) with <c>TryAdd*</c> precedence.
/// </summary>
public class ServiceCollectionExtensionsTests
{
    private static readonly Uri BaseUrl = new("https://axiam.test");

    [Fact]
    public void AddAxiam_RegistersOptions_AndBuildsSharedClient()
    {
        var services = new ServiceCollection();

        services.AddAxiam(o =>
        {
            o.BaseUrl = BaseUrl;
            o.DefaultTenantId = "acme";
        });

        using ServiceProvider provider = services.BuildServiceProvider();

        AxiamOptions options = provider.GetRequiredService<IOptions<AxiamOptions>>().Value;
        Assert.Equal("acme", options.DefaultTenantId);

        var client = provider.GetRequiredService<AxiamClient>();
        var again = provider.GetRequiredService<AxiamClient>();
        Assert.Same(client, again); // singleton
    }

    [Fact]
    public void AddAxiam_NullServices_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => ServiceCollectionExtensions.AddAxiam(null!, _ => { }));
    }

    [Fact]
    public void AddAxiam_NullConfigure_Throws()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() => services.AddAxiam(null!));
    }

    [Fact]
    public void AddAxiamAspNetCore_RegistersAxiamPolicyProvider_AndResultHandler()
    {
        var services = new ServiceCollection();

        services.AddAxiamAspNetCore(o =>
        {
            o.BaseUrl = BaseUrl;
            o.DefaultTenantId = "acme";
        });

        using ServiceProvider provider = services.BuildServiceProvider();

        var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();
        Assert.IsType<AxiamPolicyProvider>(policyProvider);

        var resultHandler = provider.GetRequiredService<IAuthorizationMiddlewareResultHandler>();
        Assert.IsType<AxiamAuthorizationMiddlewareResultHandler>(resultHandler);

        Assert.Contains(provider.GetServices<IAuthorizationHandler>(), h => h is AxiamPolicyHandler);
    }

    [Fact]
    public void AddAxiamAspNetCore_NullServices_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => ServiceCollectionExtensions.AddAxiamAspNetCore(null!, _ => { }));
    }

    [Fact]
    public void AddAxiam_ExplicitPriorClientRegistration_Wins_TryAddPrecedence()
    {
        var services = new ServiceCollection();
        var options = new Axiam.Sdk.Options.AxiamClientOptions { BaseUrl = BaseUrl, TenantId = "explicit" };
        AxiamClient explicitClient = AxiamClient.CreateForTesting(BaseUrl, "explicit", options, new NoopHandler());
        services.AddSingleton(explicitClient);

        services.AddAxiam(o =>
        {
            o.BaseUrl = BaseUrl;
            o.DefaultTenantId = "acme";
        });

        using ServiceProvider provider = services.BuildServiceProvider();
        Assert.Same(explicitClient, provider.GetRequiredService<AxiamClient>());
    }

    [Fact]
    public void AddAxiam_MtlsClientCert_FlowsThroughToClient_AndBuildsSuccessfully()
    {
        (byte[] certPem, byte[] keyPem) = ClientCertPemPair();
        var services = new ServiceCollection();

        services.AddAxiam(o =>
        {
            o.BaseUrl = BaseUrl;
            o.DefaultTenantId = "acme";
            o.ClientCertificatePem = certPem;
            o.ClientKeyPem = keyPem;
        });

        using ServiceProvider provider = services.BuildServiceProvider();

        AxiamOptions options = provider.GetRequiredService<IOptions<AxiamOptions>>().Value;
        Assert.Same(certPem, options.ClientCertificatePem);
        Assert.Same(keyPem, options.ClientKeyPem);

        // Resolving the shared client runs BuildClient -> new AxiamClient(...) ->
        // CreatePrimaryHandler(...) with a MATCHED cert/key pair, so construction succeeds
        // (§6.1). A throw here would fail the test.
        var client = provider.GetRequiredService<AxiamClient>();
        Assert.NotNull(client);
    }

    [Fact]
    public void AddAxiam_MtlsCertWithoutKey_ThrowsAtClientConstruction()
    {
        (byte[] certPem, _) = ClientCertPemPair();
        var services = new ServiceCollection();

        services.AddAxiam(o =>
        {
            o.BaseUrl = BaseUrl;
            o.DefaultTenantId = "acme";
            o.ClientCertificatePem = certPem;
            // ClientKeyPem deliberately left null — exactly one of the pair is supplied.
        });

        using ServiceProvider provider = services.BuildServiceProvider();

        // §6.1: the cert/key mismatch surfaces as an ArgumentException when the shared
        // AxiamClient is first constructed (through the AxiamOptions -> AxiamClientOptions
        // flow-through).
        Assert.Throws<ArgumentException>(() => provider.GetRequiredService<AxiamClient>());
    }

    private static (byte[] CertPem, byte[] KeyPem) ClientCertPemPair()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Axiam mTLS Client", ecdsa, HashAlgorithmName.SHA256);
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return (Encoding.ASCII.GetBytes(cert.ExportCertificatePem()), Encoding.ASCII.GetBytes(ecdsa.ExportPkcs8PrivateKeyPem()));
    }

    private sealed class NoopHandler : System.Net.Http.HttpMessageHandler
    {
        protected override System.Threading.Tasks.Task<System.Net.Http.HttpResponseMessage> SendAsync(
            System.Net.Http.HttpRequestMessage request, System.Threading.CancellationToken cancellationToken) =>
            System.Threading.Tasks.Task.FromResult(new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK));
    }
}
