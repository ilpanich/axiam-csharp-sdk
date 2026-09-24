using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.AspNetCore.Tests.Fixtures;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Options;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Axiam.Sdk.AspNetCore.Tests;

/// <summary>
/// CONTRACT.md &#167;10.1 rule 9 (contract 1.51): <see cref="AxiamAuthMiddleware"/> reads
/// its sender-constraint evidence from <c>HttpContext.Connection.ClientCertificate</c>,
/// never from a header, and refuses a <c>cnf</c>-bearing token it has no matching
/// certificate for.
/// </summary>
/// <remarks>
/// Before this fix, <see cref="AxiamAuthMiddleware"/> called the plain
/// <c>JwksVerifier.VerifyAsync</c>, which applies no rule-9 check at all — a token
/// carrying <c>cnf</c> (the &#167;6.1 device login mints one by default) was accepted here
/// exactly like an ordinary bearer token, on any connection, with or without a
/// certificate. No existing test in this project pinned that shape (a repository-wide
/// search of <c>tests/Axiam.Sdk.AspNetCore.Tests</c> for <c>cnf</c>/
/// <c>ClientCertificate</c> before this file found none), so there is nothing to invert
/// here — only new coverage to add.
/// <para>
/// A real <see cref="TestServer"/> carries no TLS handshake, so there is no real client
/// certificate for <see cref="HttpContext.Connection"/> to observe on its own. This
/// suite's host inserts ONE test-only middleware, first in the pipeline, that sets
/// <see cref="HttpContext.Connection.ClientCertificate"/> from a value the TEST driver
/// supplies out of band (never a header <see cref="AxiamAuthMiddleware"/> itself reads —
/// grep this file and <c>AxiamAuthMiddleware.cs</c> to confirm neither one shares a
/// header name for this purpose) — mirroring exactly what a real Kestrel HTTPS listener
/// configured for client-certificate authentication populates before any of an
/// application's own middleware runs. <see cref="AxiamAuthMiddleware"/> downstream of it
/// is completely unaware this is a test.
/// </para>
/// </remarks>
[Trait("Category", "Integration")]
public sealed class Rule9BoundTokenMiddlewareTests
{
    private const string TenantId = "acme-tenant";
    private static readonly Uri BaseUrl = new("https://axiam.test");

    [Fact]
    public async Task ABoundToken_WithTheMatchingCertificatePresented_Returns200()
    {
        var fixture = new JwksFixture();
        (X509Certificate2 cert, string thumbprint) = SelfSignedCert();
        string token = BoundToken(fixture, thumbprint);
        using IHost host = await CreateHostAsync(fixture, presentedCertificate: cert).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ABoundToken_WithADifferentCertificatePresented_Returns401()
    {
        var fixture = new JwksFixture();
        (X509Certificate2 _, string boundThumbprint) = SelfSignedCert();
        (X509Certificate2 differentCert, string _) = SelfSignedCert();
        string token = BoundToken(fixture, boundThumbprint);
        using IHost host = await CreateHostAsync(fixture, presentedCertificate: differentCert).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ABoundToken_WithNoCertificatePresented_Returns401()
    {
        var fixture = new JwksFixture();
        (X509Certificate2 _, string boundThumbprint) = SelfSignedCert();
        string token = BoundToken(fixture, boundThumbprint);
        using IHost host = await CreateHostAsync(fixture, presentedCertificate: null).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AnUnboundToken_StillWorks_WithOrWithoutACertificatePresented()
    {
        // The positive regression that matters more than the others (§10.1 rule 9's
        // own required-test list): rule 9 must not become "every caller needs a proof".
        var fixture = new JwksFixture();
        string unboundToken = fixture.SignJwt("user-1", TenantId, Array.Empty<string>(), DateTimeOffset.UtcNow.AddMinutes(5));
        (X509Certificate2 someCert, string _) = SelfSignedCert();

        using IHost hostNoCert = await CreateHostAsync(fixture, presentedCertificate: null).ConfigureAwait(false);
        HttpClient clientNoCert = hostNoCert.GetTestClient();
        clientNoCert.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", unboundToken);
        Assert.Equal(HttpStatusCode.OK, (await clientNoCert.GetAsync("/protected").ConfigureAwait(false)).StatusCode);

        using IHost hostWithCert = await CreateHostAsync(fixture, presentedCertificate: someCert).ConfigureAwait(false);
        HttpClient clientWithCert = hostWithCert.GetTestClient();
        clientWithCert.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", unboundToken);
        Assert.Equal(HttpStatusCode.OK, (await clientWithCert.GetAsync("/protected").ConfigureAwait(false)).StatusCode);
    }

    [Fact]
    public async Task AJktBoundToken_IsRefused_ThisMiddlewareVerifiesNoDpopProof()
    {
        var fixture = new JwksFixture();
        string token = fixture.SignIdToken(new
        {
            sub = "user-1",
            tenant_id = TenantId,
            roles = Array.Empty<string>(),
            exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            cnf = new { jkt = "some-dpop-key-thumbprint-xxxxxxxxxxxxxxxxx" },
        });
        (X509Certificate2 someCert, string _) = SelfSignedCert();
        using IHost host = await CreateHostAsync(fixture, presentedCertificate: someCert).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ---- Helpers -------------------------------------------------------------------

    /// <summary>
    /// A token carrying <c>cnf: {"x5t#S256": thumbprint}</c> — a <see cref="Dictionary{TKey,TValue}"/>
    /// payload, not an anonymous type, because the claim name contains <c>#</c> and is
    /// not a legal C# identifier.
    /// </summary>
    private static string BoundToken(JwksFixture fixture, string thumbprint) => fixture.SignIdToken(new Dictionary<string, object?>
    {
        ["sub"] = "user-1",
        ["tenant_id"] = TenantId,
        ["roles"] = Array.Empty<string>(),
        ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
        ["cnf"] = new Dictionary<string, object?> { ["x5t#S256"] = thumbprint },
    });

    private static (X509Certificate2 Cert, string ThumbprintS256) SelfSignedCert()
    {
        using RSA rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Axiam Rule9 Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        string thumbprint = JwksVerifier.CertificateThumbprintS256(cert.RawData);
        return (cert, thumbprint);
    }

    private static async Task<IHost> CreateHostAsync(JwksFixture fixture, X509Certificate2? presentedCertificate)
    {
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        AxiamClient fakeClient = AxiamClient.CreateForTesting(
            BaseUrl, TenantId, new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantId }, serverHandler);

        IHostBuilder builder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(fakeClient);
                    services.AddAxiamAspNetCore(options =>
                    {
                        options.BaseUrl = BaseUrl;
                        options.DefaultTenantId = TenantId;
                    });
                });
                webHost.Configure(app =>
                {
                    // Test-only: stands in for what a real Kestrel HTTPS listener
                    // configured for client-certificate auth populates BEFORE any
                    // application middleware runs. Reads NOTHING AxiamAuthMiddleware
                    // itself reads — it is not on the request at all, only set directly
                    // on this closure's captured value.
                    app.Use(async (context, next) =>
                    {
                        context.Connection.ClientCertificate = presentedCertificate;
                        await next();
                    });
                    app.UseRouting();
                    app.UseMiddleware<AxiamAuthMiddleware>();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/protected", async context =>
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync("ok").ConfigureAwait(false);
                        }).RequireAuthorization();
                    });
                });
            });

        return await builder.StartAsync().ConfigureAwait(false);
    }

    private sealed class FakeAxiamServerHandler : HttpMessageHandler
    {
        private readonly string _jwksDocument;

        public FakeAxiamServerHandler(string jwksDocument) => _jwksDocument = jwksDocument;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == "/oauth2/jwks")
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(_jwksDocument, Encoding.UTF8, "application/json"),
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
