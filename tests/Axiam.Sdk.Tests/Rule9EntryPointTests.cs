using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;10.1 rule 9 at the SDK's default local-verification entry point
/// (contract 1.51). <see cref="JwksVerifier.VerifyAsync"/> is the documented guard entry
/// point — <c>AxiamAuthMiddleware</c>, the &#167;11 declarative helpers and the &#167;28 MCP
/// guard all reach it — and before this fix it applied no rule-9 check at all: a token
/// carrying <c>cnf</c> was accepted exactly like an ordinary bearer token, with or
/// without any transport evidence. A token lifted off a device (which the &#167;6.1 device
/// login mints certificate-bound by default) therefore opened every guarded route.
/// </summary>
/// <remarks>
/// Against real, BouncyCastle-signed Ed25519 tokens (<see cref="JwksFixture"/>), not a
/// self-round-trip through the verifier's own code — same harness as
/// <c>JwksVerifierTests</c>.
/// </remarks>
[Trait("Category", "Fast")]
public sealed class Rule9EntryPointTests
{
    private const string Tenant = "acme";

    private sealed class FakeJwksHandler : HttpMessageHandler
    {
        private readonly string _jwksJson;
        public FakeJwksHandler(string jwksJson) => _jwksJson = jwksJson;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_jwksJson, Encoding.UTF8, "application/json"),
            });
    }

    private static (JwksVerifier Verifier, JwksFixture Fixture) CreateVerifier()
    {
        var fixture = new JwksFixture();
        var handler = new FakeJwksHandler(fixture.BuildJwksDocument());
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://axiam.test") };
        var verifier = new JwksVerifier(http, new Uri("https://axiam.test"), TimeSpan.FromMinutes(5));
        return (verifier, fixture);
    }

    private static string BoundToken(JwksFixture fixture, string thumbprint) => fixture.SignIdToken(new Dictionary<string, object?>
    {
        ["sub"] = "user-1",
        ["tenant_id"] = Tenant,
        ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
        ["cnf"] = new Dictionary<string, object?> { ["x5t#S256"] = thumbprint },
    });

    private static string UnboundToken(JwksFixture fixture) => fixture.SignIdToken(new Dictionary<string, object?>
    {
        ["sub"] = "user-1",
        ["tenant_id"] = Tenant,
        ["exp"] = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
    });

    [Fact]
    public async Task VerifyAsync_ABoundToken_IsRefused_EvenWithNoEvidenceToCheck()
    {
        (JwksVerifier verifier, JwksFixture fixture) = CreateVerifier();

        string token = BoundToken(fixture, thumbprint: "thumbprint-abc-does-not-matter");

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task VerifyAsync_AnUnboundToken_IsUnaffected()
    {
        (JwksVerifier verifier, JwksFixture fixture) = CreateVerifier();

        string token = UnboundToken(fixture);

        Assert.NotNull(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task VerifyWithProofsAsync_ABoundToken_IsAcceptedWithTheMatchingCertificate()
    {
        (JwksVerifier verifier, JwksFixture fixture) = CreateVerifier();
        string token = BoundToken(fixture, thumbprint: "thumbprint-abc");

        Assert.NotNull(await verifier.VerifyWithProofsAsync(token, Tenant, PresentedProofs.Certificate("thumbprint-abc")));
    }

    [Fact]
    public async Task VerifyWithProofsAsync_ABoundToken_IsRefusedWithADifferentCertificate()
    {
        (JwksVerifier verifier, JwksFixture fixture) = CreateVerifier();
        string token = BoundToken(fixture, thumbprint: "thumbprint-abc");

        Assert.Null(await verifier.VerifyWithProofsAsync(token, Tenant, PresentedProofs.Certificate("a-different-thumbprint")));
    }

    [Fact]
    public async Task VerifyWithProofsAsync_ABoundToken_IsRefusedWithNoEvidence()
    {
        (JwksVerifier verifier, JwksFixture fixture) = CreateVerifier();
        string token = BoundToken(fixture, thumbprint: "thumbprint-abc");

        Assert.Null(await verifier.VerifyWithProofsAsync(token, Tenant, PresentedProofs.None()));
    }

    [Fact]
    public async Task VerifyWithProofsAsync_AnUnboundToken_IsAcceptedRegardlessOfEvidence()
    {
        (JwksVerifier verifier, JwksFixture fixture) = CreateVerifier();
        string token = UnboundToken(fixture);

        Assert.NotNull(await verifier.VerifyWithProofsAsync(token, Tenant, PresentedProofs.None()));
        Assert.NotNull(await verifier.VerifyWithProofsAsync(token, Tenant, PresentedProofs.Certificate("anything")));
    }

    [Fact]
    public async Task EveryEntryPoint_AgreesOnAnUnboundToken()
    {
        // §10.3 rule 1 detail 4, applied to the two local entry points: they must never
        // disagree about whether a token is a bearer token.
        (JwksVerifier verifier, JwksFixture fixture) = CreateVerifier();
        string token = UnboundToken(fixture);

        Assert.NotNull(await verifier.VerifyAsync(token, Tenant));
        Assert.NotNull(await verifier.VerifyWithProofsAsync(token, Tenant, PresentedProofs.None()));
    }
}
