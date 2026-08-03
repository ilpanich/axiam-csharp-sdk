using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;10.1 "Minimum local-verification set (normative)" — the complete
/// required negative-test set for <see cref="JwksVerifier.VerifyAsync"/>, the single
/// local-verification implementation every &#167;10 guard in this SDK routes through.
/// </summary>
/// <remarks>
/// This suite exists because <c>SEC-071</c> and <c>SEC-080</c> were the SAME defect found
/// independently in two SDKs: each verified a different SUBSET of the token, and each
/// subset looked complete in isolation. Coverage of one rule proves nothing about the
/// others, so all seven are asserted here together against a real Ed25519 keypair and a
/// real JWKS document.
/// </remarks>
[Trait("Category", "Fast")]
public class Contract101LocalVerificationTests
{
    private const string Tenant = "acme";

    private sealed class JwksHandler : HttpMessageHandler
    {
        private readonly string _jwksJson;

        public JwksHandler(string jwksJson) => _jwksJson = jwksJson;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_jwksJson, Encoding.UTF8, "application/json"),
            });
    }

    private static (JwksVerifier Verifier, JwksFixture Fixture) Create(
        string? expectedIssuer = null,
        string? expectedAudience = null)
    {
        var fixture = new JwksFixture();
        var http = new HttpClient(new JwksHandler(fixture.BuildJwksDocument()))
        {
            BaseAddress = new Uri("https://axiam.test"),
        };
        var verifier = new JwksVerifier(
            http, new Uri("https://axiam.test"), TimeSpan.FromMinutes(5), expectedIssuer, expectedAudience);
        return (verifier, fixture);
    }

    private static long Unix(TimeSpan offset) => DateTimeOffset.UtcNow.Add(offset).ToUnixTimeSeconds();

    /// <summary>
    /// Mints a REAL HS256-signed token whose <c>kid</c> names the Ed25519 key the JWKS
    /// actually serves — the classic algorithm-confusion attempt. &#167;10.1 rule 1
    /// requires this be rejected without ever consulting that key.
    /// </summary>
    private static string SignHs256WithEdDsaKid(JwksFixture fixture, object payload)
    {
        string header = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new { alg = "HS256", kid = fixture.Kid }));
        string body = Base64Url(JsonSerializer.SerializeToUtf8Bytes(payload));
        byte[] signingInput = Encoding.ASCII.GetBytes($"{header}.{body}");
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes("attacker-chosen-hmac-secret"));
        return $"{header}.{body}.{Base64Url(hmac.ComputeHash(signingInput))}";
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // -----------------------------------------------------------------------
    // Rule 1 — signature, alg pinned to EdDSA BEFORE key lookup
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Rule1_AlgNone_IsRejected()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = JwksFixture.BuildRawToken(
            header: new { alg = "none", kid = fixture.Kid },
            payload: new { sub = "u", tenant_id = Tenant, exp = Unix(TimeSpan.FromMinutes(15)) },
            signaturePart: string.Empty);

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule1_Hs256TokenBearingAnEdDsaKid_IsRejected()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = SignHs256WithEdDsaKid(
            fixture, new { sub = "u", tenant_id = Tenant, exp = Unix(TimeSpan.FromMinutes(15)) });

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    // -----------------------------------------------------------------------
    // Rule 2 — exp is REQUIRED
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Rule2_ExpiredToken_IsRejected()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        // Beyond ClockSkewLeeway, so the leeway cannot excuse it.
        string token = fixture.SignJwt("u", Tenant, ["admin"], DateTimeOffset.UtcNow.AddHours(-2));

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule2_TokenWithNoExpClaimAtAll_IsRejected()
    {
        // The SEC-080 defect verbatim: a check that only compares an exp it FOUND admits
        // this permanent credential outright.
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignIdToken(new { sub = "u", tenant_id = Tenant });

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule2_NonNumericExpClaim_IsRejected()
    {
        // A JSON STRING is not an RFC 7519 NumericDate. Reject, never coerce, never skip.
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignIdToken(new { sub = "u", tenant_id = Tenant, exp = "not-a-number" });

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule2_NumericStringExpClaim_IsRejected()
    {
        // Even a *numeric-looking* string is the wrong JSON type and must not be coerced.
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignIdToken(
            new { sub = "u", tenant_id = Tenant, exp = Unix(TimeSpan.FromMinutes(15)).ToString() });

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule2_NullExpClaim_IsRejected()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignIdToken(new { sub = "u", tenant_id = Tenant, exp = (string?)null });

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    // -----------------------------------------------------------------------
    // Rule 3 — nbf honoured when present, absent is valid
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Rule3_NbfInTheFuture_IsRejected()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignIdToken(new
        {
            sub = "u",
            tenant_id = Tenant,
            exp = Unix(TimeSpan.FromMinutes(15)),
            nbf = Unix(TimeSpan.FromHours(2)),
        });

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule3_NbfAlreadyPassed_IsAccepted()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignIdToken(new
        {
            sub = "u",
            tenant_id = Tenant,
            exp = Unix(TimeSpan.FromMinutes(15)),
            nbf = Unix(TimeSpan.FromMinutes(-5)),
        });

        Assert.NotNull(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule3_AbsentNbf_IsAccepted()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignJwt("u", Tenant, ["admin"], DateTimeOffset.UtcNow.AddMinutes(15));

        Assert.NotNull(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule3_MalformedNbf_IsRejected()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignIdToken(new
        {
            sub = "u",
            tenant_id = Tenant,
            exp = Unix(TimeSpan.FromMinutes(15)),
            nbf = "soon",
        });

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    // -----------------------------------------------------------------------
    // Rule 4 — tenant_id REQUIRED and asserted
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Rule4_TokenForADifferentTenant_IsRejected()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignJwt("u", "some-other-tenant", ["admin"], DateTimeOffset.UtcNow.AddMinutes(15));

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule4_TokenWithNoTenantIdClaim_IsRejected()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignIdToken(new { sub = "u", exp = Unix(TimeSpan.FromMinutes(15)) });

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule4_NoConfiguredTenant_FailsClosed()
    {
        // A perfectly good token, and it must STILL be rejected: with nothing to assert
        // tenant_id against, "no configured tenant" is a fail-closed condition, not a
        // waiver.
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignJwt("u", Tenant, ["admin"], DateTimeOffset.UtcNow.AddMinutes(15));

        Assert.Null(await verifier.VerifyAsync(token, string.Empty));
    }

    // -----------------------------------------------------------------------
    // Rule 5 — iss checked only when configured
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Rule5_UnconfiguredIssuer_IsNotChecked()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignIdToken(new
        {
            sub = "u",
            tenant_id = Tenant,
            exp = Unix(TimeSpan.FromMinutes(15)),
            iss = "https://whoever.example.com",
        });

        Assert.NotNull(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule5_ConfiguredIssuerMatching_IsAccepted()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create(expectedIssuer: "https://axiam.example.com");
        string token = fixture.SignIdToken(new
        {
            sub = "u",
            tenant_id = Tenant,
            exp = Unix(TimeSpan.FromMinutes(15)),
            iss = "https://axiam.example.com",
        });

        Assert.NotNull(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule5_ConfiguredIssuerMismatch_IsRejected()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create(expectedIssuer: "https://axiam.example.com");
        string token = fixture.SignIdToken(new
        {
            sub = "u",
            tenant_id = Tenant,
            exp = Unix(TimeSpan.FromMinutes(15)),
            iss = "https://evil.example.com",
        });

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule5_ConfiguredIssuerButTokenHasNoIss_FailsClosed()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create(expectedIssuer: "https://axiam.example.com");
        string token = fixture.SignJwt("u", Tenant, ["admin"], DateTimeOffset.UtcNow.AddMinutes(15));

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    // -----------------------------------------------------------------------
    // Rule 6 — aud checked only when configured
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Rule6_UnconfiguredAudience_IsNotChecked()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignIdToken(new
        {
            sub = "u",
            tenant_id = Tenant,
            exp = Unix(TimeSpan.FromMinutes(15)),
            aud = "someone-elses-api",
        });

        Assert.NotNull(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule6_ConfiguredAudience_SingleStringMatch_IsAccepted()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create(expectedAudience: "axiam:user");
        string token = fixture.SignIdToken(new
        {
            sub = "u",
            tenant_id = Tenant,
            exp = Unix(TimeSpan.FromMinutes(15)),
            aud = "axiam:user",
        });

        Assert.NotNull(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule6_ConfiguredAudience_ArrayContainingMatch_IsAccepted()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create(expectedAudience: "axiam:user");
        string token = fixture.SignIdToken(new
        {
            sub = "u",
            tenant_id = Tenant,
            exp = Unix(TimeSpan.FromMinutes(15)),
            aud = new[] { "some-other-api", "axiam:user" },
        });

        Assert.NotNull(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule6_ConfiguredAudienceMismatch_IsRejected()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create(expectedAudience: "axiam:user");
        string token = fixture.SignIdToken(new
        {
            sub = "u",
            tenant_id = Tenant,
            exp = Unix(TimeSpan.FromMinutes(15)),
            aud = new[] { "axiam:service" },
        });

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule6_ConfiguredAudienceButTokenHasNoAud_FailsClosed()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create(expectedAudience: "axiam:user");
        string token = fixture.SignJwt("u", Tenant, ["admin"], DateTimeOffset.UtcNow.AddMinutes(15));

        Assert.Null(await verifier.VerifyAsync(token, Tenant));
    }

    // -----------------------------------------------------------------------
    // Rule 7 — named, bounded clock skew
    // -----------------------------------------------------------------------

    [Fact]
    public void Rule7_ClockSkewLeeway_IsTheRecommended60Seconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(60), JwksVerifier.ClockSkewLeeway);
    }

    [Fact]
    public async Task Rule7_NbfWithinTheNamedSkew_IsTolerated()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignIdToken(new
        {
            sub = "u",
            tenant_id = Tenant,
            exp = Unix(TimeSpan.FromMinutes(15)),
            nbf = Unix(TimeSpan.FromSeconds(30)), // < the 60 s ClockSkewLeeway
        });

        Assert.NotNull(await verifier.VerifyAsync(token, Tenant));
    }

    [Fact]
    public async Task Rule7_ExpJustPastWithinTheNamedSkew_IsTolerated()
    {
        (JwksVerifier verifier, JwksFixture fixture) = Create();
        string token = fixture.SignJwt("u", Tenant, ["admin"], DateTimeOffset.UtcNow.AddSeconds(-30));

        Assert.NotNull(await verifier.VerifyAsync(token, Tenant));
    }
}
