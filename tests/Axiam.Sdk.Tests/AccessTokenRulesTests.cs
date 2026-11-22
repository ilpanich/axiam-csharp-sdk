using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Tests.Fixtures;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;10.1 rules 10-12 (contract 1.68; audit finding N14): the access-token
/// path refuses a present <c>typ</c> other than <c>at+jwt</c>, refuses any token whose claim
/// set contains <c>purpose</c>, and requires a <c>kid</c>. Rule 12 was already enforced by this
/// verifier (it has never fallen back to "the only key"); its tests pin that.
/// </summary>
[Trait("Category", "Fast")]
public sealed class AccessTokenRulesTests
{
    private const string Tenant = "acme";

    private sealed class JwksHandler : HttpMessageHandler
    {
        private readonly string _doc;
        private int _count;
        public JwksHandler(string doc) => _doc = doc;
        public int Count => Volatile.Read(ref _count);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _count);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_doc, Encoding.UTF8, "application/json"),
            });
        }
    }

    private static (JwksVerifier Verifier, JwksFixture Fixture, JwksHandler Handler) Create()
    {
        var fixture = new JwksFixture();
        var handler = new JwksHandler(fixture.BuildJwksDocument());
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://axiam.test") };
        return (new JwksVerifier(http, new Uri("https://axiam.test"), TimeSpan.FromMinutes(5)), fixture, handler);
    }

    private static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Signs header+payload with the fixture's key, so ONLY the rule under test can refuse it.</summary>
    private static string Mint(JwksFixture fixture, Dictionary<string, object?> header, Dictionary<string, object?>? extraClaims = null)
    {
        var payload = new Dictionary<string, object?>
        {
            ["sub"] = "user-1",
            ["tenant_id"] = Tenant,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),
        };
        if (extraClaims is not null)
        {
            foreach ((string k, object? v) in extraClaims)
            {
                payload[k] = v;
            }
        }
        string h = B64(JsonSerializer.SerializeToUtf8Bytes(header));
        string p = B64(JsonSerializer.SerializeToUtf8Bytes(payload));
        byte[] input = Encoding.ASCII.GetBytes($"{h}.{p}");
        var signer = new Ed25519Signer();
        signer.Init(true, fixture.PrivateKey);
        signer.BlockUpdate(input, 0, input.Length);
        return $"{h}.{p}.{B64(signer.GenerateSignature())}";
    }

    private static Dictionary<string, object?> Header(JwksFixture f, object? typ = null, bool withTyp = true, bool withKid = true)
    {
        var h = new Dictionary<string, object?> { ["alg"] = "EdDSA" };
        if (withKid) h["kid"] = f.Kid;
        if (withTyp) h["typ"] = typ;
        return h;
    }

    // ---- Rule 10: typ ------------------------------------------------------------------

    [Theory]
    [InlineData("JWT")]
    [InlineData("logout+jwt")]
    [InlineData("secevent+jwt")]
    [InlineData("axiam-webauthn-state+jwt")]
    [InlineData("axiam-mfa-challenge+jwt")]
    [InlineData("at+jwt+x")]
    [InlineData("")]
    public async Task ATypOtherThanAtJwt_IsRefused(string typ)
    {
        (JwksVerifier verifier, JwksFixture fixture, _) = Create();
        Assert.Null(await verifier.VerifyAsync(Mint(fixture, Header(fixture, typ)), Tenant));
        Assert.Null(await verifier.VerifyWithProofsAsync(Mint(fixture, Header(fixture, typ)), Tenant, PresentedProofs.None()));
    }

    [Fact]
    public async Task ANonStringTyp_IsRefused()
    {
        (JwksVerifier verifier, JwksFixture fixture, _) = Create();
        Assert.Null(await verifier.VerifyAsync(Mint(fixture, Header(fixture, 7)), Tenant));
        Assert.Null(await verifier.VerifyAsync(Mint(fixture, Header(fixture, null)), Tenant)); // typ: null
    }

    [Theory]
    [InlineData("at+jwt")]
    [InlineData("AT+JWT")]
    [InlineData("application/at+jwt")]
    [InlineData("Application/AT+JWT")]
    public async Task AtJwt_InAnyCaseWithOrWithoutThePrefix_Passes(string typ)
    {
        (JwksVerifier verifier, JwksFixture fixture, _) = Create();
        Assert.NotNull(await verifier.VerifyAsync(Mint(fixture, Header(fixture, typ)), Tenant));
    }

    [Fact]
    public async Task AHeaderWithNoTyp_IsNotRefusedByRule10()
    {
        (JwksVerifier verifier, JwksFixture fixture, _) = Create();
        Assert.NotNull(await verifier.VerifyAsync(Mint(fixture, Header(fixture, withTyp: false)), Tenant));
    }

    // ---- Rule 11: purpose --------------------------------------------------------------

    [Theory]
    [InlineData("mfa_challenge")]
    [InlineData("webauthn_authenticate_discoverable")]
    [InlineData("")]
    public async Task ATokenWithAPurposeClaim_IsRefused_WhateverTheTyp(string purpose)
    {
        (JwksVerifier verifier, JwksFixture fixture, _) = Create();
        var claims = new Dictionary<string, object?> { ["purpose"] = purpose };

        Assert.Null(await verifier.VerifyAsync(Mint(fixture, Header(fixture, withTyp: false), claims), Tenant));
        Assert.Null(await verifier.VerifyAsync(Mint(fixture, Header(fixture, "at+jwt"), claims), Tenant));
        Assert.Null(await verifier.VerifyWithProofsAsync(Mint(fixture, Header(fixture, "at+jwt"), claims), Tenant, PresentedProofs.None()));
    }

    [Fact]
    public async Task APurposeClaimOfNull_IsStillRefused()
    {
        (JwksVerifier verifier, JwksFixture fixture, _) = Create();
        var claims = new Dictionary<string, object?> { ["purpose"] = null };
        Assert.Null(await verifier.VerifyAsync(Mint(fixture, Header(fixture, "at+jwt"), claims), Tenant));
    }

    // ---- Rule 12: kid (already enforced; these pin it) ---------------------------------

    [Fact]
    public async Task AKidLessToken_IsRefused_WithoutFallingBackToTheOnlyKey_AndWithoutAFetch()
    {
        (JwksVerifier verifier, JwksFixture fixture, JwksHandler handler) = Create();
        // Correctly signed by the JWKS's only key; refused because it names no kid.
        string token = Mint(fixture, Header(fixture, "at+jwt", withKid: false));
        Assert.Null(await verifier.VerifyAsync(token, Tenant));
        Assert.Equal(0, handler.Count);
    }

    [Fact]
    public async Task ANormalAccessToken_Passes()
    {
        (JwksVerifier verifier, JwksFixture fixture, _) = Create();
        JsonElement? claims = await verifier.VerifyAsync(Mint(fixture, Header(fixture, "at+jwt")), Tenant);
        Assert.NotNull(claims);
        Assert.Equal("user-1", claims!.Value.GetProperty("sub").GetString());
    }
}
