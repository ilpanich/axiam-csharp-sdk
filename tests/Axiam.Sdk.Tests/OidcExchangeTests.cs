using System.Net;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// <see cref="AxiamClient.OidcExchangeAsync"/> — CONTRACT.md &#167;12.1/&#167;12.4: the
/// happy path (form-encoded body, <c>?tenant_id=</c> query parameter, full ID-token
/// validation) plus one failing test per &#167;12.4 rule, using the contract's exact reason
/// codes.
/// </summary>
[Trait("Category", "Fast")]
public class OidcExchangeTests
{
    private const string Nonce = "test-nonce-value-1234567890";
    private const string Sub = "user-1";

    private static (RoutingHandler Handler, JwksFixture Fixture, AxiamClient Client) SetUp()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        var fixture = new JwksFixture();
        OidcTestKit.MapJwks(handler, fixture);
        AxiamClient client = OidcTestKit.Client(handler);
        return (handler, fixture, client);
    }

    private static void MapToken(RoutingHandler handler, string idToken, string accessToken = "access-abc", string? refreshToken = "refresh-xyz")
    {
        handler.Map("/oauth2/token", req =>
            OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson(accessToken, refreshToken, idToken)));
    }

    private static OidcExchangeParams ExchangeParams(Sensitive<string>? codeVerifier = null) => new()
    {
        Code = "auth-code-123",
        CodeVerifier = codeVerifier ?? Sensitive<string>.Wrap("verifier-abc"),
        RedirectUri = "https://app.example/callback",
        Nonce = Nonce,
    };

    [Fact]
    public async Task OidcExchangeAsync_HappyPath_SendsFormEncodedBody_WithTenantIdQuery_AndValidatesIdToken()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new
        {
            iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'),
            sub = Sub,
            aud = OidcTestKit.ClientId,
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            nonce = Nonce,
        });
        MapToken(handler, idToken);

        OidcTokenSet result = await client.OidcExchangeAsync(ExchangeParams());

        Assert.Equal("access-abc", result.AccessToken.Reveal());
        Assert.Equal("refresh-xyz", result.RefreshToken!.Value.Reveal());
        Assert.Equal("Bearer", result.TokenType);
        Assert.NotNull(result.IdClaims);
        Assert.Equal(Sub, result.IdClaims!.Sub);
        Assert.Contains(OidcTestKit.ClientId, result.IdClaims.Aud);

        var tokenRequest = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/oauth2/token");
        Assert.Equal("application/x-www-form-urlencoded", tokenRequest.Content!.Headers.ContentType!.MediaType);
        Assert.Equal($"tenant_id={OidcTestKit.TenantGuid}", tokenRequest.RequestUri!.Query.TrimStart('?'));

        Dictionary<string, string> form = OidcTestKit.ReadForm(tokenRequest);
        Assert.Equal("authorization_code", form["grant_type"]);
        Assert.Equal("auth-code-123", form["code"]);
        Assert.Equal("verifier-abc", form["code_verifier"]);
        Assert.Equal("https://app.example/callback", form["redirect_uri"]);
        Assert.Equal(OidcTestKit.ClientId, form["client_id"]);
        Assert.Equal(OidcTestKit.ClientSecret, form["client_secret"]);
    }

    [Fact]
    public async Task OidcExchangeAsync_RedactsTokensInToString()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new
        {
            iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'),
            sub = Sub,
            aud = OidcTestKit.ClientId,
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            nonce = Nonce,
        });
        MapToken(handler, idToken);

        OidcTokenSet result = await client.OidcExchangeAsync(ExchangeParams());

        Assert.Equal("[SENSITIVE]", result.AccessToken.ToString());
        Assert.Equal("[SENSITIVE]", result.RefreshToken!.Value.ToString());
        Assert.Equal("[SENSITIVE]", result.IdToken!.Value.ToString());
    }

    // ------------------------------------------------------------------
    // §12.4 ID-token failure modes — one test per rule, exact reason codes.
    // ------------------------------------------------------------------

    [Fact]
    public async Task IdToken_AlgNone_RejectedAsInvalidAlg()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = JwksFixture.BuildRawToken(
            header: new { alg = "none" },
            payload: new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, aud = OidcTestKit.ClientId, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = Nonce },
            signaturePart: "unused-signature");
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.InvalidAlg, ex.Reason);
    }

    [Fact]
    public async Task IdToken_UnexpectedAlg_RejectedAsInvalidAlg()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = JwksFixture.BuildRawToken(
            header: new { alg = "RS256", kid = fixture.Kid },
            payload: new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, aud = OidcTestKit.ClientId, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = Nonce });
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.InvalidAlg, ex.Reason);
    }

    [Fact]
    public async Task IdToken_UnknownKid_RejectedAfterOneRefetch()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(
            new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, aud = OidcTestKit.ClientId, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = Nonce },
            kidOverride: "does-not-exist");
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.UnknownKid, ex.Reason);
        Assert.Equal(1, handler.CountFor("/oauth2/jwks"));
    }

    [Fact]
    public async Task IdToken_MissingKidHeader_RejectedAsUnknownKid()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(
            new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, aud = OidcTestKit.ClientId, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = Nonce },
            includeKid: false);
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.UnknownKid, ex.Reason);
    }

    [Fact]
    public async Task IdToken_TamperedSignature_RejectedAsInvalidSignature()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string valid = fixture.SignIdToken(new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, aud = OidcTestKit.ClientId, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = Nonce });
        string[] parts = valid.Split('.');
        byte[] sig = Convert.FromBase64String(PadBase64Url(parts[2]));
        sig[^1] ^= 0xFF;
        string tampered = $"{parts[0]}.{parts[1]}.{Convert.ToBase64String(sig).TrimEnd('=').Replace('+', '-').Replace('/', '_')}";
        MapToken(handler, tampered);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.InvalidSignature, ex.Reason);
    }

    [Fact]
    public async Task IdToken_WrongIssuer_RejectedAsInvalidIssuer()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new { iss = "https://not-axiam.example", sub = Sub, aud = OidcTestKit.ClientId, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = Nonce });
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.InvalidIssuer, ex.Reason);
    }

    [Fact]
    public async Task IdToken_WrongAudience_RejectedAsInvalidAudience()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, aud = "some-other-client", exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = Nonce });
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.InvalidAudience, ex.Reason);
    }

    [Fact]
    public async Task IdToken_MultipleAudiencesWithoutMatchingAzp_RejectedAsInvalidAudience()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new
        {
            iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'),
            sub = Sub,
            aud = new[] { OidcTestKit.ClientId, "another-audience" },
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            nonce = Nonce,
        });
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.InvalidAudience, ex.Reason);
    }

    [Fact]
    public async Task IdToken_Expired_RejectedAsTokenExpired()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, aud = OidcTestKit.ClientId, exp = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.AddMinutes(-20).ToUnixTimeSeconds(), nonce = Nonce });
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.TokenExpired, ex.Reason);
    }

    [Fact]
    public async Task IdToken_MissingExpClaim_RejectedAsTokenExpired()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, aud = OidcTestKit.ClientId, iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = Nonce });
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.TokenExpired, ex.Reason);
    }

    [Fact]
    public async Task IdToken_FutureIat_RejectedAsTokenExpired()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new
        {
            iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'),
            sub = Sub,
            aud = OidcTestKit.ClientId,
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),
            nonce = Nonce,
        });
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.TokenExpired, ex.Reason);
    }

    [Fact]
    public async Task IdToken_NonceMismatch_RejectedAsNonceMismatch()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, aud = OidcTestKit.ClientId, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = "wrong-nonce" });
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.NonceMismatch, ex.Reason);
    }

    [Fact]
    public async Task IdToken_MissingNonceClaim_RejectedAsNonceMismatch()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, aud = OidcTestKit.ClientId, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds() });
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.NonceMismatch, ex.Reason);
    }

    [Fact]
    public async Task IdToken_MissingAudClaimEntirely_RejectedAsInvalidAudience()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = Nonce });
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.InvalidAudience, ex.Reason);
    }

    [Fact]
    public async Task IdToken_MissingIatClaim_RejectedAsTokenExpired()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, aud = OidcTestKit.ClientId, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), nonce = Nonce });
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.TokenExpired, ex.Reason);
    }

    [Fact]
    public async Task IdToken_FutureNbf_RejectedAsTokenExpired()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new
        {
            iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'),
            sub = Sub,
            aud = OidcTestKit.ClientId,
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            nbf = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),
            nonce = Nonce,
        });
        MapToken(handler, idToken);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));
        Assert.Equal(IdTokenFailureReasons.TokenExpired, ex.Reason);
    }

    [Fact]
    public async Task IdToken_ExtraClaims_ArePreservedInOpenMap()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new
        {
            iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'),
            sub = Sub,
            aud = OidcTestKit.ClientId,
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            nonce = Nonce,
            email = "user1@example.com",
            preferred_username = "user1",
        });
        MapToken(handler, idToken);

        OidcTokenSet result = await client.OidcExchangeAsync(ExchangeParams());

        Assert.NotNull(result.IdClaims!.Extra);
        Assert.Equal("user1@example.com", result.IdClaims.Extra!["email"].GetString());
        Assert.Equal("user1", result.IdClaims.Extra["preferred_username"].GetString());
        // Modeled claims must NOT leak into the open map.
        Assert.False(result.IdClaims.Extra.ContainsKey("sub"));
        Assert.False(result.IdClaims.Extra.ContainsKey("iss"));
    }

    [Fact]
    public async Task OidcExchangeAsync_ExplicitTenantId_OverridesClientTenant()
    {
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new { iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'), sub = Sub, aud = OidcTestKit.ClientId, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = Nonce });
        MapToken(handler, idToken);
        var explicitTenant = Guid.Parse("99999999-9999-9999-9999-999999999999");

        var parameters = ExchangeParams();
        var explicitParams = new OidcExchangeParams
        {
            Code = parameters.Code,
            CodeVerifier = parameters.CodeVerifier,
            RedirectUri = parameters.RedirectUri,
            Nonce = parameters.Nonce,
            TenantId = explicitTenant,
        };

        await client.OidcExchangeAsync(explicitParams);

        var tokenRequest = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/oauth2/token");
        Assert.Equal($"tenant_id={explicitTenant}", tokenRequest.RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task IdToken_ValidationFailure_DiscardsWholeTokenSet_AccessTokenNeverReturned()
    {
        // §12.4 rule 7: on ANY id_token failure, access_token/refresh_token from the SAME
        // response must never reach the caller — the exception is the only observable
        // outcome, there is no partial OidcTokenSet. F-13: mirror the five sibling SDKs
        // (Go, Python, Rust, PHP, TS) by using a sentinel value for BOTH tokens and
        // positively asserting it appears nowhere in the outcome or the error, not
        // merely that *an* exception was thrown.
        (RoutingHandler handler, JwksFixture fixture, AxiamClient client) = SetUp();
        string idToken = fixture.SignIdToken(new { iss = "https://wrong-issuer.example", sub = Sub, aud = OidcTestKit.ClientId, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(), iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce = Nonce });
        MapToken(handler, idToken, accessToken: "should-never-be-returned", refreshToken: "should-never-be-returned-either");

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(ExchangeParams()));

        // OidcExchangeAsync threw rather than returning an OidcTokenSet, so there is no
        // partial object a caller could read a token out of — the only observable
        // surface is the exception itself. Assert the sentinel tokens are absent from it.
        Assert.DoesNotContain("should-never-be-returned", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("should-never-be-returned", ex.ToString(), StringComparison.Ordinal);
    }

    private static string PadBase64Url(string s)
    {
        string padded = s.Replace('-', '+').Replace('_', '/');
        return padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
    }
}
