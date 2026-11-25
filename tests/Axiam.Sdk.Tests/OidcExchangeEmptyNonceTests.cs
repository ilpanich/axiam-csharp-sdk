using System.Net;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;12.4 rule 6 (SA-23 ride-along): the nonce is mandatory for
/// <see cref="AxiamClient.OidcExchangeAsync"/>, so an EMPTY expected nonce is refused before
/// the code is spent, and cannot be satisfied by an ID token carrying <c>"nonce": ""</c>.
/// </summary>
[Trait("Category", "Fast")]
public sealed class OidcExchangeEmptyNonceTests
{
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public async Task AnEmptyExpectedNonce_IsRefused_AndSatisfiedByNoIdToken(string? expectedNonce)
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        var fixture = new JwksFixture();
        OidcTestKit.MapJwks(handler, fixture);
        AxiamClient client = OidcTestKit.Client(handler);

        // An ID token that carries an empty nonce, which an empty expectation would "match".
        string idToken = fixture.SignIdToken(new
        {
            iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'),
            sub = "user-1",
            aud = OidcTestKit.ClientId,
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            nonce = string.Empty,
        });
        handler.Map("/oauth2/token", _ => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("access-abc", "refresh-xyz", idToken)));

        var @params = new OidcExchangeParams
        {
            Code = "auth-code-123",
            CodeVerifier = Sensitive<string>.Wrap("verifier-abc"),
            RedirectUri = "https://app.example/callback",
            Nonce = expectedNonce!,
        };

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(@params));

        Assert.Equal(IdTokenFailureReasons.NonceMismatch, ex.Reason);
        // Refused before the authorization code is spent at the token endpoint.
        Assert.DoesNotContain(handler.Requests, r => r.RequestUri!.AbsolutePath == "/oauth2/token");
    }
}
