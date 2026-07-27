using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// <see cref="AxiamClient.OidcRefreshAsync"/> (single-flight, §9) and
/// <see cref="AxiamClient.LoginClientCredentialsAsync"/> happy path (CONTRACT.md &#167;12.1).
/// </summary>
[Trait("Category", "Fast")]
public class OidcRefreshAndCredentialsTests
{
    private static (RoutingHandler Handler, AxiamClient Client) SetUp()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        return (handler, client);
    }

    [Fact]
    public async Task OidcRefreshAsync_HappyPath_SendsRefreshTokenGrant()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/token", _ => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("new-access", "new-refresh")));

        OidcTokenSet result = await client.OidcRefreshAsync(new OidcRefreshParams
        {
            RefreshToken = Sensitive<string>.Wrap("old-refresh"),
            Scope = "openid profile",
        });

        Assert.Equal("new-access", result.AccessToken.Reveal());
        Assert.Null(result.IdClaims); // no id_token in the response

        var tokenRequest = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/oauth2/token");
        Dictionary<string, string> form = OidcTestKit.ReadForm(tokenRequest);
        Assert.Equal("refresh_token", form["grant_type"]);
        Assert.Equal("old-refresh", form["refresh_token"]);
        Assert.Equal("openid profile", form["scope"]);
    }

    [Fact]
    public async Task OidcRefreshAsync_IsDistinctFromCookieSessionRefresh_NeverAliased()
    {
        // §12.1 "oidc_refresh vs refresh": the two operations must never fall back to one
        // another. A client with no active cookie session must still be able to call
        // OidcRefreshAsync purely off the caller-supplied refresh token.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/token", _ => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("new-access")));
        handler.Map("/api/v1/auth/refresh", _ => throw new InvalidOperationException("cookie-session refresh must never be invoked by OidcRefreshAsync"));

        await client.OidcRefreshAsync(new OidcRefreshParams { RefreshToken = Sensitive<string>.Wrap("old-refresh") });

        Assert.Equal(0, handler.CountFor("/api/v1/auth/refresh"));
    }

    [Fact]
    public async Task OidcRefreshAsync_ConcurrentCallers_ShareOutcome_NoRetryOnFailure()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        // Pre-warm the discovery cache so the only thing left to race on below is the
        // dedicated oidc_refresh single-flight guard itself, not the (already
        // single-flighted, separately tested) discovery fetch.
        await client.OidcDiscoverAsync();

        int tokenHits = 0;
        var gate = new SemaphoreSlim(0);
        handler.Map("/oauth2/token", _ =>
        {
            Interlocked.Increment(ref tokenHits);
            // Force every concurrent caller to genuinely overlap in-flight before the
            // single call completes, proving the single-flight guard rather than mere
            // scheduling luck (mirrors OidcDiscoveryTests' identical technique).
            gate.Wait(TimeSpan.FromSeconds(5));
            return OidcTestKit.Empty(System.Net.HttpStatusCode.InternalServerError);
        });

        var refreshParams = new OidcRefreshParams { RefreshToken = Sensitive<string>.Wrap("old-refresh") };
        Task<OidcTokenSet>[] tasks = Enumerable.Range(0, 5).Select(_ => client.OidcRefreshAsync(refreshParams)).ToArray();

        await Task.Delay(TimeSpan.FromMilliseconds(200));
        gate.Release(5);

        foreach (Task<OidcTokenSet> task in tasks)
        {
            await Assert.ThrowsAsync<NetworkError>(() => task);
        }
        // Every waiter shares the SAME failed attempt — no per-caller retry (§9.3).
        Assert.Equal(1, tokenHits);

        // A subsequent call starts a genuinely fresh attempt once the in-flight slot clears.
        handler.Map("/oauth2/token", _ =>
        {
            Interlocked.Increment(ref tokenHits);
            return OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("access-after-retry"));
        });
        OidcTokenSet result = await client.OidcRefreshAsync(refreshParams);
        Assert.Equal("access-after-retry", result.AccessToken.Reveal());
        Assert.Equal(2, tokenHits);
    }

    [Fact]
    public async Task LoginClientCredentialsAsync_HappyPath_SendsClientCredentialsGrant()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/token", _ => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("service-access", refreshToken: null)));

        OidcTokenSet result = await client.LoginClientCredentialsAsync(new LoginClientCredentialsParams { Scope = "reports:read" });

        Assert.Equal("service-access", result.AccessToken.Reveal());
        Assert.Null(result.RefreshToken);
        Assert.Null(result.IdClaims); // no openid scope requested, no id_token

        var tokenRequest = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/oauth2/token");
        Dictionary<string, string> form = OidcTestKit.ReadForm(tokenRequest);
        Assert.Equal("client_credentials", form["grant_type"]);
        Assert.Equal(OidcTestKit.ClientId, form["client_id"]);
        Assert.Equal(OidcTestKit.ClientSecret, form["client_secret"]);
        Assert.Equal("reports:read", form["scope"]);
    }

    [Fact]
    public async Task LoginClientCredentialsAsync_NoClientSecret_ThrowsAuthError_WithoutWireCall()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(clientSecret: null));

        await Assert.ThrowsAsync<AuthError>(() => client.LoginClientCredentialsAsync(new LoginClientCredentialsParams()));
        Assert.Equal(0, handler.CountFor("/oauth2/token"));
    }

    [Fact]
    public async Task LoginClientCredentialsAsync_AdoptAsCredential_ThrowsNotSupported()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            client.LoginClientCredentialsAsync(new LoginClientCredentialsParams { AdoptAsCredential = true }));
    }
}
