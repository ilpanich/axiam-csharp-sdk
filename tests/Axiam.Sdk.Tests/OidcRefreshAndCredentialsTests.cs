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

    /// <summary>
    /// CONTRACT.md &#167;12.1 (contract 1.60): a refresh may narrow <c>scope</c>, and the response's
    /// <c>scope</c> is the token set's — never the original grant's, never the one requested.
    /// </summary>
    [Fact]
    public async Task OidcRefreshAsync_TakesTheResponsesScopeNotTheGrantsOriginalOne()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/token", _ => OidcTestKit.JsonOk(
            """{"access_token":"narrowed-access","token_type":"Bearer","expires_in":900,"refresh_token":"next-refresh","scope":"profile"}"""));

        OidcTokenSet narrowed = await client.OidcRefreshAsync(new OidcRefreshParams
        {
            RefreshToken = Sensitive<string>.Wrap("old-refresh"),
            Scope = "openid profile email",
        });

        Assert.Equal("profile", narrowed.Scope);
        Assert.Null(narrowed.IdToken); // `openid` is gone, and with it the ID token

        handler.Map("/oauth2/token", _ => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("silent-access")));
        OidcTokenSet silent = await client.OidcRefreshAsync(new OidcRefreshParams
        {
            RefreshToken = Sensitive<string>.Wrap("next-refresh"),
            Scope = "openid profile email",
        });
        Assert.Null(silent.Scope);
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

    /// <summary>
    /// CONTRACT.md &#167;9, the contract 1.65 confirmation test. With the server's default
    /// <c>oauth2.refresh_reuse_response = revoke_session</c> a replayed refresh token ends the
    /// session, so the whole defence is single-flight: a <c>400 invalid_grant</c> is ONE wire call, every
    /// concurrent waiter receives that one error, and the spent token is never presented again.
    /// </summary>
    [Fact]
    public async Task OidcRefreshAsync_InvalidGrant_IsOneWireCall_SharedByEveryWaiter_AndTheSpentTokenIsNeverPresentedAgain()
    {
        const int Waiters = 8;
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        await client.OidcDiscoverAsync(); // pre-warm: only the refresh guard is left to race on

        var gate = new SemaphoreSlim(0);
        handler.Map("/oauth2/token", _ =>
        {
            gate.Wait(TimeSpan.FromSeconds(5)); // hold the call in flight so every waiter overlaps it
            return OidcTestKit.JsonStatus(
                System.Net.HttpStatusCode.BadRequest,
                OidcTestKit.OAuth2ErrorJson("invalid_grant", "refresh token is invalid or has been used"));
        });

        var refreshParams = new OidcRefreshParams { RefreshToken = Sensitive<string>.Wrap("spent-refresh") };
        Task<OidcTokenSet>[] tasks = Enumerable.Range(0, Waiters).Select(_ => client.OidcRefreshAsync(refreshParams)).ToArray();
        await Task.Delay(TimeSpan.FromMilliseconds(250));
        gate.Release(Waiters);

        OAuthProtocolError[] errors = new OAuthProtocolError[Waiters];
        for (int i = 0; i < Waiters; i++)
        {
            errors[i] = await Assert.ThrowsAsync<OAuthProtocolError>(() => tasks[i]);
            Assert.Equal("invalid_grant", errors[i].Error);
        }
        // One shared outcome: the same error object reaches every waiter.
        Assert.All(errors, e => Assert.Same(errors[0], e));

        // Exactly one wire call, and no retry follows it.
        await Task.Delay(TimeSpan.FromMilliseconds(250));
        var tokenRequests = handler.Requests.Where(r => r.RequestUri!.AbsolutePath == "/oauth2/token").ToList();
        Assert.Single(tokenRequests);
        Assert.Equal("spent-refresh", OidcTestKit.ReadForm(tokenRequests[0])["refresh_token"]);
        Assert.Equal(0, handler.CountFor("/api/v1/auth/refresh"));
    }

    // ---- CONTRACT.md §9 (per-refresh-token keying): the oidc_refresh single-flight is keyed by a digest of
    // the refresh token (plus tenant); callers presenting a DIFFERENT token never join and never receive
    // another token's outcome.

    private static void MapEchoingTokenEndpoint(RoutingHandler handler, SemaphoreSlim? hold = null)
    {
        handler.Map("/oauth2/token", request =>
        {
            string presented = OidcTestKit.ReadForm(request)["refresh_token"];
            hold?.Wait(TimeSpan.FromSeconds(5));
            return OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("access-for-" + presented, "next-for-" + presented));
        });
    }

    private static OidcRefreshParams RefreshWith(string token) =>
        new() { RefreshToken = Sensitive<string>.Wrap(token) };

    [Fact]
    public async Task OidcRefreshAsync_DifferentToken_DuringALiveFlight_GetsItsOwnWireCallAndItsOwnTokenSet()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        await client.OidcDiscoverAsync();
        var hold = new SemaphoreSlim(0);
        MapEchoingTokenEndpoint(handler, hold);

        Task<OidcTokenSet> a = client.OidcRefreshAsync(RefreshWith("token-A"));
        await Task.Delay(TimeSpan.FromMilliseconds(200)); // A is in flight, parked on the wire
        Task<OidcTokenSet> b = client.OidcRefreshAsync(RefreshWith("token-B"));
        await Task.Delay(TimeSpan.FromMilliseconds(200));
        hold.Release(2);

        Assert.Equal("access-for-token-A", (await a).AccessToken.Reveal());
        Assert.Equal("access-for-token-B", (await b).AccessToken.Reveal());
        Assert.Equal(2, handler.CountFor("/oauth2/token"));
    }

    [Fact]
    public async Task OidcRefreshAsync_PublishBeforeVacateWindow_SameTokenJoins_DifferentTokenRefreshesItself_AndFullVacateStartsFresh()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        await client.OidcDiscoverAsync();
        MapEchoingTokenEndpoint(handler);

        var windowOpen = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseWindow = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int hookCalls = 0;
        client.OidcRefreshBeforeVacateHook = () =>
        {
            // Hold only the FIRST owner (token-A's) between publish and vacate.
            if (Interlocked.Increment(ref hookCalls) != 1)
            {
                return Task.CompletedTask;
            }
            windowOpen.SetResult();
            return releaseWindow.Task;
        };

        Task<OidcTokenSet> a = client.OidcRefreshAsync(RefreshWith("token-A"));
        await windowOpen.Task.WaitAsync(TimeSpan.FromSeconds(5)); // A's outcome is published, its slot not yet vacated
        Assert.Equal(1, handler.CountFor("/oauth2/token"));

        // Same token, inside the window: joins the published outcome (rule 6a) — wire count stays at 1.
        OidcTokenSet joined = await client.OidcRefreshAsync(RefreshWith("token-A")).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("access-for-token-A", joined.AccessToken.Reveal());
        Assert.Equal(1, handler.CountFor("/oauth2/token"));

        // A different token, inside the same window: its own wire call and its own result.
        OidcTokenSet other = await client.OidcRefreshAsync(RefreshWith("token-B")).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("access-for-token-B", other.AccessToken.Reveal());
        Assert.Equal(2, handler.CountFor("/oauth2/token"));

        releaseWindow.SetResult();
        Assert.Equal("access-for-token-A", (await a).AccessToken.Reveal());

        // After the full vacate the same token gets a fresh wire call, with that call's own outcome.
        handler.Map("/oauth2/token", _ => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("access-second-burst")));
        OidcTokenSet fresh = await client.OidcRefreshAsync(RefreshWith("token-A"));
        Assert.Equal("access-second-burst", fresh.AccessToken.Reveal());
        Assert.Equal(3, handler.CountFor("/oauth2/token"));
    }

    [Fact]
    public async Task OidcRefreshAsync_TheRegistryNeverHoldsTheRawToken_AndEverySlotIsRemovedOnceVacated()
    {
        const string Secret = "raw-refresh-secret-value";
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        await client.OidcDiscoverAsync();
        var hold = new SemaphoreSlim(0);
        MapEchoingTokenEndpoint(handler, hold);

        Task<OidcTokenSet> a = client.OidcRefreshAsync(RefreshWith(Secret));
        Task<OidcTokenSet> b = client.OidcRefreshAsync(RefreshWith("another-secret-value"));
        await Task.Delay(TimeSpan.FromMilliseconds(200));

        Assert.Equal(2, client.OidcRefreshSlotCount);
        Assert.All(client.OidcRefreshSlotKeys, k =>
        {
            Assert.DoesNotContain("secret", k, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(64, k.Length); // lowercase hex SHA-256
            Assert.Matches("^[0-9a-f]{64}$", k);
        });

        hold.Release(2);
        await a;
        await b;
        Assert.Equal(0, client.OidcRefreshSlotCount);
    }

    [Fact]
    public async Task OidcRefreshAsync_SameTokenInADifferentTenant_IsADifferentFlight()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        await client.OidcDiscoverAsync();
        var hold = new SemaphoreSlim(0);
        MapEchoingTokenEndpoint(handler, hold);

        Task<OidcTokenSet> t1 = client.OidcRefreshAsync(new OidcRefreshParams { RefreshToken = Sensitive<string>.Wrap("same"), TenantId = Guid.NewGuid() });
        Task<OidcTokenSet> t2 = client.OidcRefreshAsync(new OidcRefreshParams { RefreshToken = Sensitive<string>.Wrap("same"), TenantId = Guid.NewGuid() });
        await Task.Delay(TimeSpan.FromMilliseconds(200));
        hold.Release(2);
        await t1;
        await t2;
        Assert.Equal(2, handler.CountFor("/oauth2/token"));
    }

    [Fact]
    public async Task OidcRefreshAsync_TenantSpelledUpperLowerOrOmittedDefault_IsOneFlight_AndScopeIsNotPartOfTheKey()
    {
        const string Tenant = "abcdef01-2345-4678-89ab-cdef01234567";
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        // The client's default tenant is configured in UPPER case.
        AxiamClient client = OidcTestKit.Client(handler, tenantId: Tenant.ToUpperInvariant());
        await client.OidcDiscoverAsync();
        var hold = new SemaphoreSlim(0);
        MapEchoingTokenEndpoint(handler, hold);

        Task<OidcTokenSet> omitted = client.OidcRefreshAsync(RefreshWith("same"));
        Task<OidcTokenSet> lower = client.OidcRefreshAsync(new OidcRefreshParams
        {
            RefreshToken = Sensitive<string>.Wrap("same"),
            TenantId = Guid.Parse(Tenant.ToLowerInvariant()),
            Scope = "a-different-scope",
        });
        Task<OidcTokenSet> upper = client.OidcRefreshAsync(new OidcRefreshParams
        {
            RefreshToken = Sensitive<string>.Wrap("same"),
            TenantId = Guid.Parse(Tenant.ToUpperInvariant()),
        });
        await Task.Delay(TimeSpan.FromMilliseconds(250));
        hold.Release(3);

        foreach (Task<OidcTokenSet> t in new[] { omitted, lower, upper })
        {
            Assert.Equal("access-for-same", (await t).AccessToken.Reveal());
        }
        Assert.Equal(1, handler.CountFor("/oauth2/token"));
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
