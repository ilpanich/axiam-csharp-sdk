using System.Net;
using System.Reflection;
using System.Text;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
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
        await WaitForVacateAsync(client);
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

    /// <summary>Waits for every oidc_refresh slot to be vacated (the flight vacates after it publishes its outcome).</summary>
    private static async Task WaitForVacateAsync(AxiamClient client)
    {
        for (int i = 0; i < 500 && client.OidcRefreshSlotCount != 0; i++)
        {
            await Task.Delay(10);
        }
        Assert.Equal(0, client.OidcRefreshSlotCount);
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
        await WaitForVacateAsync(client);

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
        await WaitForVacateAsync(client);
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

    private static CookieContainer CookiesOf(AxiamClient client) =>
        (CookieContainer)typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(client)!;

    private static void SetAccessCookie(AxiamClient client, string? tenantGuid)
    {
        static string B64(string json) => Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        CookieContainer container = CookiesOf(client);
        var cookie = new Cookie("axiam_access", tenantGuid is null ? "gone" : $"{B64("{\"alg\":\"none\"}")}.{B64($"{{\"tenant_id\":\"{tenantGuid}\"}}")}.unsigned");
        if (tenantGuid is null)
        {
            cookie.Expired = true;
        }
        container.Add(OidcTestKit.BaseUrl, cookie);
    }

    [Fact]
    public async Task OidcRefreshAsync_TenantFromTheSessionCookie_IsResolvedOnce_TheKeyAndTheWireAgree_EvenIfTheSessionChangesDuringDiscovery()
    {
        const string TenantX = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        const string TenantY = "11111111-2222-4333-8444-555555555555";
        var handler = new RoutingHandler();
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(tenantId: "acme"), tenantId: "acme");
        SetAccessCookie(client, TenantX);
        // The session changes (a login as another tenant, then a logout) while discovery is being fetched.
        handler.Map("/.well-known/openid-configuration", _ =>
        {
            SetAccessCookie(client, TenantY);
            SetAccessCookie(client, null);
            return OidcTestKit.JsonOk(OidcTestKit.DiscoveryJson(OidcTestKit.BaseUrl, null, true));
        });
        MapEchoingTokenEndpoint(handler);

        OidcTokenSet result = await client.OidcRefreshAsync(RefreshWith("rotating"));

        Assert.Equal("access-for-rotating", result.AccessToken.Reveal());
        var token = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/oauth2/token");
        Assert.Equal($"tenant_id={TenantX}", token.RequestUri!.Query.TrimStart('?'));
        await WaitForVacateAsync(client); // no slot is left behind
    }

    [Fact]
    public async Task OidcRefreshAsync_UnresolvableTenant_FailsAtOnce_NoSlot_NoDiscovery_NoTokenCall()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapEchoingTokenEndpoint(handler);
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(tenantId: "acme"), tenantId: "acme");

        await Assert.ThrowsAsync<AuthError>(() => client.OidcRefreshAsync(RefreshWith("r")));

        Assert.Equal(0, client.OidcRefreshSlotCount);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task OidcRefreshAsync_OwnerCancels_TheJoinerStillGetsTheTokenSet_AndOnlyTheOwnerSeesTheCancellation()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        await client.OidcDiscoverAsync();
        var hold = new SemaphoreSlim(0);
        MapEchoingTokenEndpoint(handler, hold);

        using var ownerCts = new CancellationTokenSource();
        Task<OidcTokenSet> owner = client.OidcRefreshAsync(RefreshWith("shared"), ownerCts.Token);
        await Task.Delay(TimeSpan.FromMilliseconds(200));
        Task<OidcTokenSet> joiner = client.OidcRefreshAsync(RefreshWith("shared"));
        await Task.Delay(TimeSpan.FromMilliseconds(100));

        ownerCts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => owner);
        hold.Release(1);

        Assert.Equal("access-for-shared", (await joiner).AccessToken.Reveal());
        Assert.Equal(1, handler.CountFor("/oauth2/token"));
        await WaitForVacateAsync(client);
    }

    [Fact]
    public async Task OidcRefreshAsync_JoinerCancels_OnlyTheJoinerSeesTheCancellation_TheOwnerStillGetsTheTokenSet()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        await client.OidcDiscoverAsync();
        var hold = new SemaphoreSlim(0);
        MapEchoingTokenEndpoint(handler, hold);

        Task<OidcTokenSet> owner = client.OidcRefreshAsync(RefreshWith("shared"));
        await Task.Delay(TimeSpan.FromMilliseconds(200));
        using var joinerCts = new CancellationTokenSource();
        Task<OidcTokenSet> joiner = client.OidcRefreshAsync(RefreshWith("shared"), joinerCts.Token);
        await Task.Delay(TimeSpan.FromMilliseconds(100));

        joinerCts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => joiner);
        hold.Release(1);

        Assert.Equal("access-for-shared", (await owner).AccessToken.Reveal());
        Assert.Equal(1, handler.CountFor("/oauth2/token"));
    }

    [Fact]
    public async Task OidcRefreshAsync_AThrowingBeforeVacateHook_StillVacatesTheSlot()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        await client.OidcDiscoverAsync();
        MapEchoingTokenEndpoint(handler);
        client.OidcRefreshBeforeVacateHook = () => throw new InvalidOperationException("hook failure");

        Assert.Equal("access-for-r", (await client.OidcRefreshAsync(RefreshWith("r"))).AccessToken.Reveal());
        await WaitForVacateAsync(client);
    }

    [Fact]
    public async Task OidcRefreshAsync_ADifferentKeysWireCallStartsAndCompletesWhileAnothersIsHeldOnTheTransport()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        await client.OidcDiscoverAsync();
        var holdA = new SemaphoreSlim(0);
        handler.Map("/oauth2/token", request =>
        {
            string presented = OidcTestKit.ReadForm(request)["refresh_token"];
            if (presented == "token-A")
            {
                holdA.Wait(TimeSpan.FromSeconds(10));
            }
            return OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("access-for-" + presented));
        });

        Task<OidcTokenSet> a = client.OidcRefreshAsync(RefreshWith("token-A"));
        await Task.Delay(TimeSpan.FromMilliseconds(200)); // A's request is parked on the transport
        Assert.Equal(1, handler.CountFor("/oauth2/token"));

        OidcTokenSet b = await client.OidcRefreshAsync(RefreshWith("token-B")).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("access-for-token-B", b.AccessToken.Reveal());
        Assert.Equal(2, handler.CountFor("/oauth2/token")); // B's wire call happened while A's was held
        Assert.False(a.IsCompleted);

        holdA.Release();
        Assert.Equal("access-for-token-A", (await a).AccessToken.Reveal());
    }

    [Fact]
    public async Task OidcRefreshAsync_TwentyConcurrentDistinctTokens_AllCompleteUnderATimeout()
    {
        const int N = 20;
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        await client.OidcDiscoverAsync();
        MapEchoingTokenEndpoint(handler);

        Task<OidcTokenSet>[] tasks = Enumerable.Range(0, N).Select(i => client.OidcRefreshAsync(RefreshWith("token-" + i))).ToArray();
        OidcTokenSet[] results = await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(20));

        for (int i = 0; i < N; i++)
        {
            Assert.Equal("access-for-token-" + i, results[i].AccessToken.Reveal());
        }
        Assert.Equal(N, handler.CountFor("/oauth2/token"));
        await WaitForVacateAsync(client);
    }

    /// <summary>Serves discovery from the inner handler; the token endpoint never answers until cancelled.</summary>
    private sealed class HangingTokenHandler(RoutingHandler inner) : DelegatingHandler(inner)
    {
        public int TokenCalls;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == "/oauth2/token")
            {
                Interlocked.Increment(ref TokenCalls);
                await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            }
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }

    [Fact]
    public async Task OidcRefreshAsync_FlightBoundFires_EveryCallerGetsNetworkError_NotARawCancellation()
    {
        var routing = new RoutingHandler();
        OidcTestKit.MapDiscovery(routing);
        var handler = new HangingTokenHandler(routing);
        AxiamClient client = OidcTestKit.Client(handler);
        await client.OidcDiscoverAsync();
        client.OidcRefreshFlightTimeoutOverride = TimeSpan.FromMilliseconds(300);

        Task<OidcTokenSet>[] callers = Enumerable.Range(0, 3).Select(_ => client.OidcRefreshAsync(RefreshWith("hangs"))).ToArray();

        foreach (Task<OidcTokenSet> caller in callers)
        {
            NetworkError error = await Assert.ThrowsAsync<NetworkError>(() => caller.WaitAsync(TimeSpan.FromSeconds(10)));
            Assert.DoesNotContain("hangs", error.Message, StringComparison.Ordinal);
        }
        Assert.Equal(1, handler.TokenCalls);
        await WaitForVacateAsync(client);
    }

    [Fact]
    public void OidcRefreshFlightTimeout_IsDerivedFromTheClientsOptions_AndNeverBelowOneRequestTimeout()
    {
        var handler = new RoutingHandler();
        AxiamClientOptions longOptions = OidcTestKit.Options() with { RequestTimeout = TimeSpan.FromSeconds(120) };
        AxiamClient longer = OidcTestKit.Client(handler, longOptions);
        Assert.True(longer.OidcRefreshFlightTimeout > TimeSpan.FromSeconds(120));

        AxiamClientOptions singleOptions = OidcTestKit.Options() with { RequestTimeout = TimeSpan.FromSeconds(7), RetryEnabled = false };
        AxiamClient single = OidcTestKit.Client(handler, singleOptions);
        Assert.True(single.OidcRefreshFlightTimeout >= TimeSpan.FromSeconds(7));
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
