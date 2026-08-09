using System.Net;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Device Authorization Grant — CONTRACT.md &#167;14.
/// </summary>
/// <remarks>
/// Fixtures use a 1-second interval so the wire assertions — which answers loop, which terminate,
/// how many requests actually go out, and the &#167;14.3 rule 2 ordering guarantee — run in about
/// as long as they take to describe.
/// </remarks>
[Trait("Category", "Fast")]
public class OidcDeviceFlowTests
{
    private const string DeviceAuthPath = "/oauth2/device_authorization";
    private const string TokenPath = "/oauth2/token";

    /// <summary>A device client: no client secret, per &#167;14.1.</summary>
    private static (RoutingHandler Handler, AxiamClient Client) SetUp(bool withOptionalEndpoints = true)
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler, withOptionalEndpoints: withOptionalEndpoints);
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(clientSecret: null));
        return (handler, client);
    }

    private static void MapAuthorization(RoutingHandler handler, int expiresIn = 30, int? interval = 1) =>
        handler.Map(DeviceAuthPath, _ => OidcTestKit.JsonOk(
            OidcTestKit.DeviceAuthorizationJson(expiresIn: expiresIn, interval: interval)));

    /// <summary>Replies with each responder in order, repeating the last once exhausted.</summary>
    private static Func<int> ScriptToken(RoutingHandler handler, params Func<HttpResponseMessage>[] steps)
    {
        int index = 0;
        handler.Map(TokenPath, _ =>
        {
            int i = index++;
            return steps[Math.Min(i, steps.Length - 1)]();
        });
        return () => index;
    }

    private static HttpResponseMessage OAuthError(string code) =>
        OidcTestKit.JsonStatus(HttpStatusCode.BadRequest, OidcTestKit.OAuth2ErrorJson(code, $"{code} description"));

    private static HttpResponseMessage TokenSuccess() =>
        OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("device-access-token", "device-refresh-token"));

    // -----------------------------------------------------------------------
    // DeviceAuthorizeAsync
    // -----------------------------------------------------------------------

    [Fact]
    public async Task DeviceAuthorizeAsync_IsUnauthenticated_AndSendsTenantIdAsQuery()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        Dictionary<string, string>? form = null;
        Uri? uri = null;
        handler.Map(DeviceAuthPath, request =>
        {
            form = OidcTestKit.ReadForm(request);
            uri = request.RequestUri;
            return OidcTestKit.JsonOk(OidcTestKit.DeviceAuthorizationJson());
        });

        DeviceAuthorization authorization = await client.DeviceAuthorizeAsync(
            new DeviceAuthorizeParams(Scope: "openid profile"));

        Assert.NotNull(form);
        // §14.1: a device that cannot show a browser cannot hold a client secret, and the SDK
        // must not refuse such a client.
        Assert.False(form!.ContainsKey("client_secret"));
        Assert.Equal("openid profile", form["scope"]);
        // §12.1 note 2: tenant_id is a query parameter, never a body field.
        Assert.False(form.ContainsKey("tenant_id"));
        Assert.Contains("tenant_id=", uri!.Query, StringComparison.Ordinal);

        Assert.Equal(OidcTestKit.UserCode, authorization.UserCode);
        Assert.Equal(1, authorization.Interval);
        Assert.NotNull(authorization.VerificationUriComplete);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    public async Task DeviceAuthorizeAsync_AbsentOrZeroInterval_DefaultsToFiveSeconds(int? interval)
    {
        // §14.2 rule 2: an SDK MUST NOT hard-code a faster floor, and a server-sent 0 is treated
        // as absent — polling with no delay is never what the server meant.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapAuthorization(handler, expiresIn: 600, interval: interval);

        DeviceAuthorization authorization = await client.DeviceAuthorizeAsync(new DeviceAuthorizeParams());

        Assert.Equal(AxiamClient.DefaultDevicePollIntervalSeconds, authorization.Interval);
    }

    [Fact]
    public async Task DeviceAuthorizeAsync_NoEndpointAdvertised_ThrowsRatherThanGuessingAUrl()
    {
        (RoutingHandler _, AxiamClient client) = SetUp(withOptionalEndpoints: false);

        AuthError error = await Assert.ThrowsAsync<AuthError>(
            () => client.DeviceAuthorizeAsync(new DeviceAuthorizeParams()));

        Assert.Contains("device_authorization_endpoint", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DeviceAuthorizeAsync_RedactsTheDeviceCodeButNotTheUserCode()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapAuthorization(handler);

        DeviceAuthorization authorization = await client.DeviceAuthorizeAsync(new DeviceAuthorizeParams());

        // §14.5: device_code is a bearer credential and must never render.
        Assert.DoesNotContain(OidcTestKit.DeviceCode, authorization.DeviceCode.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(OidcTestKit.DeviceCode, authorization.ToString(), StringComparison.Ordinal);
        Assert.Equal(OidcTestKit.DeviceCode, authorization.DeviceCode.Reveal());
        // §14.5: user_code is NOT wrapped — it exists to be read aloud, and wrapping it would
        // defeat the one thing it is for.
        Assert.Equal(OidcTestKit.UserCode, authorization.UserCode);
        Assert.Contains(OidcTestKit.UserCode, authorization.ToString(), StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // §14.2 polling
    // -----------------------------------------------------------------------

    [Fact]
    public async Task DeviceLoginAsync_LoopsOnAuthorizationPending()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapAuthorization(handler);
        Func<int> calls = ScriptToken(
            handler,
            () => OAuthError("authorization_pending"),
            () => OAuthError("authorization_pending"),
            TokenSuccess);

        OidcTokenSet tokens = await client.DeviceLoginAsync(
            new DeviceLoginParams(OnUserCode: _ => Task.CompletedTask));

        Assert.Equal(3, calls());
        Assert.Equal("device-access-token", tokens.AccessToken.Reveal());
    }

    [Fact]
    public async Task DeviceLoginAsync_SlowDownIsNotTerminal()
    {
        // The interval increase itself is not wall-clock-asserted; what matters is that
        // slow_down is not mistaken for a terminal answer. An SDK that let it fall through
        // would abort a grant the user is still approving.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapAuthorization(handler, expiresIn: 60);
        Func<int> calls = ScriptToken(handler, () => OAuthError("slow_down"), TokenSuccess);

        OidcTokenSet tokens = await client.DeviceLoginAsync(
            new DeviceLoginParams(OnUserCode: _ => Task.CompletedTask));

        Assert.Equal(2, calls());
        Assert.Equal("device-access-token", tokens.AccessToken.Reveal());
    }

    [Theory]
    [InlineData("access_denied")]
    [InlineData("expired_token")]
    [InlineData("invalid_grant")]
    public async Task DeviceLoginAsync_TerminalAnswersStopTheLoopAtOnce(string code)
    {
        // §14.2 rule 3: "a human said no" and "nobody answered" are the only two pieces of
        // information the device can act on, so they must not be collapsed.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapAuthorization(handler);
        Func<int> calls = ScriptToken(handler, () => OAuthError(code));

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.DeviceLoginAsync(new DeviceLoginParams(OnUserCode: _ => Task.CompletedTask)));

        Assert.Equal(code, error.Error);
        Assert.Equal(1, calls());
    }

    [Fact]
    public async Task DeviceLoginAsync_StopsAtExpiresIn_EvenWhileTheServerSaysPending()
    {
        // 2-second grant, 1-second interval: one poll at t=1, then the t=2 tick is the deadline
        // and must not be sent.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapAuthorization(handler, expiresIn: 2, interval: 1);
        Func<int> calls = ScriptToken(handler, () => OAuthError("authorization_pending"));

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.DeviceLoginAsync(new DeviceLoginParams(OnUserCode: _ => Task.CompletedTask)));

        // §14.2 rule 4: reported under the same code the server would have used, so a caller's
        // branch does not care which side noticed first.
        Assert.Equal("expired_token", error.Error);
        Assert.Equal(1, calls());
    }

    [Fact]
    public async Task DeviceLoginAsync_ServerErrorMidPoll_IsRetriedNotTerminal()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapAuthorization(handler, expiresIn: 60);
        Func<int> calls = ScriptToken(
            handler,
            () => OAuthError("authorization_pending"),
            () => OidcTestKit.Empty(HttpStatusCode.InternalServerError),
            () => OidcTestKit.Empty(HttpStatusCode.ServiceUnavailable),
            TokenSuccess);

        OidcTokenSet tokens = await client.DeviceLoginAsync(
            new DeviceLoginParams(OnUserCode: _ => Task.CompletedTask));

        // §14.2 rule 6: a server restart must not lose a grant the user has already approved.
        Assert.Equal(4, calls());
        Assert.Equal("device-access-token", tokens.AccessToken.Reveal());
    }

    // -----------------------------------------------------------------------
    // §14.3 DeviceLoginAsync
    // -----------------------------------------------------------------------

    [Fact]
    public async Task DeviceLoginAsync_SurfacesTheUserCodeBeforeTheFirstPoll()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapAuthorization(handler);
        var order = new List<string>();
        handler.Map(TokenPath, _ =>
        {
            order.Add("poll");
            return TokenSuccess();
        });

        string? seen = null;
        await client.DeviceLoginAsync(new DeviceLoginParams(OnUserCode: async authorization =>
        {
            // An async callback: a device rendering a QR code may need to await a paint, and
            // polling before that completes would defeat rule 2 as surely as not calling back.
            await Task.Delay(20);
            order.Add("userCode");
            seen = authorization.UserCode;
        }));

        Assert.Equal(new[] { "userCode", "poll" }, order);
        Assert.Equal(OidcTestKit.UserCode, seen);
    }

    [Fact]
    public async Task DeviceLoginAsync_ReturnsTheTokenSet()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapAuthorization(handler);
        handler.Map(TokenPath, _ => TokenSuccess());

        OidcTokenSet tokens = await client.DeviceLoginAsync(
            new DeviceLoginParams(OnUserCode: _ => Task.CompletedTask));

        // §14.6 as amended by the contract 1.7 errata: assert the RETURNED token set.
        Assert.Equal("device-access-token", tokens.AccessToken.Reveal());
        Assert.Equal("Bearer", tokens.TokenType);
    }

    [Fact]
    public async Task DeviceLoginAsync_AdoptAsCredential_ThrowsNotSupported()
    {
        // §14.3 rule 4 defers to the §12.1 adoption MAY, and this port's settled posture there
        // is NotSupportedException. Taking a second posture here would be exactly the
        // per-language improvisation the contract exists to prevent.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapAuthorization(handler);

        NotSupportedException error = await Assert.ThrowsAsync<NotSupportedException>(
            () => client.DeviceLoginAsync(
                new DeviceLoginParams(OnUserCode: _ => Task.CompletedTask, AdoptAsCredential: true)));

        Assert.Contains("AdoptAsCredential", error.Message, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // DevicePollAsync standalone
    // -----------------------------------------------------------------------

    [Fact]
    public async Task DevicePollAsync_SurfacesPendingForHandRolledLoops()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map(TokenPath, _ => OAuthError("authorization_pending"));

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode))));

        Assert.Equal("authorization_pending", error.Error);
    }

    [Fact]
    public async Task DevicePollAsync_SendsTheDeviceCodeGrant()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        Dictionary<string, string>? form = null;
        handler.Map(TokenPath, request =>
        {
            form = OidcTestKit.ReadForm(request);
            return TokenSuccess();
        });

        await client.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode)));

        Assert.NotNull(form);
        Assert.Equal("urn:ietf:params:oauth:grant-type:device_code", form!["grant_type"]);
        Assert.Equal(OidcTestKit.DeviceCode, form["device_code"]);
    }
}
