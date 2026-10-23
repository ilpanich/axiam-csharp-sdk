using System.Net;
using System.Net.Http.Headers;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Contract 1.64, CONTRACT.md &#167;14.2 rule 9 (last paragraph) and &#167;14.6, against a mocked server: a
/// <c>429 rate_limit_exceeded</c> on a device poll is waited out, not terminal. The sleeps are recorded, not served.
/// </summary>
[Trait("Category", "Fast")]
public class Contract164DevicePollRateLimitTests
{
    private const string DeviceAuthPath = "/oauth2/device_authorization";
    private const string TokenPath = "/oauth2/token";

    private static HttpResponseMessage RateLimited(int? retryAfterSeconds)
    {
        HttpResponseMessage response = OidcTestKit.JsonStatus(
            (HttpStatusCode)429, OidcTestKit.OAuth2ErrorJson("rate_limit_exceeded", "too many requests"));
        if (retryAfterSeconds is { } seconds)
        {
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(seconds));
        }

        return response;
    }

    private static HttpResponseMessage Pending() =>
        OidcTestKit.JsonStatus(HttpStatusCode.BadRequest, OidcTestKit.OAuth2ErrorJson("authorization_pending", "pending"));

    private static HttpResponseMessage Tokens() =>
        OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("device-access-token"));

    private static (AxiamClient Client, List<TimeSpan> Sleeps, Func<int> Polls) SetUp(
        int expiresIn, int interval, params Func<HttpResponseMessage>[] steps)
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        handler.Map(DeviceAuthPath, _ => OidcTestKit.JsonOk(OidcTestKit.DeviceAuthorizationJson(expiresIn: expiresIn, interval: interval)));
        int index = 0;
        handler.Map(TokenPath, _ => steps[Math.Min(index++, steps.Length - 1)]());
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(clientSecret: null));
        var sleeps = new List<TimeSpan>();
        client.DevicePollDelay = (delay, _) =>
        {
            sleeps.Add(delay);
            return Task.CompletedTask;
        };
        return (client, sleeps, () => index);
    }

    private static DeviceLoginParams Login() => new(OnUserCode: _ => Task.CompletedTask);

    /// <summary>
    /// The &#167;14.6 test as the contract words it: one poll answered <c>429</c> with <c>Retry-After</c>; the loop waits
    /// at least that long, polls again and completes; the interval is unchanged (the poll after it is scheduled at the
    /// interval held before, not five seconds longer).
    /// </summary>
    [Fact]
    public async Task A429WithRetryAfterIsWaitedOutAndTheIntervalIsUnchanged()
    {
        (AxiamClient client, List<TimeSpan> sleeps, Func<int> polls) = SetUp(
            expiresIn: 600, interval: 5, Pending, () => RateLimited(20), Pending, Tokens);

        OidcTokenSet set = await client.DeviceLoginAsync(Login());

        Assert.Equal("device-access-token", set.AccessToken.Reveal());
        Assert.Equal(4, polls());
        // 5 s (first poll), 5 s (after pending), 20 s (the 429's Retry-After, one interval), 5 s (the interval, unchanged).
        Assert.Equal(new[] { 5.0, 5.0, 20.0, 5.0 }, sleeps.Select(s => s.TotalSeconds).ToArray());
    }

    /// <summary>A <c>Retry-After</c> shorter than the interval is a minimum, not a shortcut: the interval is still served.</summary>
    [Fact]
    public async Task ARetryAfterBelowTheIntervalDoesNotShortenTheWait()
    {
        (AxiamClient client, List<TimeSpan> sleeps, _) = SetUp(expiresIn: 600, interval: 5, () => RateLimited(1), Tokens);

        await client.DeviceLoginAsync(Login());

        Assert.Equal(new[] { 5.0, 5.0 }, sleeps.Select(s => s.TotalSeconds).ToArray());
    }

    /// <summary>A <c>429</c> without <c>Retry-After</c> is still not terminal and still counts as one interval.</summary>
    [Fact]
    public async Task A429WithoutRetryAfterIsNotTerminal()
    {
        (AxiamClient client, List<TimeSpan> sleeps, _) = SetUp(expiresIn: 600, interval: 5, () => RateLimited(null), Tokens);

        await client.DeviceLoginAsync(Login());

        Assert.Equal(new[] { 5.0, 5.0 }, sleeps.Select(s => s.TotalSeconds).ToArray());
    }

    /// <summary>
    /// A <c>Retry-After</c> past the <c>expires_in</c> deadline is capped by it: the loop raises the typed
    /// <c>expired_token</c> of rule 4 and sends nothing after the deadline.
    /// </summary>
    [Fact]
    public async Task ARetryAfterPastTheDeadlineEndsInExpiredTokenAndSendsNothingMore()
    {
        (AxiamClient client, List<TimeSpan> sleeps, Func<int> polls) = SetUp(
            expiresIn: 30, interval: 5, () => RateLimited(120), Tokens);

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(() => client.DeviceLoginAsync(Login()));

        Assert.True(error.IsExpiredToken);
        Assert.Equal(1, polls());
        Assert.Equal(new[] { 5.0 }, sleeps.Select(s => s.TotalSeconds).ToArray());
    }

    /// <summary>The single <c>DevicePollAsync</c> call still raises the &#167;2 <c>OAuthProtocolError</c> of rule 9's first paragraph.</summary>
    [Fact]
    public async Task ASinglePollRaisesRateLimitExceeded()
    {
        (AxiamClient client, _, _) = SetUp(expiresIn: 600, interval: 5, () => RateLimited(3));

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode))));

        Assert.Equal("rate_limit_exceeded", error.Error);
    }
}
