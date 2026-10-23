using System.Net;
using System.Text;
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
        // The server's own body (contract 1.64 amended): no error_description.
        HttpResponseMessage response = OidcTestKit.JsonStatus((HttpStatusCode)429, """{"error":"rate_limit_exceeded"}""");
        if (retryAfterSeconds is { } seconds)
        {
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(seconds));
        }

        return response;
    }

    private static HttpResponseMessage SlowDown429(int retryAfterSeconds)
    {
        HttpResponseMessage response = OidcTestKit.JsonStatus((HttpStatusCode)429, """{"error":"slow_down"}""");
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(retryAfterSeconds));
        return response;
    }

    /// <summary>What AXIAM's token endpoint answers an internal failure (contract 1.64 amended, §14.2 rule 6).</summary>
    private static HttpResponseMessage ServerError500() =>
        OidcTestKit.JsonStatus(HttpStatusCode.InternalServerError, """{"error":"server_error","error_description":"db"}""");

    /// <summary>A response body whose first read takes 1.5 s of real time and honours the token, as a socket read does.</summary>
    private sealed class SlowBody(byte[] bytes, Action onDelivered) : Stream
    {
        private int _position;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_position >= bytes.Length)
            {
                return 0;
            }

            await Task.Delay(1500, cancellationToken).ConfigureAwait(false);
            int count = Math.Min(buffer.Length, bytes.Length - _position);
            bytes.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            onDelivered();
            return count;
        }

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static HttpResponseMessage Pending() =>
        OidcTestKit.JsonStatus(HttpStatusCode.BadRequest, OidcTestKit.OAuth2ErrorJson("authorization_pending", "pending"));

    private static HttpResponseMessage Tokens() =>
        OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("device-access-token"));

    /// <summary>A clock that only moves when a test or a recorded sleep moves it.</summary>
    private sealed class FakeTime : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 23, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    private static (AxiamClient Client, List<TimeSpan> Sleeps, Func<int> Polls) SetUp(
        int expiresIn, int interval, params Func<HttpResponseMessage>[] steps) =>
        SetUp(expiresIn, interval, TimeSpan.Zero, new List<DateTimeOffset>(), steps);

    private static (AxiamClient Client, List<TimeSpan> Sleeps, Func<int> Polls) SetUp(
        int expiresIn, int interval, TimeSpan requestTime, List<DateTimeOffset> pollStarts, params Func<HttpResponseMessage>[] steps) =>
        SetUp(expiresIn, interval, requestTime, pollStarts, retry: true, steps);

    private static (AxiamClient Client, List<TimeSpan> Sleeps, Func<int> Polls) SetUp(
        int expiresIn, int interval, TimeSpan requestTime, List<DateTimeOffset> pollStarts, bool retry, params Func<HttpResponseMessage>[] steps)
    {
        var time = new FakeTime();
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        handler.Map(DeviceAuthPath, _ => OidcTestKit.JsonOk(OidcTestKit.DeviceAuthorizationJson(expiresIn: expiresIn, interval: interval)));
        int index = 0;
        handler.Map(TokenPath, _ =>
        {
            pollStarts.Add(time.GetUtcNow());
            time.Advance(requestTime);
            return steps[Math.Min(index++, steps.Length - 1)]();
        });
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(clientSecret: null) with
        {
            RetryEnabled = retry,
            RetryBaseDelay = TimeSpan.FromMilliseconds(1),
            RetryMaxDelay = TimeSpan.FromMilliseconds(2),
        });
        var sleeps = new List<TimeSpan>();
        client.DevicePollTime = time;
        client.DevicePollDelay = (delay, _) =>
        {
            sleeps.Add(delay);
            time.Advance(delay);
            return Task.CompletedTask;
        };
        return (client, sleeps, () => index);
    }

    /// <summary>The loop's own waits: the in-poll &#167;16 backoff (a few ms) is recorded by the same sleeper and left out.</summary>
    private static double[] Intervals(List<TimeSpan> sleeps) =>
        sleeps.Where(s => s >= TimeSpan.FromSeconds(1)).Select(s => s.TotalSeconds).ToArray();

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

        // WaitAsync: a wait served on the real clock instead of refused would block for 120 s; fail fast instead.
        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.DeviceLoginAsync(Login()).WaitAsync(TimeSpan.FromSeconds(10)));

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

    /// <summary>
    /// A third case (contract 1.64 amended, &#167;14.6): a <c>429</c> whose body says <c>slow_down</c>, then <c>200</c>,
    /// does not raise the interval (C164-04). Only the <c>400</c> does.
    /// </summary>
    [Fact]
    public async Task A429WhoseBodySaysSlowDownIsTheWaitAndDoesNotRaiseTheInterval()
    {
        (AxiamClient client, List<TimeSpan> sleeps, _) = SetUp(expiresIn: 600, interval: 5, () => SlowDown429(1), Pending, Tokens);

        await client.DeviceLoginAsync(Login());

        Assert.Equal(new[] { 5.0, 5.0, 5.0 }, sleeps.Select(s => s.TotalSeconds).ToArray());
    }

    /// <summary>The control for the case above: the same body as a <c>400</c> raises the interval for good.</summary>
    [Fact]
    public async Task ASlowDownOnA400StillRaisesTheInterval()
    {
        (AxiamClient client, List<TimeSpan> sleeps, _) = SetUp(
            expiresIn: 600, interval: 5,
            () => OidcTestKit.JsonStatus(HttpStatusCode.BadRequest, OidcTestKit.OAuth2ErrorJson("slow_down", "slower")),
            Pending, Tokens);

        await client.DeviceLoginAsync(Login());

        Assert.Equal(new[] { 5.0, 10.0, 10.0 }, sleeps.Select(s => s.TotalSeconds).ToArray());
    }

    /// <summary>
    /// &#167;14.2 rule 6 (contract 1.64 amended; C164-03): a <c>5xx</c> is a transport failure whatever its body. The
    /// mock answers the body the server sends, <c>500 {"error":"server_error",&#8230;}</c>, mid-poll, then the tokens.
    /// With retry on (the default) each poll retries inside the attempt, so the loop takes no extra interval.
    /// </summary>
    [Fact]
    public async Task A500WithTheServersOwnOAuthBodyIsNotTerminal()
    {
        (AxiamClient client, List<TimeSpan> sleeps, Func<int> polls) = SetUp(
            expiresIn: 600, interval: 5, Pending, ServerError500, ServerError500, Tokens);

        OidcTokenSet set = await client.DeviceLoginAsync(Login());

        Assert.Equal("device-access-token", set.AccessToken.Reveal());
        Assert.Equal(4, polls());
        Assert.Equal(new[] { 5.0, 5.0 }, Intervals(sleeps));
    }

    /// <summary>The same with retry disabled: one request per poll, so the loop takes an interval per failure (still not terminal).</summary>
    [Fact]
    public async Task WithRetryDisabledA500CostsOneRequestPerPollAndAnInterval()
    {
        (AxiamClient client, List<TimeSpan> sleeps, Func<int> polls) = SetUp(
            expiresIn: 600, interval: 5, TimeSpan.Zero, new List<DateTimeOffset>(), retry: false,
            Pending, ServerError500, ServerError500, Tokens);

        await client.DeviceLoginAsync(Login());

        Assert.Equal(4, polls());
        Assert.Equal(new[] { 5.0, 5.0, 5.0, 5.0 }, sleeps.Select(s => s.TotalSeconds).ToArray());
    }

    /// <summary>
    /// &#167;14.6 (contract 1.64 amended, C164-35): two <c>500</c>s then <c>200</c> - a single poll makes three requests
    /// and returns the tokens, and <c>DeviceLoginAsync</c> completes within one interval with those three requests.
    /// </summary>
    [Fact]
    public async Task APollRetriesA5xxInsideTheAttemptUnderSection16()
    {
        (AxiamClient single, _, Func<int> singlePolls) = SetUp(expiresIn: 600, interval: 5, ServerError500, ServerError500, Tokens);
        OidcTokenSet set = await single.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode)));
        Assert.Equal("device-access-token", set.AccessToken.Reveal());
        Assert.Equal(3, singlePolls());

        (AxiamClient client, List<TimeSpan> sleeps, Func<int> polls) = SetUp(expiresIn: 600, interval: 5, ServerError500, ServerError500, Tokens);
        await client.DeviceLoginAsync(Login());
        Assert.Equal(3, polls());
        Assert.Equal(new[] { 5.0 }, Intervals(sleeps));
    }

    /// <summary>A third <c>500</c> in a row exhausts the cap: three requests, then <c>DevicePollAsync</c> surfaces the failure.</summary>
    [Fact]
    public async Task AThirdConsecutive5xxExhaustsTheCapAndIsSurfaced()
    {
        (AxiamClient client, _, Func<int> polls) = SetUp(expiresIn: 600, interval: 5, ServerError500);

        NetworkError error = await Assert.ThrowsAsync<NetworkError>(
            () => client.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode))));

        Assert.Equal(500, error.HttpStatus);
        Assert.Equal(3, polls());
    }

    /// <summary>A transport failure is retried inside the poll as well.</summary>
    [Fact]
    public async Task ATransportFailureIsRetriedInsideThePoll()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        int attempts = 0;
        handler.Map(TokenPath, _ => ++attempts < 3 ? throw new HttpRequestException("connection reset") : Tokens());
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(clientSecret: null) with
        {
            RetryBaseDelay = TimeSpan.FromMilliseconds(1),
            RetryMaxDelay = TimeSpan.FromMilliseconds(2),
        });

        await client.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode)));

        Assert.Equal(3, attempts);
    }

    /// <summary>A <c>429</c> is not retried inside the poll: one request, the wait being the loop's.</summary>
    [Fact]
    public async Task A429IsNeverRetriedInsideThePoll()
    {
        (AxiamClient client, _, Func<int> polls) = SetUp(expiresIn: 600, interval: 5, () => RateLimited(1), Tokens);

        await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode))));

        Assert.Equal(1, polls());

        // A bodiless 429 as well.
        (AxiamClient bodiless, _, Func<int> bodilessPolls) = SetUp(
            expiresIn: 600, interval: 5, () => OidcTestKit.Empty((HttpStatusCode)429), Tokens);
        await Assert.ThrowsAsync<NetworkError>(
            () => bodiless.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode))));
        Assert.Equal(1, bodilessPolls());
    }

    /// <summary>A single poll on that <c>500</c> is the &#167;2 <c>NetworkError</c>, not an <c>OAuthProtocolError</c>.</summary>
    [Fact]
    public async Task ASinglePollOnA500WithAnOAuthBodyIsANetworkError()
    {
        (AxiamClient client, _, _) = SetUp(expiresIn: 600, interval: 5, ServerError500);

        NetworkError error = await Assert.ThrowsAsync<NetworkError>(
            () => client.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode))));

        Assert.Equal(500, error.HttpStatus);
    }

    /// <summary>
    /// &#167;14.2 rule 4 and &#167;14.6 case 2 (C164-05): the deadline is measured on the clock, so the time a request takes
    /// counts. With a 10 s request, <c>expires_in</c> 30 and interval 5, no poll starts at or after the deadline.
    /// </summary>
    [Fact]
    public async Task NoPollIsSentAtOrAfterTheDeadlineWhenRequestsTakeTime()
    {
        var pollStarts = new List<DateTimeOffset>();
        (AxiamClient client, _, Func<int> polls) = SetUp(
            expiresIn: 30, interval: 5, TimeSpan.FromSeconds(10), pollStarts, Pending);
        DateTimeOffset start = client.DevicePollTime.GetUtcNow();

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(() => client.DeviceLoginAsync(Login()));

        Assert.True(error.IsExpiredToken);
        Assert.Equal(2, polls());
        Assert.All(pollStarts, t => Assert.True(t - start < TimeSpan.FromSeconds(30)));
    }

    /// <summary>
    /// A client whose deadline runs on a fake clock but whose server answers in real time: with <c>expires_in</c> 6 and
    /// interval 5, one second is left when the poll is sent. <paramref name="token"/> and <paramref name="jwks"/> answer after
    /// the real delays they name, and move the fake clock past the deadline.
    /// </summary>
    private static (AxiamClient Client, FakeTime Time) SetUpSlowServer(
        Func<HttpResponseMessage> token, Func<HttpResponseMessage>? jwks = null)
    {
        var time = new FakeTime();
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        handler.Map(DeviceAuthPath, _ => OidcTestKit.JsonOk(OidcTestKit.DeviceAuthorizationJson(expiresIn: 6, interval: 5)));
        handler.Map(TokenPath, _ => token());
        if (jwks is not null)
        {
            handler.Map("/oauth2/jwks", _ => jwks());
        }

        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(clientSecret: null));
        client.DevicePollTime = time;
        client.DevicePollDelay = (delay, _) =>
        {
            time.Advance(delay);
            return Task.CompletedTask;
        };
        return (client, time);
    }

    /// <summary>
    /// C164-40 / C164-46: the deadline governs the waits and the decision to send, not a request already sent. The poll is
    /// sent with one second left, and the <c>200</c> arrives 1.5 s of <b>real</b> time later, after the deadline. The tokens are
    /// returned. (A deadline token armed on the real clock cancels the read at 1 s and fails this test.)
    /// </summary>
    [Fact]
    public async Task A200ThatArrivesAfterTheDeadlineStillReturnsTheTokens()
    {
        FakeTime? clock = null;
        (AxiamClient client, FakeTime time) = SetUpSlowServer(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            // Headers at once; the body takes 1.5 s of real time, and the fake clock passes the deadline with it.
            Content = new StreamContent(new SlowBody(Encoding.UTF8.GetBytes(Tokens().Content.ReadAsStringAsync().Result), () => clock!.Advance(TimeSpan.FromSeconds(2))))
            {
                Headers = { ContentType = new MediaTypeHeaderValue("application/json") },
            },
        });
        clock = time;
        DateTimeOffset start = time.GetUtcNow();

        OidcTokenSet set = await client.DeviceLoginAsync(Login());

        Assert.Equal("device-access-token", set.AccessToken.Reveal());
        Assert.True(time.GetUtcNow() - start > TimeSpan.FromSeconds(6));
    }

    /// <summary>
    /// C164-46, the variant with an <c>id_token</c>: the <c>200</c> is on time, but the JWKS fetch that verifies its
    /// <c>id_token</c> answers 1.5 s of real time later, after the deadline. The token set, <c>id_token</c> verified, is returned.
    /// </summary>
    [Fact]
    public async Task AnIdTokenWhoseJwksArrivesAfterTheDeadlineIsStillVerifiedAndReturned()
    {
        var jwks = new JwksFixture();
        string origin = OidcTestKit.BaseUrl.ToString().TrimEnd('/');
        string idToken = jwks.SignIdToken(new
        {
            iss = origin,
            sub = Guid.NewGuid().ToString(),
            aud = OidcTestKit.ClientId,
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        });
        (AxiamClient client, _) = SetUpSlowServer(
            () => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("device-access-token", idToken: idToken)),
            () =>
            {
                Thread.Sleep(1500);
                return OidcTestKit.JsonOk(jwks.BuildJwksDocument());
            });

        OidcTokenSet set = await client.DeviceLoginAsync(Login());

        Assert.Equal("device-access-token", set.AccessToken.Reveal());
        Assert.NotNull(set.IdToken);
    }

    /// <summary>
    /// The verifier rethrows a caller's own cancellation instead of reporting a bad signature (C164-40, C164-46): a JWKS
    /// fetch the caller cancels is an <see cref="OperationCanceledException"/>, not an <see cref="AuthError"/>.
    /// </summary>
    [Fact]
    public async Task ACallersCancellationDuringIdTokenVerificationIsNotAnInvalidSignature()
    {
        var jwks = new JwksFixture();
        string idToken = jwks.SignIdToken(new
        {
            iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'),
            sub = Guid.NewGuid().ToString(),
            aud = OidcTestKit.ClientId,
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        });
        using var cts = new CancellationTokenSource();
        (AxiamClient client, _) = SetUpSlowServer(
            () => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("device-access-token", idToken: idToken)),
            () =>
            {
                cts.Cancel();
                Thread.Sleep(200);
                return OidcTestKit.JsonOk(jwks.BuildJwksDocument());
            });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode)), cts.Token));
    }

    /// <summary>
    /// C164-36/41 (the P10 analogue): a <c>503</c> with <c>Retry-After: 120</c> and <c>expires_in</c> 30. The in-poll &#167;16 wait
    /// that would pass the deadline is not served: <c>expired_token</c>, one request, nothing at or after t=30.
    /// </summary>
    [Fact]
    public async Task ARetryAfterPastTheDeadlineInsideThePollIsNotServed()
    {
        var pollStarts = new List<DateTimeOffset>();
        (AxiamClient client, List<TimeSpan> sleeps, Func<int> polls) = SetUp(
            expiresIn: 30, interval: 5, TimeSpan.Zero, pollStarts, () =>
            {
                HttpResponseMessage response = OidcTestKit.JsonStatus(
                    HttpStatusCode.ServiceUnavailable, """{"error":"temporarily_unavailable"}""");
                response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(120));
                return response;
            });
        DateTimeOffset start = client.DevicePollTime.GetUtcNow();

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(() => client.DeviceLoginAsync(Login()));

        Assert.True(error.IsExpiredToken);
        Assert.Equal(1, polls());
        Assert.Equal(new[] { 5.0 }, sleeps.Select(s => s.TotalSeconds).ToArray());
        Assert.All(pollStarts, t => Assert.True(t - start < TimeSpan.FromSeconds(30)));
    }

    /// <summary>
    /// C164-41: the <c>200</c> is parsed outside the retry. A body that does not parse is one request, not three: the device
    /// code is already redeemed, and a re-send could only be refused.
    /// </summary>
    [Fact]
    public async Task A200ThatDoesNotParseIsOneRequestNotARetry()
    {
        (AxiamClient client, _, Func<int> polls) = SetUp(
            expiresIn: 600, interval: 5, () => OidcTestKit.JsonOk("{not json"));

        await Assert.ThrowsAsync<NetworkError>(
            () => client.DevicePollAsync(new DevicePollParams(Sensitive<string>.Wrap(OidcTestKit.DeviceCode))));

        Assert.Equal(1, polls());
    }
}
