using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;12.4 rule 2 (contract 1.68; audit finding C5): an unknown <c>kid</c>
/// triggers at most ONE JWKS re-fetch per cooldown window, and an unbounded or non-positive
/// <c>JwksCacheTtl</c> cannot defeat the cache. Time is a mocked clock, never slept.
/// </summary>
[Trait("Category", "Fast")]
public sealed class JwksVerifierCooldownTests
{
    private const string Tenant = "acme";
    private static readonly string[] Roles = ["admin"];

    /// <summary>Counts JWKS fetches and serves whichever document the test last set.</summary>
    private sealed class CountingJwksHandler : HttpMessageHandler
    {
        private int _count;
        public string Document { get; set; }
        public int Count => Volatile.Read(ref _count);

        public CountingJwksHandler(string document) => Document = document;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _count);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(Document, Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class MockClock
    {
        public DateTimeOffset Now { get; private set; } = new(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);
        public void Advance(TimeSpan by) => Now += by;
    }

    private static (JwksVerifier Verifier, JwksFixture Fixture, CountingJwksHandler Handler, MockClock Clock) Create(TimeSpan ttl)
    {
        var fixture = new JwksFixture();
        var handler = new CountingJwksHandler(fixture.BuildJwksDocument());
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://axiam.test") };
        var clock = new MockClock();
        var verifier = new JwksVerifier(http, new Uri("https://axiam.test"), ttl) { CacheClock = () => clock.Now };
        return (verifier, fixture, handler, clock);
    }

    private static string Token(JwksFixture fixture, string? kid = null) =>
        fixture.SignJwt("user-1", Tenant, Roles, DateTimeOffset.UtcNow.AddMinutes(15), kidOverride: kid);

    [Fact]
    public async Task FiftyUnknownKidsInOneWindow_CauseAtMostOneFetch_AndAreAllRejected()
    {
        (JwksVerifier verifier, JwksFixture fixture, CountingJwksHandler handler, _) = Create(TimeSpan.FromMinutes(5));

        // Warm the cache with a token carrying the served kid.
        Assert.NotNull(await verifier.VerifyAsync(Token(fixture), Tenant));
        int afterWarm = handler.Count;

        for (int i = 0; i < 50; i++)
        {
            string forged = Token(fixture, kid: $"forged-kid-{i}");
            Assert.Null(await verifier.VerifyAsync(forged, Tenant));
        }

        Assert.True(handler.Count - afterWarm <= 1,
            $"50 unknown kids inside one window caused {handler.Count - afterWarm} JWKS fetches; at most 1 is allowed");
        // The warm kid still verifies without any further fetch.
        int before = handler.Count;
        Assert.NotNull(await verifier.VerifyAsync(Token(fixture), Tenant));
        Assert.Equal(before, handler.Count);
    }

    [Fact]
    public async Task ARotatedKid_IsAcceptedAfterTheWindow_WithOneFetch()
    {
        (JwksVerifier verifier, JwksFixture fixture, CountingJwksHandler handler, MockClock clock) = Create(TimeSpan.FromMinutes(5));
        Assert.NotNull(await verifier.VerifyAsync(Token(fixture), Tenant));

        // An unknown kid opens the window.
        Assert.Null(await verifier.VerifyAsync(Token(fixture, kid: "not-yet-published"), Tenant));

        // The server rotates; a token under the new key inside the window is rejected from the cache.
        var rotated = new JwksFixture();
        handler.Document = rotated.BuildJwksDocument();
        int inWindow = handler.Count;
        Assert.Null(await verifier.VerifyAsync(Token(rotated), Tenant));
        Assert.Equal(inWindow, handler.Count);

        // Past the window (and still inside the cache TTL) the new kid is fetched once and accepted.
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.NotNull(await verifier.VerifyAsync(Token(rotated), Tenant));
        Assert.Equal(inWindow + 1, handler.Count);
    }

    [Fact]
    public async Task ACacheTtlLongerThanFiveMinutes_IsClampedToFiveMinutes()
    {
        (JwksVerifier verifier, JwksFixture fixture, CountingJwksHandler handler, MockClock clock) = Create(TimeSpan.FromDays(30));
        Assert.NotNull(await verifier.VerifyAsync(Token(fixture), Tenant));
        int afterFill = handler.Count;

        clock.Advance(TimeSpan.FromMinutes(4));
        Assert.NotNull(await verifier.VerifyAsync(Token(fixture), Tenant));
        Assert.Equal(afterFill, handler.Count); // still cached

        clock.Advance(TimeSpan.FromMinutes(2)); // 6 minutes after the fill
        Assert.NotNull(await verifier.VerifyAsync(Token(fixture), Tenant));
        Assert.Equal(afterFill + 1, handler.Count);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public async Task ANonPositiveCacheTtl_FallsBackToTheDefault_NotToNoCaching(int seconds)
    {
        (JwksVerifier verifier, JwksFixture fixture, CountingJwksHandler handler, MockClock clock) = Create(TimeSpan.FromSeconds(seconds));
        Assert.NotNull(await verifier.VerifyAsync(Token(fixture), Tenant));
        int afterFill = handler.Count;

        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.NotNull(await verifier.VerifyAsync(Token(fixture), Tenant));
        Assert.Equal(afterFill, handler.Count);
    }
}
