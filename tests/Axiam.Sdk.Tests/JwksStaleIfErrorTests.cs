using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;12.4 rule 2, "Stale-if-error, bounded" (contract 1.69, D-10): the cache's age runs from the
/// last SUCCESSFUL fetch; a failed refresh keeps the held keys until TTL + 300 s after that anchor and then every
/// token is refused until a fetch succeeds. Time is an injected clock, never slept.
/// </summary>
[Trait("Category", "Fast")]
public sealed class JwksStaleIfErrorTests
{
    private const string Tenant = "acme";
    private static readonly string[] Roles = ["admin"];
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(300);

    private sealed class Server : HttpMessageHandler
    {
        private int _count;
        public int Count => Volatile.Read(ref _count);
        public Func<HttpRequestMessage, HttpResponseMessage> Respond { get; set; }
        public List<string?> IfNoneMatch { get; } = new();

        /// <summary>When set, a request waits (asynchronously) for it before being answered: a hanging endpoint.</summary>
        public Task? Gate { get; set; }

        public Server(Func<HttpRequestMessage, HttpResponseMessage> respond) => Respond = respond;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _count);
            IfNoneMatch.Add(request.Headers.IfNoneMatch.ToString());
            if (Gate is { } gate)
            {
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            return Respond(request);
        }
    }

    private sealed class Clock
    {
        public DateTimeOffset Now { get; private set; } = new(2026, 11, 27, 12, 0, 0, TimeSpan.Zero);
        public void Advance(TimeSpan by) => Now += by;
    }

    private static HttpResponseMessage Ok(string document, string? etag = null, string? cacheControl = null)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(document, Encoding.UTF8, "application/json"),
        };
        if (etag is not null)
        {
            response.Headers.ETag = new EntityTagHeaderValue(etag);
        }
        if (cacheControl is not null)
        {
            response.Headers.CacheControl = CacheControlHeaderValue.Parse(cacheControl);
        }
        return response;
    }

    private static (JwksVerifier Verifier, JwksFixture Fixture, Server Server, Clock Clock) Create(TimeSpan? ttl = null, string? cacheControl = null)
    {
        var fixture = new JwksFixture();
        string document = fixture.BuildJwksDocument();
        var server = new Server(_ => Ok(document, "\"v1\"", cacheControl));
        var http = new HttpClient(server) { BaseAddress = new Uri("https://axiam.test") };
        var clock = new Clock();
        var verifier = new JwksVerifier(http, new Uri("https://axiam.test"), ttl ?? Ttl) { CacheClock = () => clock.Now };
        return (verifier, fixture, server, clock);
    }

    private static string Token(JwksFixture fixture, string? kid = null) =>
        fixture.SignJwt("user-1", Tenant, Roles, DateTimeOffset.UtcNow.AddMinutes(15), kidOverride: kid);

    private static async Task<bool> Accepts(JwksVerifier verifier, JwksFixture fixture, string? kid = null)
    {
        bool ok = await verifier.VerifyAsync(Token(fixture, kid), Tenant) is not null;
        await verifier.IdleAsync(); // a usable held key answers without waiting; let its background refresh land
        return ok;
    }

    // The conformance test of §12.4 rule 2, in the contract's order.
    [Fact]
    public async Task ConformanceTest_HeldKeysRideOutAFailingEndpointForExactlyTtlPlus300Seconds()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture)); // the successful fetch: the anchor

        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);

        clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        Assert.True(await Accepts(verifier, fixture), "held kid accepted at TTL+1 s while the refresh fails");

        // The empty set is a failed refresh, not a replacement.
        server.Respond = _ => Ok("""{"keys":[]}""");
        clock.Advance(TimeSpan.FromSeconds(61)); // past the failed-attempt window
        Assert.True(await Accepts(verifier, fixture), "an empty key set must leave the held kid accepted");

        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        clock.Advance(TimeSpan.FromSeconds(188)); // TTL + 250 s after the anchor
        Assert.False(await Accepts(verifier, fixture, "unknown-kid"), "an unknown kid is refused");
        Assert.True(await Accepts(verifier, fixture), "...while the held kid is still accepted at TTL+250 s");

        clock.Advance(TimeSpan.FromSeconds(51)); // TTL + 301 s
        Assert.False(await Accepts(verifier, fixture), "held kid refused at TTL+301 s");

        // One successful fetch and it is accepted again.
        server.Respond = _ => Ok(fixture.BuildJwksDocument(), "\"v2\"");
        clock.Advance(TimeSpan.FromSeconds(61));
        int fetchesBefore = server.Count;
        Assert.True(await Accepts(verifier, fixture), "accepted again after one successful fetch");
        Assert.Equal(fetchesBefore + 1, server.Count);
    }

    [Fact]
    public async Task AHeldKid_IsStillAcceptedAtExactlyTtlPlus300Seconds_AndRefusedOneSecondLater()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));
        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.InternalServerError);

        clock.Advance(Ttl + TimeSpan.FromSeconds(300));
        Assert.True(await Accepts(verifier, fixture));
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.False(await Accepts(verifier, fixture));
    }

    [Fact]
    public async Task ATransportError_AndANonJwksBody_AreFailedRefreshes_TheHeldKeysSurvive()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));

        server.Respond = _ => throw new HttpRequestException("connection refused");
        clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        Assert.True(await Accepts(verifier, fixture));

        server.Respond = _ => Ok("<html>not a jwks</html>");
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.True(await Accepts(verifier, fixture));
    }

    [Theory]
    [InlineData("""{"keys":[]}""")]
    [InlineData("""{"keys":[{}]}""")]
    [InlineData("""{"keys":[0]}""")]
    [InlineData("""{"keys":[null]}""")]
    [InlineData("[0]")]
    public async Task ADocumentWithNoJwk_IsAFailedRefresh_TheHeldKeysSurvive(string body)
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));
        server.Respond = _ => Ok(body);
        clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        Assert.True(await Accepts(verifier, fixture));
        clock.Advance(TimeSpan.FromSeconds(300)); // past TTL + 300 s: the anchor never moved
        Assert.False(await Accepts(verifier, fixture));
    }

    [Fact]
    public async Task AColdCacheWithAFailingEndpoint_CostsOneFetchPerWindow_NotOnePerToken()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, _) = Create();
        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        for (int i = 0; i < 20; i++)
        {
            Assert.False(await Accepts(verifier, fixture));
        }
        Assert.Equal(1, server.Count);
    }

    [Fact]
    public async Task AnEtagWithControlCharactersOrOver256Bytes_IsNotEchoed()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        string doc = fixture.BuildJwksDocument();
        server.Respond = _ => Ok(doc, "\"" + new string('a', 300) + "\"");
        Assert.True(await Accepts(verifier, fixture));
        clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        Assert.True(await Accepts(verifier, fixture));
        Assert.Equal(string.Empty, server.IfNoneMatch[^1]);
    }

    [Fact]
    public async Task AClockMovingBackwards_MeansRefreshDue_NeverFresh()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));
        int before = server.Count;
        clock.Advance(TimeSpan.FromHours(-1));
        Assert.True(await Accepts(verifier, fixture));
        Assert.Equal(before + 1, server.Count);
    }

    [Fact]
    public async Task AnUnusableButWellFormedJwk_IsSkipped_TheRestOfTheSetIsAdopted()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));
        string good = fixture.BuildJwksDocument();
        string withRsa = good.Replace("{\"keys\":[", "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"},{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"bad\",\"x\":\"!!\"},");
        server.Respond = _ => Ok(withRsa);
        clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        Assert.True(await Accepts(verifier, fixture));
        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        clock.Advance(Ttl - TimeSpan.FromSeconds(1) + TimeSpan.FromSeconds(250)); // beyond the OLD anchor's bound: the set was adopted
        Assert.True(await Accepts(verifier, fixture));
    }

    [Fact]
    public async Task AJwksOfValidKeysNoneOfThemEdDSA_IsASuccessPerTheContract_AndVerifiesNothing()
    {
        // Pins the contract's wording: a document holding a valid JWK is a success; it is adopted.
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));
        server.Respond = _ => Ok("""{"keys":[{"kty":"RSA","kid":"r","n":"AQAB","e":"AQAB"}]}""");
        clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        await verifier.VerifyAsync(Token(fixture), Tenant); // starts the refresh (the held key may answer first)
        await verifier.IdleAsync();
        Assert.False(await Accepts(verifier, fixture)); // the adopted RSA-only set verifies nothing
    }

    [Fact]
    public async Task AFailedRefresh_CountsTowardTheWindow_ACooldownBoundsTheFetches()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));
        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        int before = server.Count;

        for (int i = 0; i < 20; i++)
        {
            Assert.True(await Accepts(verifier, fixture));
        }

        Assert.Equal(before + 1, server.Count);
    }

    [Fact]
    public async Task AnUnknownKidRefresh_ThatFails_NeverOpensOrExtendsTheStaleWindow()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));
        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);

        clock.Advance(Ttl - TimeSpan.FromSeconds(10)); // inside the TTL
        Assert.False(await Accepts(verifier, fixture, "unknown-kid"));
        Assert.True(await Accepts(verifier, fixture), "the held set stays in place");

        clock.Advance(TimeSpan.FromSeconds(10 + 301)); // TTL + 301 s after the ORIGINAL anchor
        Assert.False(await Accepts(verifier, fixture), "the failed unknown-kid attempt did not move the anchor");
    }

    [Fact]
    public async Task ANotModified_ToAConditionalRequest_IsASuccess_AndMovesTheAnchor()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));

        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.NotModified);
        clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        Assert.True(await Accepts(verifier, fixture));
        Assert.Equal("\"v1\"", server.IfNoneMatch[^1]);

        // The 304 moved the anchor to now: TTL + 250 s after the ORIGINAL fetch is still inside the new TTL.
        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        clock.Advance(Ttl + TimeSpan.FromSeconds(250));
        Assert.True(await Accepts(verifier, fixture));
        clock.Advance(TimeSpan.FromSeconds(51 + 1));
        Assert.False(await Accepts(verifier, fixture));
    }

    [Fact]
    public async Task ATtlLongerThanFiveMinutes_IsClampedToFiveMinutes()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create(TimeSpan.FromDays(30));
        Assert.True(await Accepts(verifier, fixture));
        int afterFill = server.Count;

        clock.Advance(TimeSpan.FromSeconds(299));
        Assert.True(await Accepts(verifier, fixture));
        Assert.Equal(afterFill, server.Count);

        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.True(await Accepts(verifier, fixture));
        Assert.Equal(afterFill + 1, server.Count);
    }

    [Fact]
    public async Task AnAdvertisedMaxAge_IsUsedOnlyWhenNothingIsConfigured_ClampedTo300s()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create(TimeSpan.Zero, cacheControl: "max-age=86400");
        Assert.True(await Accepts(verifier, fixture));
        int afterFill = server.Count;
        clock.Advance(TimeSpan.FromSeconds(301));
        Assert.True(await Accepts(verifier, fixture));
        Assert.Equal(afterFill + 1, server.Count);

        (verifier, fixture, server, clock) = Create(TimeSpan.Zero, cacheControl: "max-age=90");
        Assert.True(await Accepts(verifier, fixture));
        afterFill = server.Count;
        clock.Advance(TimeSpan.FromSeconds(91));
        Assert.True(await Accepts(verifier, fixture));
        Assert.Equal(afterFill + 1, server.Count);

        // A configured TTL wins over the advertised max-age.
        (verifier, fixture, server, clock) = Create(TimeSpan.FromSeconds(300), cacheControl: "max-age=90");
        Assert.True(await Accepts(verifier, fixture));
        afterFill = server.Count;
        clock.Advance(TimeSpan.FromSeconds(91));
        Assert.True(await Accepts(verifier, fixture));
        Assert.Equal(afterFill, server.Count);
    }

    [Fact]
    public async Task A203WithAJwksBody_IsAFailedRefresh_TheHeldSetIsKept_AndTheAnchorUnmoved()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));
        string doc = fixture.BuildJwksDocument();
        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.NonAuthoritativeInformation)
        {
            Content = new StringContent(doc, Encoding.UTF8, "application/json"),
        };
        clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        Assert.True(await Accepts(verifier, fixture));
        clock.Advance(TimeSpan.FromSeconds(300)); // TTL + 301 s after the original anchor
        Assert.False(await Accepts(verifier, fixture), "a 203 did not move the anchor");
    }

    [Fact]
    public async Task ANotModified_RereadsTheMaxAgeItCarries_WhenNoTtlIsConfigured()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create(TimeSpan.Zero, cacheControl: "max-age=300");
        Assert.True(await Accepts(verifier, fixture));
        server.Respond = _ =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.NotModified);
            r.Headers.CacheControl = CacheControlHeaderValue.Parse("max-age=90");
            return r;
        };
        clock.Advance(TimeSpan.FromSeconds(301));
        Assert.True(await Accepts(verifier, fixture)); // the 304 moved the anchor and set TTL 90 s
        int count = server.Count;
        clock.Advance(TimeSpan.FromSeconds(89));
        Assert.True(await Accepts(verifier, fixture));
        Assert.Equal(count, server.Count);
        clock.Advance(TimeSpan.FromSeconds(2)); // past the 90 s the 304 carried
        Assert.True(await Accepts(verifier, fixture));
        Assert.Equal(count + 1, server.Count);
    }

    [Fact]
    public async Task AHeldKeyWithAHangingRefresh_IsNotKeptWaiting()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));
        var release = new TaskCompletionSource();
        server.Gate = release.Task;
        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        // The first verification starts the hanging fetch; others while it is in flight must not queue behind it.
        Task<System.Text.Json.JsonElement?> first = verifier.VerifyAsync(Token(fixture), Tenant);
        Assert.Same(first, await Task.WhenAny(first, Task.Delay(TimeSpan.FromSeconds(5))));
        for (int i = 0; i < 3; i++)
        {
            Task<System.Text.Json.JsonElement?> next = verifier.VerifyAsync(Token(fixture), Tenant);
            Assert.Same(next, await Task.WhenAny(next, Task.Delay(TimeSpan.FromSeconds(5))));
            Assert.NotNull(await next);
        }
        release.SetResult();
        await verifier.IdleAsync();
    }

    [Fact]
    public async Task ACancelledCaller_NeverOpensTheUnknownKidWindow_TheNextNewKidTokenFetches()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));
        var rotated = new JwksFixture();
        var release = new TaskCompletionSource();
        string rotatedDoc = rotated.BuildJwksDocument();
        server.Gate = release.Task;
        server.Respond = _ => Ok(rotatedDoc);

        using var cts = new CancellationTokenSource();
        Task<System.Text.Json.JsonElement?> cancelled = verifier.VerifyAsync(Token(rotated), Tenant, cts.Token);
        await Task.Delay(100);
        cts.Cancel(); // the client went away while the fetch was in flight
        Assert.Null(await Record.ExceptionAsync(async () => { try { await cancelled; } catch (OperationCanceledException) { } }));
        release.SetResult();
        await verifier.IdleAsync();

        // The fetch ran to its own end and succeeded: the new kid is now known, no window refused it.
        Assert.True(await Accepts(verifier, rotated));
    }

    [Fact]
    public async Task ANegativeAge_WithAFailingRefresh_RefusesTheHeldKey()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));
        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        clock.Advance(TimeSpan.FromHours(-1));
        Assert.False(await Accepts(verifier, fixture));
    }

    [Fact]
    public async Task AWindowStartedMoreThanAWindowInTheFuture_MeansTheClockSteppedBack_AndTheWindowIsOver()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create();
        Assert.True(await Accepts(verifier, fixture));
        server.Respond = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        clock.Advance(Ttl + TimeSpan.FromSeconds(1));
        Assert.True(await Accepts(verifier, fixture)); // a failed refresh opens the window at T
        int count = server.Count;

        clock.Advance(TimeSpan.FromMinutes(-10)); // the window start is now ten minutes in the future
        await verifier.VerifyAsync(Token(fixture, "unknown-kid"), Tenant);
        await verifier.IdleAsync();
        Assert.Equal(count + 1, server.Count);
    }

    [Fact]
    public async Task ATinyAdvertisedMaxAge_NeverMeansOneFetchPerVerification()
    {
        (JwksVerifier verifier, JwksFixture fixture, Server server, Clock clock) = Create(TimeSpan.Zero, cacheControl: "max-age=1");
        Assert.True(await Accepts(verifier, fixture));
        int count = server.Count;
        for (int i = 0; i < 20; i++)
        {
            clock.Advance(TimeSpan.FromSeconds(2));
            Assert.True(await Accepts(verifier, fixture));
        }
        Assert.True(server.Count - count <= 1, $"{server.Count - count} fetches in 40 s with a 60 s window");
    }

    // ---- config_clamped at construction (§19 rule 6) ----

    private static AxiamClient NewClient(TimeSpan ttl, List<TelemetryEvent> events) =>
        AxiamClient.CreateForTesting(
            new Uri("https://axiam.test"), "acme",
            new AxiamClientOptions { BaseUrl = new Uri("https://axiam.test"), TenantId = "acme", JwksCacheTtl = ttl, TelemetryHook = events.Add },
            new Server(_ => Ok("""{"keys":[]}""")));

    [Fact]
    public void AClampedConfiguredJwksCacheTtl_EmitsOneConfigClampedEvent()
    {
        var events = new List<TelemetryEvent>();
        using AxiamClient client = NewClient(TimeSpan.FromMinutes(10), events);

        ConfigClampedEvent clamp = Assert.Single(events.OfType<ConfigClampedEvent>(), e => e.Setting == "JwksCacheTtl");
        Assert.Equal(TimeSpan.FromMinutes(10).ToString(), clamp.Requested);
        Assert.Equal(TimeSpan.FromSeconds(300).ToString(), clamp.Effective);
        Assert.Equal("§12.4 rule 2", clamp.ContractReference);
    }

    [Theory]
    [InlineData(300)]
    [InlineData(60)]
    public void AJwksCacheTtlWithinTheLimit_EmitsNothing(int seconds)
    {
        var events = new List<TelemetryEvent>();
        using AxiamClient client = NewClient(TimeSpan.FromSeconds(seconds), events);

        Assert.DoesNotContain(events.OfType<ConfigClampedEvent>(), e => e.Setting == "JwksCacheTtl");
    }
}
