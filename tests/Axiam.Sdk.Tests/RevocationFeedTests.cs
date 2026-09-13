using System.Collections.Generic;
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
/// CONTRACT.md &#167;10.4 — the optional session-revocation feed (contract 1.44, AXIAM
/// threats T-39 and T-143).
/// </summary>
/// <remarks>
/// <para>The feature is a narrowing, not a control, and the tests are organised around the
/// five rules that make that true rather than around the type's method list:</para>
/// <list type="bullet">
///   <item><strong>Default off</strong> — a verifier built as every caller builds one today
///   fetches nothing, asserted by counting requests on the wire rather than by inspecting a
///   flag.</item>
///   <item><strong>Never on the request path</strong> — a revoked session is rejected AFTER
///   one poll and not before, which pins that the guard is not fetching per request.</item>
///   <item><strong>Never fail closed</strong> — unreachable, non-<c>200</c>, unparseable and
///   wrong-<c>alg</c> each behave as no feed at all, and specifically NOT as an empty
///   list.</item>
///   <item><strong>Only ever rejects</strong> — a token that fails a &#167;10.1 rule is
///   rejected whatever the feed says, and the feed is not even consulted for it.</item>
///   <item><strong>No <c>sid</c>, never matched</strong> — a client-credentials token, an
///   RPT or a token exchange has no session behind it.</item>
/// </list>
/// </remarks>
[Trait("Category", "Fast")]
public class RevocationFeedTests
{
    private const string Tenant = "acme";
    private const string FeedPath = "/oauth2/revocations";
    private const string JwksPath = "/oauth2/jwks";
    private static readonly Uri BaseUrl = new("https://axiam.test");

    /// <summary>
    /// The &#167;10.4 pinned vector: this <c>sid</c> hashes to this entry. Pinned rather
    /// than computed so a change to <see cref="RevocationFeed.EntryFor"/> is a test failure
    /// and not a silently-agreeing round trip.
    /// </summary>
    private const string PinnedSid = "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b";

    private const string PinnedEntry = "i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ";

    /// <summary>Serves the JWKS document and, optionally, a feed document; counts both.</summary>
    private sealed class FeedHandler : HttpMessageHandler
    {
        private readonly string _jwksJson;
        private readonly Func<HttpResponseMessage>? _feedResponder;
        private int _jwksCount;
        private int _feedCount;

        public FeedHandler(string jwksJson, Func<HttpResponseMessage>? feedResponder)
        {
            _jwksJson = jwksJson;
            _feedResponder = feedResponder;
        }

        public int JwksCount => _jwksCount;

        public int FeedCount => _feedCount;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (path == FeedPath)
            {
                Interlocked.Increment(ref _feedCount);
                if (_feedResponder is null)
                {
                    throw new HttpRequestException("connection refused");
                }

                return Task.FromResult(_feedResponder());
            }

            Interlocked.Increment(ref _jwksCount);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_jwksJson, Encoding.UTF8, "application/json"),
            });
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static string FeedJson(params string[] entries) =>
        JsonSerializer.Serialize(new
        {
            alg = "SHA-256",
            issued_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ttl = 900,
            revoked = entries,
        });

    /// <summary>An AXIAM-shaped access token carrying <paramref name="sid"/> — or none.</summary>
    private static string TokenWithSid(JwksFixture fixture, string? sid)
    {
        var payload = new Dictionary<string, object>
        {
            ["sub"] = "user-1",
            ["tenant_id"] = Tenant,
            ["roles"] = new[] { "admin" },
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
        };
        if (sid is not null)
        {
            payload["sid"] = sid;
        }

        return fixture.SignIdToken(payload);
    }

    private static (JwksVerifier Verifier, JwksFixture Fixture, FeedHandler Handler, RevocationFeed? Feed)
        Build(Func<HttpResponseMessage>? feedResponder, bool attachFeed, TimeSpan? pollInterval = null)
    {
        var fixture = new JwksFixture();
        var handler = new FeedHandler(fixture.BuildJwksDocument(), feedResponder);
        var http = new HttpClient(handler) { BaseAddress = BaseUrl };
        RevocationFeed? feed = attachFeed ? new RevocationFeed(http, BaseUrl, pollInterval) : null;
        var verifier = new JwksVerifier(http, BaseUrl, TimeSpan.FromMinutes(5), revocationFeed: feed);
        return (verifier, fixture, handler, feed);
    }

    // -- The entry encoding is pinned ---------------------------------------

    [Fact]
    public void EntryFor_MatchesThePinnedVector()
    {
        Assert.Equal(PinnedEntry, RevocationFeed.EntryFor(PinnedSid));
    }

    [Fact]
    public void EntryFor_HashesTheClaimAsRead_NotAReRenderedUuid()
    {
        // Upper-case is a DIFFERENT string and must hash differently: §10.4 says hash the
        // claim as read, precisely so the answer does not depend on a UUID parser.
        Assert.NotEqual(
            RevocationFeed.EntryFor(PinnedSid),
            RevocationFeed.EntryFor(PinnedSid.ToUpperInvariant()));
    }

    [Fact]
    public void EntryFor_IsBase64UrlUnpadded()
    {
        string entry = RevocationFeed.EntryFor(PinnedSid);
        Assert.DoesNotContain('=', entry);
        Assert.DoesNotContain('+', entry);
        Assert.DoesNotContain('/', entry);
    }

    // -- Default off --------------------------------------------------------

    [Fact]
    public async Task NoFeedAttached_FetchesNothing_AndAcceptsARevokedSession()
    {
        // The I4 twin: a verifier built exactly as every caller builds one today. The
        // session IS revoked on the server, and this verifier neither knows nor asks.
        (JwksVerifier verifier, JwksFixture fixture, FeedHandler handler, _) =
            Build(() => Json(HttpStatusCode.OK, FeedJson(PinnedEntry)), attachFeed: false);

        JsonElement? claims = await verifier.VerifyAsync(TokenWithSid(fixture, PinnedSid), Tenant);

        Assert.NotNull(claims);
        Assert.Equal(0, handler.FeedCount);
    }

    // -- Never on the request path ------------------------------------------

    [Fact]
    public async Task RevokedSession_IsRejected_AfterOnePollAndNotBefore()
    {
        (JwksVerifier verifier, JwksFixture fixture, FeedHandler handler, _) =
            Build(() => Json(HttpStatusCode.OK, FeedJson(PinnedEntry)), attachFeed: true);
        string jwt = TokenWithSid(fixture, PinnedSid);

        Assert.Null(await verifier.VerifyAsync(jwt, Tenant));
        Assert.Equal(1, handler.FeedCount);

        // Still rejected, and still exactly one fetch: the second answer came from the
        // cached set, which is what "never on the request path" means.
        Assert.Null(await verifier.VerifyAsync(jwt, Tenant));
        Assert.Equal(1, handler.FeedCount);
    }

    [Fact]
    public async Task ManyVerifications_PollOnce_WithinOneInterval()
    {
        (JwksVerifier verifier, JwksFixture fixture, FeedHandler handler, _) =
            Build(() => Json(HttpStatusCode.OK, FeedJson(PinnedEntry)), attachFeed: true);
        string jwt = TokenWithSid(fixture, "some-other-session");

        for (int i = 0; i < 25; i++)
        {
            Assert.NotNull(await verifier.VerifyAsync(jwt, Tenant));
        }

        Assert.Equal(1, handler.FeedCount);
    }

    [Fact]
    public async Task UnlistedSession_IsAccepted()
    {
        (JwksVerifier verifier, JwksFixture fixture, _, _) =
            Build(() => Json(HttpStatusCode.OK, FeedJson(PinnedEntry)), attachFeed: true);

        JsonElement? claims =
            await verifier.VerifyAsync(TokenWithSid(fixture, "a-session-nobody-revoked"), Tenant);

        Assert.NotNull(claims);
    }

    // -- Never fail closed ---------------------------------------------------

    [Fact]
    public async Task UnreachableFeed_BehavesAsNoFeedAtAll()
    {
        // The I4 twin for the feature ON: the feed is attached and the deployment does not
        // serve it. Every verification must succeed exactly as it does with no feed.
        (JwksVerifier verifier, JwksFixture fixture, FeedHandler handler, _) =
            Build(feedResponder: null, attachFeed: true);

        JsonElement? claims = await verifier.VerifyAsync(TokenWithSid(fixture, PinnedSid), Tenant);

        Assert.NotNull(claims);
        Assert.Equal(1, handler.FeedCount);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.Unauthorized)]
    public async Task NonOkStatus_BehavesAsNoFeedAtAll(HttpStatusCode status)
    {
        (JwksVerifier verifier, JwksFixture fixture, _, _) =
            Build(() => Json(status, FeedJson(PinnedEntry)), attachFeed: true);

        Assert.NotNull(await verifier.VerifyAsync(TokenWithSid(fixture, PinnedSid), Tenant));
    }

    [Fact]
    public async Task UnparseableBody_BehavesAsNoFeedAtAll()
    {
        (JwksVerifier verifier, JwksFixture fixture, _, _) =
            Build(() => Json(HttpStatusCode.OK, "{not json"), attachFeed: true);

        Assert.NotNull(await verifier.VerifyAsync(TokenWithSid(fixture, PinnedSid), Tenant));
    }

    [Fact]
    public async Task UnknownAlg_BehavesAsNoFeedAtAll_NotAsAnEmptyList()
    {
        // The document lists this very session. An SDK that ignored `alg` would reject;
        // one that treated the document as an empty list would accept for the WRONG
        // reason and stop holding any previously-good set. Acceptance here is correct,
        // and the next test pins that the "empty list" reading is not what happened.
        string body = JsonSerializer.Serialize(new
        {
            alg = "SHA-512",
            revoked = new[] { PinnedEntry },
        });
        (JwksVerifier verifier, JwksFixture fixture, _, _) =
            Build(() => Json(HttpStatusCode.OK, body), attachFeed: true);

        Assert.NotNull(await verifier.VerifyAsync(TokenWithSid(fixture, PinnedSid), Tenant));
    }

    [Fact]
    public async Task AFailedPoll_DoesNotUnrevokeAnAlreadyKnownSession()
    {
        // This is the difference between "unusable" and "empty", made observable: the
        // first poll succeeds and knows the session is revoked; the second fails. A feed
        // that collapsed failure into an empty list would now ADMIT a session it had
        // already been told was revoked.
        int call = 0;
        var fixture = new JwksFixture();
        var handler = new FeedHandler(fixture.BuildJwksDocument(), () =>
            Interlocked.Increment(ref call) == 1
                ? Json(HttpStatusCode.OK, FeedJson(PinnedEntry))
                : Json(HttpStatusCode.InternalServerError, "{}"));
        var http = new HttpClient(handler) { BaseAddress = BaseUrl };
        var feed = new RevocationFeed(http, BaseUrl);
        var verifier = new JwksVerifier(http, BaseUrl, TimeSpan.FromMinutes(5), revocationFeed: feed);
        string jwt = TokenWithSid(fixture, PinnedSid);

        Assert.Null(await verifier.VerifyAsync(jwt, Tenant));

        // Force the interval to have elapsed, so the next verification really re-polls.
        feed.TimeProvider = () => DateTimeOffset.UtcNow.AddMinutes(10);

        Assert.Null(await verifier.VerifyAsync(jwt, Tenant));
        Assert.Equal(2, handler.FeedCount);
    }

    [Fact]
    public async Task OverflowingDocument_IsDroppedWhole_NotTruncated()
    {
        var entries = new string[RevocationFeed.MaxEntries + 1];
        for (int i = 0; i < entries.Length; i++)
        {
            entries[i] = RevocationFeed.EntryFor($"session-{i}");
        }

        entries[0] = PinnedEntry;

        (JwksVerifier verifier, JwksFixture fixture, _, _) =
            Build(() => Json(HttpStatusCode.OK, FeedJson(entries)), attachFeed: true);

        // Listed in the document, and admitted — because the whole set was dropped. A
        // truncating implementation would admit some revoked sessions and report none.
        Assert.NotNull(await verifier.VerifyAsync(TokenWithSid(fixture, PinnedSid), Tenant));
    }

    // -- It only ever rejects ------------------------------------------------

    [Fact]
    public async Task ATokenFailingASection101Rule_IsRejected_WithoutConsultingTheFeed()
    {
        (JwksVerifier verifier, JwksFixture fixture, FeedHandler handler, _) =
            Build(() => Json(HttpStatusCode.OK, FeedJson()), attachFeed: true);

        // Wrong tenant: rejected by §10.1 long before §10.4 could have an opinion.
        string jwt = fixture.SignIdToken(new
        {
            sub = "user-1",
            tenant_id = "some-other-tenant",
            roles = new[] { "admin" },
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
            sid = PinnedSid,
        });

        Assert.Null(await verifier.VerifyAsync(jwt, Tenant));
        Assert.Equal(0, handler.FeedCount);
    }

    [Fact]
    public async Task AnExpiredToken_IsRejected_WithoutConsultingTheFeed()
    {
        (JwksVerifier verifier, JwksFixture fixture, FeedHandler handler, _) =
            Build(() => Json(HttpStatusCode.OK, FeedJson()), attachFeed: true);

        string jwt = fixture.SignIdToken(new
        {
            sub = "user-1",
            tenant_id = Tenant,
            roles = new[] { "admin" },
            exp = DateTimeOffset.UtcNow.AddMinutes(-30).ToUnixTimeSeconds(),
            sid = PinnedSid,
        });

        Assert.Null(await verifier.VerifyAsync(jwt, Tenant));
        Assert.Equal(0, handler.FeedCount);
    }

    // -- A token with no sid is never matched --------------------------------

    [Fact]
    public async Task TokenWithoutSid_IsNeverMatched()
    {
        // A client-credentials token, an RPT or a token exchange. The feed happens to list
        // the hash of the empty string; nothing may match it.
        (JwksVerifier verifier, JwksFixture fixture, _, _) = Build(
            () => Json(HttpStatusCode.OK, FeedJson(RevocationFeed.EntryFor(string.Empty))),
            attachFeed: true);

        Assert.NotNull(await verifier.VerifyAsync(TokenWithSid(fixture, sid: null), Tenant));
    }

    // -- Bounds --------------------------------------------------------------

    [Fact]
    public void PollInterval_IsClampedUp_NotRefused()
    {
        var http = new HttpClient(new FeedHandler("{}", null)) { BaseAddress = BaseUrl };

        var floored = new RevocationFeed(http, BaseUrl, TimeSpan.FromMilliseconds(100));
        Assert.Equal(RevocationFeed.MinPollInterval, floored.PollInterval);

        var honoured = new RevocationFeed(http, BaseUrl, TimeSpan.FromMinutes(2));
        Assert.Equal(TimeSpan.FromMinutes(2), honoured.PollInterval);

        var defaulted = new RevocationFeed(http, BaseUrl);
        Assert.Equal(RevocationFeed.DefaultPollInterval, defaulted.PollInterval);
    }

    [Fact]
    public void FeedUri_IsTheDocumentedPath()
    {
        var http = new HttpClient(new FeedHandler("{}", null)) { BaseAddress = BaseUrl };
        var feed = new RevocationFeed(http, BaseUrl);

        Assert.Equal("https://axiam.test/oauth2/revocations", feed.FeedUri.ToString());
        Assert.Equal(FeedPath, RevocationFeed.FeedPath);
    }

    [Fact]
    public void RelativeBaseUrl_IsRefused()
    {
        var http = new HttpClient(new FeedHandler("{}", null));
        Assert.Throws<ArgumentException>(() =>
            new RevocationFeed(http, new Uri("/oauth2", UriKind.Relative)));
    }

    [Fact]
    public async Task JwksFetching_IsUnaffectedByTheFeed()
    {
        // The two caches are independent: attaching a feed must not change how often the
        // JWKS document is fetched.
        (JwksVerifier verifier, JwksFixture fixture, FeedHandler handler, _) =
            Build(() => Json(HttpStatusCode.OK, FeedJson()), attachFeed: true);
        string jwt = TokenWithSid(fixture, PinnedSid);

        await verifier.VerifyAsync(jwt, Tenant);
        await verifier.VerifyAsync(jwt, Tenant);

        Assert.Equal(1, handler.JwksCount);
    }
}
