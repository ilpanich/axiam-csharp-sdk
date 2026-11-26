using System.Web;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// RP-initiated and back-channel logout — CONTRACT.md &#167;12.7.
/// </summary>
/// <remarks>
/// The &#167;12.7.6 required tests. The <see cref="AxiamClient.VerifyLogoutTokenAsync"/> half
/// carries the security weight: its input arrives unsolicited, from the network, and instructs the
/// RP to terminate a session — so each rejection test names the attack it prevents rather than
/// merely asserting an error.
/// </remarks>
[Trait("Category", "Fast")]
public class OidcLogoutTests
{
    private const string IdToken = "the-users-id-token";
    private const string LogoutSid = "session-abc";
    private const string LogoutJti = "logout-token-jti-1";
    private const string BackchannelEvent = "http://schemas.openid.net/event/backchannel-logout";

    private static string Issuer => OidcTestKit.BaseUrl.ToString().TrimEnd('/');

    private static (RoutingHandler Handler, AxiamClient Client, JwksFixture Jwks) SetUp(bool withOptionalEndpoints = true)
    {
        var handler = new RoutingHandler();
        var jwks = new JwksFixture();
        OidcTestKit.MapDiscovery(handler, withOptionalEndpoints: withOptionalEndpoints);
        OidcTestKit.MapJwks(handler, jwks);
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(clientSecret: null));
        return (handler, client, jwks);
    }

    /// <summary>A VALID logout claim set; each argument breaks exactly one §12.7.3 rule.</summary>
    private static Dictionary<string, object?> LogoutClaims(
        string? issuer = null,
        string? audience = null,
        string? subject = "user-1",
        string? sid = LogoutSid,
        string? jti = LogoutJti,
        long? expOffset = 120,
        long? iatOffset = 0,
        object? events = null,
        bool omitEvents = false,
        string? nonce = null)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = issuer ?? Issuer,
            ["aud"] = audience ?? OidcTestKit.ClientId,
            ["iat"] = now + (iatOffset ?? 0),
            ["exp"] = now + (expOffset ?? 120),
        };
        if (subject is not null)
        {
            claims["sub"] = subject;
        }
        if (sid is not null)
        {
            claims["sid"] = sid;
        }
        if (jti is not null)
        {
            claims["jti"] = jti;
        }
        if (!omitEvents)
        {
            claims["events"] = events ?? new Dictionary<string, object> { [BackchannelEvent] = new { } };
        }
        if (nonce is not null)
        {
            claims["nonce"] = nonce;
        }
        return claims;
    }

    private static string Query(string url, string name) =>
        HttpUtility.ParseQueryString(new Uri(url).Query)[name] ?? string.Empty;

    // -----------------------------------------------------------------------
    // §12.7.2 LogoutUrlAsync
    // -----------------------------------------------------------------------

    [Fact]
    public async Task LogoutUrlAsync_UsesTheDiscoveredEndpoint()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture _) = SetUp();

        string url = await client.LogoutUrlAsync(new LogoutUrlParams(Sensitive<string>.Wrap(IdToken)));

        // §12.7.2 rule 1: the endpoint comes from discovery. Code that builds
        // "{issuer}/oauth2/end_session" works against AXIAM and breaks against every other OP the
        // same application is pointed at.
        Assert.Contains("/oauth2/end_session", url, StringComparison.Ordinal);
        Assert.Equal(IdToken, Query(url, "id_token_hint"));
    }

    [Fact]
    public async Task LogoutUrlAsync_OmitsWhatWasNotSupplied_AndPassesStateThrough()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture _) = SetUp();

        string bare = await client.LogoutUrlAsync(new LogoutUrlParams(Sensitive<string>.Wrap(IdToken)));
        Assert.Equal(string.Empty, Query(bare, "post_logout_redirect_uri"));
        Assert.Equal(string.Empty, Query(bare, "state"));

        string full = await client.LogoutUrlAsync(new LogoutUrlParams(
            Sensitive<string>.Wrap(IdToken),
            PostLogoutRedirectUri: "https://app.example.com/bye",
            State: "caller-generated-state"));

        Assert.Equal("https://app.example.com/bye", Query(full, "post_logout_redirect_uri"));
        // §12.7.2 rule 2: the SDK never invents one, because the value only means something to
        // the caller.
        Assert.Equal("caller-generated-state", Query(full, "state"));
    }

    [Fact]
    public async Task LogoutUrlAsync_DoesNotPreValidateTheRedirect()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture _) = SetUp();

        // §12.7.2 rule 3: the allow-list lives in the client's server-side registration. A
        // client-side copy would drift and reject a URI an operator had just registered.
        string url = await client.LogoutUrlAsync(new LogoutUrlParams(
            Sensitive<string>.Wrap(IdToken),
            PostLogoutRedirectUri: "https://somewhere-else.example/x"));

        Assert.Equal("https://somewhere-else.example/x", Query(url, "post_logout_redirect_uri"));
    }

    [Fact]
    public async Task LogoutUrlAsync_NoEndSessionEndpoint_ThrowsWithoutEchoingTheIdToken()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture _) = SetUp(withOptionalEndpoints: false);

        AuthError error = await Assert.ThrowsAsync<AuthError>(
            () => client.LogoutUrlAsync(new LogoutUrlParams(Sensitive<string>.Wrap("super-secret-id-token"))));

        Assert.Contains("end_session_endpoint", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("super-secret-id-token", error.Message, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // §12.7.3 VerifyLogoutTokenAsync
    // -----------------------------------------------------------------------

    [Fact]
    public async Task VerifyLogoutTokenAsync_ValidToken_SurfacesSidSubAndJti()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture jwks) = SetUp();
        string token = jwks.SignIdToken(LogoutClaims());

        VerifiedLogoutToken verified = await client.VerifyLogoutTokenAsync(token);

        // Not a bare bool: the RP has to know WHICH session to end, and a verifier that only says
        // "valid" forces the caller to re-parse the token themselves with none of these checks.
        Assert.Equal(LogoutSid, verified.Sid);
        Assert.Equal("user-1", verified.Sub);
        Assert.Equal(LogoutJti, verified.Jti);
    }

    [Fact]
    public async Task VerifyLogoutTokenAsync_AnIdTokenReplayedAsOne_IsRejected()
    {
        // The attack rules 3 and 4 exist to stop, asserted with a real, otherwise-valid ID token
        // rather than a synthetic mutation: correctly signed by a published key, right issuer and
        // audience, unexpired. Only the missing `events` and the present `nonce` distinguish it.
        (RoutingHandler _, AxiamClient client, JwksFixture jwks) = SetUp();
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string idToken = jwks.SignIdToken(new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["aud"] = OidcTestKit.ClientId,
            ["sub"] = "user-1",
            ["iat"] = now,
            ["exp"] = now + 300,
            ["nonce"] = "the-request-nonce",
        });

        await Assert.ThrowsAsync<AuthError>(() => client.VerifyLogoutTokenAsync(idToken));
    }

    [Fact]
    public async Task VerifyLogoutTokenAsync_NoEventsOrWrongEvent_IsRejected()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture jwks) = SetUp();

        AuthError noEvents = await Assert.ThrowsAsync<AuthError>(
            () => client.VerifyLogoutTokenAsync(jwks.SignIdToken(LogoutClaims(omitEvents: true))));
        Assert.Contains("events", noEvents.Message, StringComparison.Ordinal);

        string otherEvent = jwks.SignIdToken(LogoutClaims(
            events: new Dictionary<string, object> { ["http://schemas.openid.net/event/other"] = new { } }));
        await Assert.ThrowsAsync<AuthError>(() => client.VerifyLogoutTokenAsync(otherEvent));
    }

    [Fact]
    public async Task VerifyLogoutTokenAsync_EventsValueNotAnObject_IsRejected()
    {
        // Back-Channel Logout 1.0 §2.4 specifies a JSON object (normally empty); accepting a
        // string would let a near-miss token through on a technicality.
        (RoutingHandler _, AxiamClient client, JwksFixture jwks) = SetUp();
        string token = jwks.SignIdToken(LogoutClaims(
            events: new Dictionary<string, object> { [BackchannelEvent] = "not-an-object" }));

        await Assert.ThrowsAsync<AuthError>(() => client.VerifyLogoutTokenAsync(token));
    }

    [Fact]
    public async Task VerifyLogoutTokenAsync_Nonce_IsRejectedNotIgnored()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture jwks) = SetUp();
        string token = jwks.SignIdToken(LogoutClaims(nonce: "n-0S6_WzA2Mj"));

        AuthError error = await Assert.ThrowsAsync<AuthError>(() => client.VerifyLogoutTokenAsync(token));
        Assert.Contains("nonce", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VerifyLogoutTokenAsync_NamesNeitherSidNorSub_IsRejected()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture jwks) = SetUp();
        string token = jwks.SignIdToken(LogoutClaims(sid: null, subject: null));

        AuthError error = await Assert.ThrowsAsync<AuthError>(() => client.VerifyLogoutTokenAsync(token));
        Assert.Contains("identifies no session", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VerifyLogoutTokenAsync_SubOnlyIsAccepted_AndSidIsPreferred()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture jwks) = SetUp();

        VerifiedLogoutToken subOnly = await client.VerifyLogoutTokenAsync(jwks.SignIdToken(LogoutClaims(sid: null)));
        Assert.Null(subOnly.Sid);
        Assert.Equal("user-1", subOnly.Sub);

        // With sid present the RP must end THAT session only — falling back to "every session for
        // sub" is over-reach the server itself refuses.
        VerifiedLogoutToken both = await client.VerifyLogoutTokenAsync(jwks.SignIdToken(LogoutClaims()));
        Assert.Equal(LogoutSid, both.Sid);
    }

    [Fact]
    public async Task VerifyLogoutTokenAsync_AnotherClientOrIssuer_IsRejected()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture jwks) = SetUp();

        AuthError audError = await Assert.ThrowsAsync<AuthError>(
            () => client.VerifyLogoutTokenAsync(jwks.SignIdToken(LogoutClaims(audience: "some-other-rp"))));
        Assert.Contains("audience", audError.Message, StringComparison.Ordinal);

        AuthError issError = await Assert.ThrowsAsync<AuthError>(
            () => client.VerifyLogoutTokenAsync(jwks.SignIdToken(LogoutClaims(issuer: "https://evil.example.com"))));
        Assert.Contains("issuer", issError.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VerifyLogoutTokenAsync_UnpublishedKey_IsRejectedWithoutEchoingTheToken()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture _) = SetUp();
        var rogue = new JwksFixture();
        string token = rogue.SignIdToken(LogoutClaims());

        // The signature is what makes the token a statement rather than a request.
        AuthError error = await Assert.ThrowsAsync<AuthError>(() => client.VerifyLogoutTokenAsync(token));
        Assert.DoesNotContain(token, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VerifyLogoutTokenAsync_ExpiredOrStale_IsRejected()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture jwks) = SetUp();

        // A long-lived logout token is a replayable session-termination command.
        await Assert.ThrowsAsync<AuthError>(
            () => client.VerifyLogoutTokenAsync(jwks.SignIdToken(LogoutClaims(iatOffset: -700, expOffset: -600))));

        // exp still ahead, but issued a day ago: a captured delivery being replayed rather than a
        // live one.
        AuthError stale = await Assert.ThrowsAsync<AuthError>(
            () => client.VerifyLogoutTokenAsync(jwks.SignIdToken(LogoutClaims(iatOffset: -86_400, expOffset: 600))));
        Assert.Contains("too old", stale.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VerifyLogoutTokenAsync_IssuedInTheFuture_IsRejected()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture jwks) = SetUp();
        string token = jwks.SignIdToken(LogoutClaims(iatOffset: 600, expOffset: 900));

        AuthError error = await Assert.ThrowsAsync<AuthError>(() => client.VerifyLogoutTokenAsync(token));
        Assert.Contains("future", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VerifyLogoutTokenAsync_NoJti_IsRejected()
    {
        (RoutingHandler _, AxiamClient client, JwksFixture jwks) = SetUp();
        string token = jwks.SignIdToken(LogoutClaims(jti: null));

        AuthError error = await Assert.ThrowsAsync<AuthError>(() => client.VerifyLogoutTokenAsync(token));
        // Without jti the RP cannot dedup at-least-once redeliveries.
        Assert.Contains("jti", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VerifyLogoutTokenAsync_SameTokenTwice_DoesNotThrow()
    {
        // §12.7.3 rule 7. Delivery is at-least-once with retry, so a valid token legitimately
        // arrives twice — that is a retry, not an attack. An SDK that dedupped internally would
        // have no durable store and would silently drop a real second logout after a restart, so
        // jti is surfaced for the RP to dedup on and never consumed here.
        (RoutingHandler _, AxiamClient client, JwksFixture jwks) = SetUp();
        string token = jwks.SignIdToken(LogoutClaims());

        VerifiedLogoutToken first = await client.VerifyLogoutTokenAsync(token);
        VerifiedLogoutToken second = await client.VerifyLogoutTokenAsync(token);

        Assert.Equal(first, second);
        Assert.Equal(LogoutJti, first.Jti);
    }

    // -----------------------------------------------------------------------
    // Contract 1.69 (#880): the server signs the logout token with a `kid`; the key is selected by it.
    // -----------------------------------------------------------------------

    private static IReadOnlyList<KeyValuePair<string, object>> ServerLogoutHeader(string? kid) =>
        kid is null
            ? new[] { new KeyValuePair<string, object>("alg", "EdDSA"), new KeyValuePair<string, object>("typ", "logout+jwt") }
            : new[]
            {
                new KeyValuePair<string, object>("alg", "EdDSA"),
                new KeyValuePair<string, object>("typ", "logout+jwt"),
                new KeyValuePair<string, object>("kid", kid),
            };

    private static AxiamClient ClientWithJwks(string jwksDocument)
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler, withOptionalEndpoints: true);
        handler.Map("/oauth2/jwks", _ => OidcTestKit.JsonOk(jwksDocument));
        return OidcTestKit.Client(handler, OidcTestKit.Options(clientSecret: null));
    }

    [Fact]
    public async Task AServerShapedLogoutToken_VerifiesAgainstATwoKeyJwks_TheSigningKeyNotFirst()
    {
        var other = new JwksFixture();
        var signer = new JwksFixture();
        string token = signer.SignWithExactHeader(ServerLogoutHeader(signer.Kid), LogoutClaims());

        // The header is exactly what the server sends, and nothing else.
        string headerJson = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(
            token.Split('.')[0].Replace('-', '+').Replace('_', '/').PadRight((token.Split('.')[0].Length + 3) / 4 * 4, '=')));
        Assert.Equal($$"""{"alg":"EdDSA","typ":"logout+jwt","kid":"{{signer.Kid}}"}""", headerJson);

        AxiamClient client = ClientWithJwks(JwksFixture.BuildJwksDocument(other, signer));

        VerifiedLogoutToken verified = await client.VerifyLogoutTokenAsync(token);

        Assert.Equal(LogoutSid, verified.Sid);
        Assert.Equal(LogoutJti, verified.Jti);
    }

    [Fact]
    public async Task AKidlessLogoutToken_IsRefusedAsUnknownKid_AgainstAOneKeyJwksWhoseKeySignedIt()
    {
        var signer = new JwksFixture();
        string token = signer.SignWithExactHeader(ServerLogoutHeader(null), LogoutClaims());
        AxiamClient client = ClientWithJwks(JwksFixture.BuildJwksDocument(signer));

        AuthError error = await Assert.ThrowsAsync<AuthError>(() => client.VerifyLogoutTokenAsync(token));

        Assert.Equal(IdTokenFailureReasons.UnknownKid, error.Reason);
    }

    [Fact]
    public async Task AnUnknownKidOnALogoutToken_IsRefusedAsUnknownKid()
    {
        var signer = new JwksFixture();
        var published = new JwksFixture();
        string token = signer.SignWithExactHeader(ServerLogoutHeader(signer.Kid), LogoutClaims());
        AxiamClient client = ClientWithJwks(JwksFixture.BuildJwksDocument(published));

        AuthError error = await Assert.ThrowsAsync<AuthError>(() => client.VerifyLogoutTokenAsync(token));

        Assert.Equal(IdTokenFailureReasons.UnknownKid, error.Reason);
    }

    [Fact]
    public async Task Rules10And11_StayOffTheLogoutAndIdTokenPaths_WhileTheAccessTokenGuardRefusesOnThem()
    {
        // §10.1 rules 10 (typ at+jwt) and 11 (purpose) belong to the access-token path only. Every token below
        // carries tenant_id and a future exp, so no other rule of the guard can refuse it: the control (typ at+jwt, no
        // purpose) is accepted, and each variant differs from it ONLY in what rule 10 or rule 11 looks at.
        var signer = new JwksFixture();
        string jwksDoc = signer.BuildJwksDocument();
        AxiamClient client = ClientWithJwks(jwksDoc);
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        string Mint(string typ, bool purpose) => signer.SignWithExactHeader(
            new[]
            {
                new KeyValuePair<string, object>("alg", "EdDSA"),
                new KeyValuePair<string, object>("typ", typ),
                new KeyValuePair<string, object>("kid", signer.Kid),
            },
            new Dictionary<string, object?>
            {
                ["iss"] = Issuer, ["aud"] = OidcTestKit.ClientId, ["sub"] = "user-1", ["tenant_id"] = "acme",
                ["iat"] = now, ["exp"] = now + 600, ["jti"] = LogoutJti, ["sid"] = LogoutSid,
                ["events"] = new Dictionary<string, object> { [BackchannelEvent] = new { } },
                ["purpose"] = purpose ? "mfa" : null,
            }.Where(kv => kv.Value is not null).ToDictionary(kv => kv.Key, kv => kv.Value));

        var http = new HttpClient(new StubJwksHandler(jwksDoc)) { BaseAddress = new Uri("https://axiam.test") };
        var guard = new Axiam.Sdk.Auth.JwksVerifier(http, new Uri("https://axiam.test"), TimeSpan.FromMinutes(5));
        var oidc = Axiam.Sdk.Auth.JwksVerifier.ForJwksUri(http, new Uri("https://axiam.test/oauth2/jwks"), TimeSpan.FromMinutes(5));

        // Control: with at+jwt and no purpose the guard accepts, so nothing else in these tokens can refuse them.
        Assert.NotNull(await guard.VerifyAsync(Mint("at+jwt", purpose: false), "acme"));

        string logoutTyp = Mint("logout+jwt", purpose: false);   // rule 10 alone
        string idTyp = Mint("JWT", purpose: false);              // rule 10 alone
        string withPurpose = Mint("at+jwt", purpose: true);      // rule 11 alone
        Assert.Null(await guard.VerifyAsync(logoutTyp, "acme"));
        Assert.Null(await guard.VerifyAsync(idTyp, "acme"));
        Assert.Null(await guard.VerifyAsync(withPurpose, "acme"));

        // The OIDC path's signature step (shared by VerifyLogoutTokenAsync and the ID-token validator) applies
        // neither rule: all three verify.
        Assert.NotNull((await oidc.VerifyOidcIdTokenSignatureAsync(logoutTyp)).Payload);
        Assert.NotNull((await oidc.VerifyOidcIdTokenSignatureAsync(idTyp)).Payload);
        Assert.NotNull((await oidc.VerifyOidcIdTokenSignatureAsync(withPurpose)).Payload);

        // And the public logout verifier accepts the server-shaped logout+jwt token (rule 10 does not apply).
        Assert.Equal(LogoutJti, (await client.VerifyLogoutTokenAsync(logoutTyp)).Jti);
    }

    private sealed class StubJwksHandler : HttpMessageHandler
    {
        private readonly string _doc;
        public StubJwksHandler(string doc) => _doc = doc;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(_doc, System.Text.Encoding.UTF8, "application/json"),
            });
    }
}
