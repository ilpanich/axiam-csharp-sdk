using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Axiam.Sdk.Webauthn;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;24 — the WebAuthn relying-party layer and the &#167;24.6a JSON bridge.
/// </summary>
/// <remarks>
/// Two assertions are worth reading twice:
/// <list type="bullet">
///   <item><c>RegisterStart_503_IsNotRetried</c> asserts on the <b>request count</b>, not
///   the exception type, because &#167;24.4 rule 2 regresses the moment someone tidies a
///   retry predicate — and a type assertion would still pass.</item>
///   <item><c>StateToken_IsNeverParsed</c> hands the SDK a state token that is not a JWT at
///   all. If anything decoded one, this is where it would fail.</item>
/// </list>
/// </remarks>
[Trait("Category", "Fast")]
public class WebauthnTests
{
    private static readonly Uri BaseUrl = new("https://axiam.test");
    private const string TenantGuid = "22222222-2222-2222-2222-222222222222";
    private const string OrgGuid = "33333333-3333-3333-3333-333333333333";
    private const string StateToken = "state-token-fixture-value-do-not-log";
    private const string ChallengeToken = "challenge-token-fixture-do-not-log";
    private const string AccessToken = "access-token-fixture-do-not-log";
    private const string RefreshToken = "refresh-token-fixture-do-not-log";

    private const string RegisterStartPath = "/api/v1/auth/webauthn/register/start";
    private const string RegisterFinishPath = "/api/v1/auth/webauthn/register/finish";
    private const string AuthStartPath = "/api/v1/auth/webauthn/authenticate/start";
    private const string DiscoverableStartPath = "/api/v1/auth/webauthn/authenticate/discoverable/start";
    private const string DiscoverableFinishPath = "/api/v1/auth/webauthn/authenticate/discoverable/finish";

    /// <summary>
    /// Deliberately "unusual but valid": every optional field populated, so the
    /// pass-through assertion has something to catch an over-eager implementation
    /// dropping. A minimal fixture would prove nothing.
    /// </summary>
    private const string CreationChallenge = """
        {"publicKey":{
          "challenge":"Y2hhbGxlbmdlLWJ5dGVz",
          "rp":{"id":"axiam.test","name":"AXIAM Test"},
          "user":{"id":"dXNlci1oYW5kbGU","name":"alice","displayName":"Alice"},
          "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-8},
                              {"type":"public-key","alg":-257}],
          "timeout":60000,
          "excludeCredentials":[{"id":"ZXhpc3Rpbmc","type":"public-key","transports":["usb","nfc"]}],
          "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,
                                    "userVerification":"required"},
          "attestation":"direct",
          "extensions":{"credProps":true}
        }}
        """;

    private const string MinimalCreationChallenge = """
        {"publicKey":{
          "challenge":"bWluaW1hbA",
          "rp":{"name":"AXIAM Test"},
          "user":{"id":"dQ","name":"bob","displayName":"Bob"},
          "pubKeyCredParams":[{"type":"public-key","alg":-7}]
        }}
        """;

    private const string DiscoverableChallenge = """
        {"publicKey":{"challenge":"ZGlzY292ZXJhYmxl","rpId":"axiam.test",
         "allowCredentials":[],"userVerification":"required"}}
        """;

    /// <summary>Carries an unknown key the SDK must forward rather than strip.</summary>
    private const string RegistrationResponse = """
        {"id":"bmV3LWNyZWQ","rawId":"bmV3LWNyZWQ",
         "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                     "attestationObject":"o2NmbXRkbm9uZQ",
                     "transports":["internal"],
                     "vendorSpecific":"must-survive"},
         "type":"public-key","clientExtensionResults":{"credProps":{"rk":true}}}
        """;

    private const string AuthenticationResponse = """
        {"id":"bmV3LWNyZWQ","rawId":"bmV3LWNyZWQ",
         "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                     "authenticatorData":"YXV0aC1kYXRh","signature":"c2ln",
                     "userHandle":"dXNlci1oYW5kbGU"},
         "type":"public-key","clientExtensionResults":{}}
        """;

    private static string B64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Jwt(object payload)
    {
        string header = B64Url(Encoding.UTF8.GetBytes("""{"alg":"none"}"""));
        string body = B64Url(JsonSerializer.SerializeToUtf8Bytes(payload));
        return $"{header}.{body}.unsigned";
    }

    private static void SeedSession(AxiamClient client)
    {
        FieldInfo field = typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var container = (CookieContainer)field.GetValue(client)!;
        container.Add(BaseUrl, new Cookie("axiam_access", Jwt(new
        {
            sub = "user-1",
            tenant_id = TenantGuid,
            org_id = OrgGuid,
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
        })));
    }

    private static AxiamClient Client(RoutingHandler handler, AxiamClientOptions? options = null) =>
        AxiamClient.CreateForTesting(
            BaseUrl,
            TenantGuid,
            options ?? new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantGuid, OrgId = Guid.Parse(OrgGuid) },
            handler);

    private static HttpResponseMessage ChallengeResponse(string challenge) =>
        OidcTestKit.JsonOk($$"""{"challenge":{{challenge}},"state_token":"{{StateToken}}"}""");

    private static HttpResponseMessage CredentialResponse() =>
        OidcTestKit.JsonStatus(HttpStatusCode.Created, $$"""
            {"id":"{{Guid.NewGuid()}}","credential_id":"bmV3LWNyZWQ","name":"Alice's laptop",
             "credential_type":"passkey","created_at":"2026-08-22T10:00:00Z"}
            """);

    private static HttpResponseMessage WebauthnLoginResponse() =>
        OidcTestKit.JsonOk($$"""
            {"access_token":"{{AccessToken}}","refresh_token":"{{RefreshToken}}",
             "session_id":"{{Guid.NewGuid()}}","expires_in":900}
            """);

    // -----------------------------------------------------------------------
    // §24.0 — options and responses pass through untouched
    // -----------------------------------------------------------------------

    [Fact]
    public async Task RegisterStart_OptionsPassThroughStructurallyUnchanged()
    {
        using var handler = new RoutingHandler();
        handler.Map(RegisterStartPath, _ => ChallengeResponse(CreationChallenge));
        using AxiamClient client = Client(handler);
        SeedSession(client);

        WebauthnChallenge challenge = await client.WebauthnRegisterStartAsync();

        // Structural equality, not a spot-check of three fields: the failure mode this
        // guards is an SDK that quietly drops the one option it did not recognize.
        using JsonDocument expected = JsonDocument.Parse(CreationChallenge);
        Assert.Equal(
            JsonSerializer.Serialize(expected.RootElement),
            JsonSerializer.Serialize(challenge.Challenge));
    }

    [Fact]
    public async Task RegisterStart_SynthesizesNoFieldTheServerOmitted()
    {
        using var handler = new RoutingHandler();
        handler.Map(RegisterStartPath, _ => ChallengeResponse(MinimalCreationChallenge));
        using AxiamClient client = Client(handler);
        SeedSession(client);

        WebauthnChallenge challenge = await client.WebauthnRegisterStartAsync();
        JsonElement options = challenge.Challenge.GetProperty("publicKey");

        Assert.False(options.TryGetProperty("authenticatorSelection", out _), "the SDK must not invent a selection");
        Assert.False(options.TryGetProperty("timeout", out _), "the SDK must not invent a timeout");
        Assert.False(options.TryGetProperty("attestation", out _), "the SDK must not invent a conveyance");
    }

    [Fact]
    public async Task RegisterFinish_AuthenticatorResponseReachesTheWireByteForByte()
    {
        string? sent = null;
        using var handler = new RoutingHandler();
        handler.Map(RegisterFinishPath, request =>
        {
            sent = OidcTestKit.ReadRawBody(request);
            return CredentialResponse();
        });
        using AxiamClient client = Client(handler);
        SeedSession(client);

        await client.WebauthnRegisterFinishAsync(Sensitive.Of(StateToken), "Alice's laptop", RegistrationResponse);

        // The literal substring, not a parsed comparison: this is the assertion that
        // catches a re-encode (§24.0), which a structural comparison would happily pass.
        Assert.Contains(RegistrationResponse.Trim(), sent);
        Assert.Contains("must-survive", sent);
    }

    // -----------------------------------------------------------------------
    // §24.1 — register requires a session
    // -----------------------------------------------------------------------

    [Fact]
    public async Task RegisterWithoutASession_MakesZeroWireCalls()
    {
        using var handler = new RoutingHandler();
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthError>(() => client.WebauthnRegisterStartAsync());
        await Assert.ThrowsAsync<AuthError>(() =>
            client.WebauthnRegisterFinishAsync(Sensitive.Of(StateToken), "k", RegistrationResponse));

        // Asserted on the transport, not the exception type: §24.1 requires the refusal to
        // be client-side.
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task RegisterFinish_ReturnsTheCredential()
    {
        using var handler = new RoutingHandler();
        handler.Map(RegisterFinishPath, _ => CredentialResponse());
        using AxiamClient client = Client(handler);
        SeedSession(client);

        WebauthnCredential credential = await client.WebauthnRegisterFinishAsync(
            Sensitive.Of(StateToken), "Alice's laptop", RegistrationResponse);

        Assert.Equal("bmV3LWNyZWQ", credential.CredentialId);
        Assert.Equal("passkey", credential.CredentialType);
        Assert.Null(credential.LastUsedAt);
    }

    // -----------------------------------------------------------------------
    // §24.2 — two ceremonies, not one with a flag
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AuthenticateStart_SendsTheChallengeToken()
    {
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(AuthStartPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return ChallengeResponse(DiscoverableChallenge);
        });
        using AxiamClient client = Client(handler);

        await client.WebauthnAuthenticateStartAsync(Sensitive.Of(ChallengeToken));

        Assert.Equal(ChallengeToken, body.GetProperty("challenge_token").GetString());
    }

    [Fact]
    public async Task DiscoverableStart_SendsAWorkspaceAndNoChallengeToken()
    {
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(DiscoverableStartPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return ChallengeResponse(DiscoverableChallenge);
        });
        using AxiamClient client = Client(handler);

        await client.WebauthnDiscoverableStartAsync();

        Assert.False(
            body.TryGetProperty("challenge_token", out _),
            "merging the two ceremonies reproduces a bug the server already fixed (§24.2)");
        Assert.Equal(OrgGuid, body.GetProperty("org_id").GetString());
        Assert.Equal(TenantGuid, body.GetProperty("tenant_id").GetString());
    }

    [Fact]
    public async Task DiscoverableStart_ExplicitWorkspaceOverridesTheClientConfiguration()
    {
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(DiscoverableStartPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return ChallengeResponse(DiscoverableChallenge);
        });
        using AxiamClient client = Client(handler);

        // §24.1: unlike the /oauth2 endpoints this one accepts slugs.
        await client.WebauthnDiscoverableStartAsync(
            new WebauthnWorkspace { OrgSlug = "other-org", TenantSlug = "other-tenant" });

        Assert.Equal("other-org", body.GetProperty("org_slug").GetString());
        Assert.Equal("other-tenant", body.GetProperty("tenant_slug").GetString());
        Assert.False(body.TryGetProperty("org_id", out _));
    }

    [Fact]
    public async Task DiscoverableStart_WithoutAnOrganization_IsRefusedClientSide()
    {
        using var handler = new RoutingHandler();
        var options = new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantGuid };
        using AxiamClient client = Client(handler, options);

        await Assert.ThrowsAsync<AuthError>(() => client.WebauthnDiscoverableStartAsync());
        Assert.Empty(handler.Requests);
    }

    // -----------------------------------------------------------------------
    // §24.3 — credential adoption
    // -----------------------------------------------------------------------

    [Fact]
    public async Task DiscoverableFinish_ReturnsTheSession()
    {
        using var handler = new RoutingHandler();
        handler.Map(DiscoverableFinishPath, _ => WebauthnLoginResponse());
        using AxiamClient client = Client(handler);
        SeedSession(client);

        WebauthnLoginResult result = await client.WebauthnDiscoverableFinishAsync(
            Sensitive.Of(StateToken), AuthenticationResponse);

        Assert.Equal(900L, result.ExpiresIn);
        Assert.NotEqual(Guid.Empty, result.SessionId);
    }

    [Fact]
    public async Task DiscoverableFinish_DropsAMemoizedDecision()
    {
        var resource = Guid.Parse("44444444-4444-4444-4444-444444444444");
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/authz/check", _ => OidcTestKit.JsonOk("""{"allowed":true}"""));
        handler.Map(DiscoverableFinishPath, _ => WebauthnLoginResponse());

        var options = new AxiamClientOptions
        {
            BaseUrl = BaseUrl,
            TenantId = TenantGuid,
            OrgId = Guid.Parse(OrgGuid),
            DecisionMemoTtl = TimeSpan.FromMinutes(5),
        };
        using AxiamClient client = Client(handler, options);
        SeedSession(client);

        await client.Authz.CheckAccessAsync("read", resource);
        await client.Authz.CheckAccessAsync("read", resource);
        Assert.Equal(1, handler.CountFor("/api/v1/authz/check"));

        await client.WebauthnDiscoverableFinishAsync(Sensitive.Of(StateToken), AuthenticationResponse);

        // §24.3 rule 4: memo entries are keyed by subject, and the ceremony changed it —
        // so this must hit the wire again rather than answer from a warm cache.
        await client.Authz.CheckAccessAsync("read", resource);
        Assert.Equal(2, handler.CountFor("/api/v1/authz/check"));
    }

    // -----------------------------------------------------------------------
    // §24.4 — the two error rows that are not the §2 defaults
    // -----------------------------------------------------------------------

    [Fact]
    public async Task RegisterStart_503_IsNotRetried()
    {
        using var handler = new RoutingHandler();
        handler.Map(RegisterStartPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.ServiceUnavailable, """{"message":"FIDO metadata unavailable"}"""));
        using AxiamClient client = Client(handler);
        SeedSession(client);

        await Assert.ThrowsAnyAsync<Exception>(() => client.WebauthnRegisterStartAsync());

        // §24.4 rule 2, asserted on the request count: a 503 here is a server
        // CONFIGURATION state, retrying changes nothing, and this regresses silently the
        // moment the retry predicate is tidied.
        Assert.Equal(1, handler.CountFor(RegisterStartPath));
    }

    [Fact]
    public async Task RegisterFinish_403_KeepsTheAttestationPolicyMessage()
    {
        using var handler = new RoutingHandler();
        handler.Map(RegisterFinishPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.Forbidden, """{"message":"this security key is not FIDO certified"}"""));
        using AxiamClient client = Client(handler);
        SeedSession(client);

        AuthzError error = await Assert.ThrowsAsync<AuthzError>(() =>
            client.WebauthnRegisterFinishAsync(Sensitive.Of(StateToken), "key", RegistrationResponse));

        // §24.4 rule 1: the policy message is the only way the person holding the key
        // learns a different one would work.
        Assert.Contains("FIDO certified", error.Message);
    }

    [Fact]
    public async Task DiscoverableFinish_401_IsAnAuthError()
    {
        using var handler = new RoutingHandler();
        handler.Map(DiscoverableFinishPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.Unauthorized, """{"message":"assertion failed"}"""));
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthError>(() =>
            client.WebauthnDiscoverableFinishAsync(Sensitive.Of(StateToken), AuthenticationResponse));
    }

    // -----------------------------------------------------------------------
    // §24.5 — opaque and sensitive
    // -----------------------------------------------------------------------

    [Fact]
    public async Task StateToken_IsNeverParsed()
    {
        // Not a JWT, not base64, not three dot-separated parts. If anything decoded it,
        // this round trip would not survive.
        const string nonsense = "-----definitely not a jwt-----";
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(DiscoverableStartPath, _ => OidcTestKit.JsonOk(
            $$"""{"challenge":{{DiscoverableChallenge}},"state_token":"{{nonsense}}"}"""));
        handler.Map(DiscoverableFinishPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return WebauthnLoginResponse();
        });
        using AxiamClient client = Client(handler);

        WebauthnChallenge challenge = await client.WebauthnDiscoverableStartAsync();
        Assert.Equal(nonsense, challenge.StateToken.Reveal());

        await client.WebauthnDiscoverableFinishAsync(challenge.StateToken, AuthenticationResponse);

        Assert.Equal(nonsense, body.GetProperty("state_token").GetString());
    }

    [Fact]
    public async Task NoFixtureTokenAppearsInARenderedValue()
    {
        using var handler = new RoutingHandler();
        handler.Map(RegisterStartPath, _ => ChallengeResponse(CreationChallenge));
        handler.Map(DiscoverableFinishPath, _ => WebauthnLoginResponse());
        using AxiamClient client = Client(handler);
        SeedSession(client);

        WebauthnChallenge challenge = await client.WebauthnRegisterStartAsync();
        Assert.DoesNotContain(StateToken, challenge.ToString());
        Assert.DoesNotContain(StateToken, challenge.StateToken.ToString());

        WebauthnLoginResult login = await client.WebauthnDiscoverableFinishAsync(
            Sensitive.Of(StateToken), AuthenticationResponse);
        Assert.DoesNotContain(AccessToken, login.ToString());
        Assert.DoesNotContain(RefreshToken, login.ToString());
    }

    // -----------------------------------------------------------------------
    // §24.6a — the JSON bridge
    // -----------------------------------------------------------------------

    [Fact]
    public async Task RequestJson_RoundTripsAndDropsThePublicKeyWrapper()
    {
        using var handler = new RoutingHandler();
        handler.Map(RegisterStartPath, _ => ChallengeResponse(CreationChallenge));
        using AxiamClient client = Client(handler);
        SeedSession(client);

        WebauthnChallenge challenge = await client.WebauthnRegisterStartAsync();
        using JsonDocument parsed = JsonDocument.Parse(challenge.RequestJson);

        // The inner options object: the publicKey wrapper belongs to the DOM's
        // CredentialCreationOptions, and the platform JSON APIs — the very ones this
        // accessor exists for — do not want it.
        Assert.False(parsed.RootElement.TryGetProperty("publicKey", out _));

        using JsonDocument expected = JsonDocument.Parse(CreationChallenge);
        Assert.Equal(
            JsonSerializer.Serialize(expected.RootElement.GetProperty("publicKey")),
            JsonSerializer.Serialize(parsed.RootElement));
        Assert.Equal("direct", parsed.RootElement.GetProperty("attestation").GetString());
        Assert.Equal(60000, parsed.RootElement.GetProperty("timeout").GetInt32());
    }

    [Fact]
    public async Task AResponseThatIsNotAJsonObjectIsRefusedBeforeTheWire()
    {
        using var handler = new RoutingHandler();
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthError>(() =>
            client.WebauthnDiscoverableFinishAsync(Sensitive.Of(StateToken), "not json at all"));
        await Assert.ThrowsAsync<AuthError>(() =>
            client.WebauthnDiscoverableFinishAsync(Sensitive.Of(StateToken), """["an","array"]"""));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public void TheErrorClassificationIsReachableWithoutALinkedApi()
    {
        // §24.6b rule 5, required of this SDK too: a Blazor or MAUI front end relaying a
        // DOMException name has the same five outcomes.
        Assert.Equal(WebauthnFailure.Cancelled, WebauthnFailures.Classify("NotAllowedError"));
        Assert.Equal(WebauthnFailure.AlreadyRegistered, WebauthnFailures.Classify("InvalidStateError"));
        Assert.Equal(WebauthnFailure.Timeout, WebauthnFailures.Classify("AbortError"));
        Assert.Equal(WebauthnFailure.Unsupported, WebauthnFailures.Classify("NotSupportedError"));
        Assert.Equal(WebauthnFailure.Unsupported, WebauthnFailures.Classify("SecurityError"));
        Assert.Equal(WebauthnFailure.Unknown, WebauthnFailures.Classify("SomethingElseError"));
        Assert.Equal(WebauthnFailure.Unknown, WebauthnFailures.Classify(null));

        // ASAuthorizationError.canceled spells it with one L.
        Assert.Equal(WebauthnFailure.Cancelled, WebauthnFailures.Classify("canceled"));
    }

    [Fact]
    public void AlreadyRegisteredIsDistinguishableFromCancelled()
    {
        Assert.NotEqual(
            WebauthnFailures.Classify("InvalidStateError"),
            WebauthnFailures.Classify("NotAllowedError"));

        // The only classification whose remedy is "use a different device".
        Assert.Contains("different device", WebauthnFailure.AlreadyRegistered.Message());
        // And the one that must not accuse the user: it also covers a silent timeout,
        // which the spec refuses to distinguish.
        Assert.Contains("cancelled or timed out", WebauthnFailure.Cancelled.Message());
    }
}
