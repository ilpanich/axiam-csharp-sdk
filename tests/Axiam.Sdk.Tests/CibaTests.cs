using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CIBA — CONTRACT.md &#167;33.8's sixteen tests (t01–t16), with every <c>auth_req_id</c>,
/// notification token, client secret and signing key generated at run time.
/// </summary>
public sealed class CibaTests : IDisposable
{
    private const string BcPath = "/oauth2/bc-authorize";
    private const string TokenPath = "/oauth2/token";
    private const string ClientId = "ciba-teller";

    private static readonly string Origin = OidcTestKit.BaseUrl.ToString().TrimEnd('/');

    private readonly CapturingHandler _handler = new();
    private readonly JwksFixture _jwks = new();
    private readonly string _secret = Secrets.Fresh();
    private readonly List<AxiamClient> _clients = new();

    public CibaTests()
    {
        _handler.Map("GET", "/.well-known/openid-configuration", _ => CapturingHandler.Json(200, Discovery()));
        _handler.Map("GET", "/oauth2/jwks", _ => CapturingHandler.Json(200, _jwks.BuildJwksDocument()));
    }

    public void Dispose()
    {
        foreach (AxiamClient c in _clients)
        {
            c.Dispose();
        }
    }

    private static string Discovery(JsonObject? aliases = null, bool ciba = true)
    {
        JsonObject doc = JsonNode.Parse(OidcTestKit.DiscoveryJson(OidcTestKit.BaseUrl))!.AsObject();
        if (ciba)
        {
            doc["backchannel_authentication_endpoint"] = $"{Origin}{BcPath}";
            doc["backchannel_token_delivery_modes_supported"] = new JsonArray("poll", "ping");
            doc["backchannel_authentication_request_signing_alg_values_supported"] = new JsonArray("PS256", "ES256", "EdDSA");
            doc["backchannel_user_code_parameter_supported"] = false;
        }

        if (aliases is not null)
        {
            doc["mtls_endpoint_aliases"] = aliases.DeepClone();
        }

        return doc.ToJsonString();
    }

    private AxiamClient Client(bool secret = true, bool mtls = false)
    {
        var options = new AxiamClientOptions
        {
            BaseUrl = OidcTestKit.BaseUrl,
            TenantId = OidcTestKit.TenantGuid,
            OidcClientId = ClientId,
            OidcClientSecret = secret ? _secret : null,
        };
        if (mtls)
        {
            (byte[] cert, byte[] key) = SelfSignedIdentity();
            options = options with { ClientCertificatePem = cert, ClientKeyPem = key };
        }

        AxiamClient client = AxiamClient.CreateForTesting(OidcTestKit.BaseUrl, OidcTestKit.TenantGuid, options, _handler);
        _clients.Add(client);
        return client;
    }

    private static (byte[] Cert, byte[] Key) SelfSignedIdentity()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=ciba-teller", key, HashAlgorithmName.SHA256);
        using X509Certificate2 cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        return (Encoding.ASCII.GetBytes(cert.ExportCertificatePem()), Encoding.ASCII.GetBytes(key.ExportPkcs8PrivateKeyPem()));
    }

    private static CibaInitiateParams Request(CibaDelivery? delivery = null) => new()
    {
        Scope = "openid payments",
        Hint = CibaUserHint.LoginHint("alice"),
        Delivery = delivery ?? CibaDelivery.Poll,
    };

    private void MapInitiate(string authReqId, int expiresIn = 120, int? interval = 5) =>
        _handler.Map("POST", BcPath, _ =>
        {
            var body = new JsonObject { ["auth_req_id"] = authReqId, ["expires_in"] = expiresIn };
            if (interval is not null)
            {
                body["interval"] = interval;
            }

            return CapturingHandler.Json(200, body.ToJsonString());
        });

    private string Tokens() => OidcTestKit.TokenResponseJson(
        "at-" + Secrets.Fresh(),
        idToken: _jwks.SignIdToken(new
        {
            iss = Origin,
            sub = Guid.NewGuid().ToString(),
            aud = ClientId,
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            acr = "urn:axiam:acr:mfa",
        }));

    /// <summary>Answers the token endpoint from a script, one entry per request; the last repeats.</summary>
    private void ScriptToken(params Func<HttpResponseMessage>[] answers)
    {
        int n = 0;
        _handler.Map("POST", TokenPath, _ => answers[Math.Min(n++, answers.Length - 1)]());
    }

    private static HttpResponseMessage OAuth(int status, string error, string? description = null) =>
        CapturingHandler.Json(status, description is null
            ? $$"""{"error":"{{error}}"}"""
            : $$"""{"error":"{{error}}","error_description":"{{description}}"}""");

    private static CibaInitiateResponse Initiated(ManualCibaClock clock, long expiresIn = 120, long interval = 5) =>
        new(Sensitive<string>.Wrap(Secrets.Fresh()), expiresIn, interval, clock.UtcNow);

    // ── Initiation and polling ───────────────────────────────────────────────

    /// <summary>t01: the notification token and the auth_req_id are on the wire and in no rendering.</summary>
    [Fact]
    public async Task T01_TheValuesAreOnTheWireAndInNoRendering()
    {
        string notification = Secrets.Fresh();
        string authReqId = Secrets.Fresh();
        AxiamClient client = Client();
        MapInitiate(authReqId);

        CibaInitiateResponse initiated = await client.CibaInitiateAsync(Request(CibaDelivery.Ping(Sensitive<string>.Wrap(notification))));
        Assert.Equal(notification, _handler.To(BcPath)[0].Form()["client_notification_token"]);
        Assert.Equal(authReqId, initiated.AuthReqId.Expose());

        ScriptToken(() => CapturingHandler.Json(200, Tokens()));
        await client.CibaPollAsync(new CibaPollParams(initiated.AuthReqId));
        Assert.Equal(authReqId, _handler.To(TokenPath)[0].Form()["auth_req_id"]);

        CibaDelivery ping = CibaDelivery.Ping(Sensitive<string>.Wrap(notification));
        foreach ((string label, string rendering) in new[]
                 {
                     ("response ToString", initiated.ToString()),
                     ("response Json", JsonSerializer.Serialize(initiated)),
                     ("delivery ToString", ping.ToString()),
                     ("delivery Json", JsonSerializer.Serialize(ping)),
                     ("poll params", new CibaPollParams(initiated.AuthReqId).ToString()),
                 })
        {
            Secrets.AssertAbsent(rendering, authReqId, label);
            Secrets.AssertAbsent(rendering, notification, label);
        }

        _handler.Map("POST", BcPath, _ => OAuth(400, "invalid_request", "bad hint"));
        OAuthProtocolError e = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.CibaInitiateAsync(Request(CibaDelivery.Ping(Sensitive<string>.Wrap(notification)))));
        Secrets.AssertAbsent(e.ToString(), notification, "error rendering");
        Secrets.AssertAbsent(e.ToString(), _secret, "error rendering");
    }

    /// <summary>t02: no credential is refused locally; one is sent on initiate and poll; tenant_id in the query only.</summary>
    [Fact]
    public async Task T02_ClientAuthenticationIsMandatory()
    {
        AxiamClient anonymous = Client(secret: false);
        await Assert.ThrowsAsync<AuthError>(() => anonymous.CibaInitiateAsync(Request()));
        await Assert.ThrowsAsync<AuthError>(() => anonymous.CibaPollAsync(new CibaPollParams(Sensitive<string>.Wrap(Secrets.Fresh()))));
        Assert.Empty(_handler.Requests);

        AxiamClient client = Client();
        MapInitiate(Secrets.Fresh());
        ScriptToken(() => CapturingHandler.Json(200, Tokens()));
        CibaInitiateResponse initiated = await client.CibaInitiateAsync(Request());
        await client.CibaPollAsync(new CibaPollParams(initiated.AuthReqId));
        foreach (CapturingHandler.Captured sent in _handler.To(BcPath).Concat(_handler.To(TokenPath)))
        {
            Dictionary<string, string> form = sent.Form();
            Assert.Equal(ClientId, form["client_id"]);
            Assert.Equal(_secret, form["client_secret"]);
            Assert.False(form.ContainsKey("tenant_id"));
            Assert.Equal(OidcTestKit.TenantGuid, sent.Query()["tenant_id"]);
            Assert.Equal(OidcTestKit.TenantGuid, Assert.Single(sent.Header("X-Tenant-Id")));
        }

        Assert.Equal(CibaGrant, _handler.To(TokenPath)[0].Form()["grant_type"]);

        // tls_client_auth: an mTLS client with no secret sends client_id only.
        _handler.Requests.Clear();
        AxiamClient mtls = Client(secret: false, mtls: true);
        await mtls.CibaInitiateAsync(Request());
        Dictionary<string, string> mtlsForm = _handler.To(BcPath)[0].Form();
        Assert.Equal(ClientId, mtlsForm["client_id"]);
        Assert.False(mtlsForm.ContainsKey("client_secret"));
    }

    private const string CibaGrant = "urn:openid:params:grant-type:ciba";

    /// <summary>t03: exactly the members set are sent; no member exists for the refused parameters; ping needs a token.</summary>
    [Fact]
    public async Task T03_ExactlyTheMembersSetAreSent()
    {
        AxiamClient client = Client();
        MapInitiate(Secrets.Fresh());

        await client.CibaInitiateAsync(Request());
        Assert.Equal(
            new[] { "client_id", "client_secret", "login_hint", "scope" },
            _handler.To(BcPath)[0].Form().Keys.OrderBy(k => k, StringComparer.Ordinal));

        await client.CibaInitiateAsync(new CibaInitiateParams
        {
            Scope = "openid",
            Hint = CibaUserHint.IdTokenHint("id." + Secrets.Fresh()),
            BindingMessage = "Pay 42 EUR to ACME",
            RequestedExpiry = 120,
            AcrValues = "urn:axiam:acr:mfa",
            Resource = "https://payments.example",
        });
        Dictionary<string, string> full = _handler.To(BcPath)[1].Form();
        Assert.Equal(
            new[] { "acr_values", "binding_message", "client_id", "client_secret", "id_token_hint", "requested_expiry", "resource", "scope" },
            full.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal("120", full["requested_expiry"]);
        Assert.Equal("Pay 42 EUR to ACME", full["binding_message"]);

        foreach (string forbidden in new[] { "LoginHintToken", "UserCode", "RequestUri", "ExtraParams" })
        {
            Assert.Null(typeof(CibaInitiateParams).GetProperty(forbidden));
        }

        Assert.Empty(typeof(CibaUserHint).GetConstructors());
        await Assert.ThrowsAsync<ValidationError>(() => client.CibaInitiateAsync(Request(CibaDelivery.Ping(Sensitive<string>.Wrap(string.Empty)))));
        await Assert.ThrowsAsync<ValidationError>(() => client.CibaInitiateAsync(Request(CibaDelivery.Ping(default))));
        await Assert.ThrowsAsync<ValidationError>(() => client.CibaInitiateAsync(new CibaInitiateParams { Scope = string.Empty, Hint = CibaUserHint.LoginHint("a") }));
        await Assert.ThrowsAsync<ValidationError>(() => client.CibaInitiateAsync(new CibaInitiateParams { Scope = "openid", Hint = null! }));
        Assert.Equal(2, _handler.To(BcPath).Count);
    }

    /// <summary>t04: initiate is sent once on a 503, a 429 and a dropped connection (retry-enabled client).</summary>
    [Fact]
    public async Task T04_InitiateIsNeverRetried()
    {
        AxiamClient client = Client();
        _handler.Map("POST", BcPath, _ => CapturingHandler.Status(503));
        await Assert.ThrowsAsync<NetworkError>(() => client.CibaInitiateAsync(Request()));
        Assert.Single(_handler.To(BcPath));

        _handler.Map("POST", BcPath, _ => OAuth(429, "rate_limit_exceeded"));
        OAuthProtocolError limited = await Assert.ThrowsAsync<OAuthProtocolError>(() => client.CibaInitiateAsync(Request()));
        Assert.Equal("rate_limit_exceeded", limited.Error);
        Assert.Equal(2, _handler.To(BcPath).Count);

        _handler.Map("POST", BcPath, _ => throw new HttpRequestException("connection reset by peer"));
        await Assert.ThrowsAsync<NetworkError>(() => client.CibaInitiateAsync(Request()));
        Assert.Equal(3, _handler.To(BcPath).Count);

        _handler.Map("POST", BcPath, _ => CapturingHandler.Status(429));
        await Assert.ThrowsAsync<NetworkError>(() => client.CibaInitiateAsync(Request()));
        Assert.Equal(4, _handler.To(BcPath).Count);
    }

    /// <summary>t05: pending loops, slow_down persists, and the terminal answers are distinct.</summary>
    [Fact]
    public async Task T05_PollOutcomes()
    {
        AxiamClient client = Client();
        var clock = new ManualCibaClock();
        ScriptToken(
            () => OAuth(400, "slow_down"),
            () => OAuth(400, "slow_down"),
            () => OAuth(400, "authorization_pending"),
            () => CapturingHandler.Json(200, Tokens()));
        OidcTokenSet tokens = await client.CibaAwaitAsync(Initiated(clock), new CibaAwaitParams(Clock: clock));
        Assert.NotNull(tokens.IdToken);
        Assert.Equal(new double[] { 5, 10, 15, 15 }, clock.Sleeps.Select(s => s.TotalSeconds));
        Assert.Equal(4, _handler.To(TokenPath).Count);

        foreach (string terminal in new[] { "access_denied", "expired_token", "invalid_grant", "something_new" })
        {
            _handler.Requests.Clear();
            ScriptToken(() => OAuth(400, terminal, "decided"));
            var c = new ManualCibaClock();
            OAuthProtocolError e = await Assert.ThrowsAsync<OAuthProtocolError>(
                () => client.CibaAwaitAsync(Initiated(c), new CibaAwaitParams(Clock: c)));
            Assert.Equal(terminal, e.Error);
            Assert.Equal(terminal == "access_denied", e.IsAccessDenied);
            Assert.Equal(terminal == "expired_token", e.IsExpiredToken);
            Assert.Single(_handler.To(TokenPath));
        }
    }

    /// <summary>t06: the first poll waits the response's interval (7), or 5 when it is absent.</summary>
    [Fact]
    public async Task T06_TheFirstPollWaits()
    {
        AxiamClient client = Client();
        foreach ((int? sent, double expected) in new (int?, double)[] { (7, 7), (null, 5), (0, 5) })
        {
            _handler.Requests.Clear();
            MapInitiate(Secrets.Fresh(), interval: sent);
            CibaInitiateResponse initiated = await client.CibaInitiateAsync(Request());
            Assert.Equal((long)expected, initiated.Interval);

            var clock = new ManualCibaClock(initiated.ReceivedAt);
            int requestsAtFirstSleep = -1;
            clock.OnSleep = () => requestsAtFirstSleep = requestsAtFirstSleep < 0 ? _handler.To(TokenPath).Count : requestsAtFirstSleep;
            ScriptToken(() => CapturingHandler.Json(200, Tokens()));
            await client.CibaAwaitAsync(initiated, new CibaAwaitParams(Clock: clock));
            Assert.Equal(expected, clock.Sleeps[0].TotalSeconds);
            Assert.Equal(0, requestsAtFirstSleep);
        }
    }

    /// <summary>t07: no request after expires_in; expired_token raised locally.</summary>
    [Fact]
    public async Task T07_TheDeadlineIsLocal()
    {
        AxiamClient client = Client();
        var clock = new ManualCibaClock();
        var times = new List<double>();
        DateTimeOffset start = clock.UtcNow;
        _handler.Map("POST", TokenPath, _ =>
        {
            times.Add((clock.UtcNow - start).TotalSeconds);
            return OAuth(400, "authorization_pending");
        });
        OAuthProtocolError e = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.CibaAwaitAsync(Initiated(clock, expiresIn: 12, interval: 5), new CibaAwaitParams(Clock: clock)));
        Assert.True(e.IsExpiredToken);
        Assert.Equal(new double[] { 5, 10 }, times);
    }

    /// <summary>t08: a 500 and a 429 mid-loop are survived; the 200 carries its ID token and access token.</summary>
    [Fact]
    public async Task T08_TransientFailuresAreNotTerminal()
    {
        AxiamClient client = Client();
        var clock = new ManualCibaClock();
        string tokens = Tokens();
        ScriptToken(
            () => OAuth(400, "authorization_pending"),
            () => CapturingHandler.Status(500),
            () => OAuth(429, "rate_limit_exceeded"),
            () => CapturingHandler.Status(429),
            () => CapturingHandler.Json(200, tokens));
        OidcTokenSet set = await client.CibaAwaitAsync(Initiated(clock), new CibaAwaitParams(Clock: clock));
        Assert.StartsWith("at-", set.AccessToken.Expose(), StringComparison.Ordinal);
        Assert.NotNull(set.IdToken);
        Assert.False(string.IsNullOrEmpty(set.IdClaims!.Sub));
        Assert.Equal(5, _handler.To(TokenPath).Count);
    }

    /// <summary>t09: a second poll after the 200 is invalid_grant and not retried.</summary>
    [Fact]
    public async Task T09_ARequestIsRedeemedOnce()
    {
        AxiamClient client = Client();
        ScriptToken(() => CapturingHandler.Json(200, Tokens()), () => OAuth(400, "invalid_grant"));
        var id = Sensitive<string>.Wrap(Secrets.Fresh());
        await client.CibaPollAsync(new CibaPollParams(id));
        OAuthProtocolError e = await Assert.ThrowsAsync<OAuthProtocolError>(() => client.CibaPollAsync(new CibaPollParams(id)));
        Assert.Equal("invalid_grant", e.Error);
        Assert.Equal(2, _handler.To(TokenPath).Count);
    }

    // ── The ping ─────────────────────────────────────────────────────────────

    private static KeyValuePair<string, string> H(string name, string value) => new(name, value);

    /// <summary>t10: a valid ping returns its auth_req_id, Sensitive, in any scheme case.</summary>
    [Fact]
    public void T10_AValidPingReturnsItsId()
    {
        AxiamClient client = Client();
        string token = Secrets.Fresh();
        string id = Secrets.Fresh();
        foreach (string scheme in new[] { "Bearer", "bearer", "BEARER" })
        {
            Sensitive<string> got = client.CibaHandlePing(
                new[] { H("Content-Type", "application/json"), H("authorization", $"{scheme} {token}") },
                $$"""{"auth_req_id":"{{id}}"}""",
                Sensitive<string>.Wrap(token));
            Assert.Equal(id, got.Expose());
            Assert.Equal("[SENSITIVE]", got.ToString());
        }

        Sensitive<string> fromBytes = client.CibaHandlePing(
            new[] { H("Authorization", $"Bearer {token}") }, Encoding.UTF8.GetBytes($$"""{"auth_req_id":"{{id}}"}"""), Sensitive<string>.Wrap(token));
        Assert.Equal(id, fromBytes.Expose());
    }

    /// <summary>t11: wrong, absent, empty, duplicated, Basic, last-character and double-space bearers are refused; constant-time compare.</summary>
    [Fact]
    public void T11_ABadAuthorizationIsRefused()
    {
        AxiamClient client = Client();
        string token = Secrets.Fresh();
        string body = $$"""{"auth_req_id":"{{Secrets.Fresh()}}"}""";
        string lastDiffers = token[..^1] + (token[^1] == 'A' ? 'B' : 'A');
        KeyValuePair<string, string>[][] cases =
        {
            new[] { H("Authorization", $"Bearer {Secrets.Fresh()}") },
            Array.Empty<KeyValuePair<string, string>>(),
            new[] { H("Authorization", string.Empty) },
            new[] { H("Authorization", "Bearer ") },
            new[] { H("Authorization", $"Bearer {token}"), H("authorization", $"Bearer {token}") },
            new[] { H("Authorization", $"Basic {token}") },
            new[] { H("Authorization", $"Bearer {lastDiffers}") },
            new[] { H("Authorization", $"Bearer  {token}") },
            new[] { H("Authorization", token) },
        };
        foreach (KeyValuePair<string, string>[] headers in cases)
        {
            AuthError e = Assert.Throws<AuthError>(() => client.CibaHandlePing(headers, body, Sensitive<string>.Wrap(token)));
            Secrets.AssertAbsent(e.Message, token, "ping refusal");
        }

        Assert.Throws<AuthError>(() => client.CibaHandlePing(new[] { H("Authorization", $"Bearer {token}") }, body, Sensitive<string>.Wrap(string.Empty)));

        // Structural: the comparison is the BCL's constant-time one.
        string source = File.ReadAllText(Path.Combine(RepoRoot(), "Axiam.Sdk", "AxiamClient.Ciba.cs"));
        int start = source.IndexOf("public Sensitive<string> CibaHandlePing(", StringComparison.Ordinal);
        int end = source.IndexOf("static ValidationError Malformed()", start, StringComparison.Ordinal);
        Assert.Contains("CryptographicOperations.FixedTimeEquals(presented, expected)", source[start..end], StringComparison.Ordinal);
        Assert.DoesNotContain("SequenceEqual", source[start..end], StringComparison.Ordinal);
        Assert.DoesNotContain("expectedToken.Reveal() ==", source[start..end], StringComparison.Ordinal);
    }

    /// <summary>t12: a malformed body is a ValidationError; extra members are ignored.</summary>
    [Fact]
    public void T12_AMalformedBodyIsAValidationError()
    {
        AxiamClient client = Client();
        string token = Secrets.Fresh();
        var headers = new[] { H("Authorization", $"Bearer {token}") };
        foreach (string body in new[] { "not json", "{}", """{"auth_req_id":5}""", """{"auth_req_id":""}""", "[]", """{"auth_req_id":null}""", string.Empty })
        {
            Assert.Throws<ValidationError>(() => client.CibaHandlePing(headers, body, Sensitive<string>.Wrap(token)));
        }

        Assert.Throws<ValidationError>(() => client.CibaHandlePing(headers, new byte[] { 0xff, 0xfe }, Sensitive<string>.Wrap(token)));
        string id = Secrets.Fresh();
        Assert.Equal(id, client.CibaHandlePing(headers, $$"""{"auth_req_id":"{{id}}","status":"approved","x":[1]}""", Sensitive<string>.Wrap(token)).Expose());
    }

    /// <summary>t13: the ping helper makes no network call — the transport fails the test if touched.</summary>
    [Fact]
    public void T13_ThePingHelperMakesNoNetworkCall()
    {
        var tripwire = new TripwireHandler();
        using AxiamClient client = AxiamClient.CreateForTesting(OidcTestKit.BaseUrl, OidcTestKit.TenantGuid, new AxiamClientOptions
        {
            BaseUrl = OidcTestKit.BaseUrl,
            TenantId = OidcTestKit.TenantGuid,
            OidcClientId = ClientId,
            OidcClientSecret = _secret,
        }, tripwire);
        string token = Secrets.Fresh();
        client.CibaHandlePing(new[] { H("Authorization", $"Bearer {token}") }, """{"auth_req_id":"x1"}""", Sensitive<string>.Wrap(token));
        Assert.Throws<AuthError>(() => client.CibaHandlePing(Array.Empty<KeyValuePair<string, string>>(), "{}", Sensitive<string>.Wrap(token)));
        Assert.Throws<ValidationError>(() => client.CibaHandlePing(new[] { H("Authorization", $"Bearer {token}") }, "{}", Sensitive<string>.Wrap(token)));
        Assert.Equal(0, tripwire.Calls);
    }

    // ── The signed form ──────────────────────────────────────────────────────

    private static (string Pem, Func<byte[], byte[], bool> Verify) EdKey()
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
        byte[] der = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetEncoded();
        string pem = $"-----BEGIN PRIVATE KEY-----\n{Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)}\n-----END PRIVATE KEY-----\n";
        var pub = (Ed25519PublicKeyParameters)pair.Public;
        return (pem, (input, sig) =>
        {
            var v = new Ed25519Signer();
            v.Init(false, pub);
            v.BlockUpdate(input, 0, input.Length);
            return v.VerifySignature(sig);
        });
    }

    private static (string Pem, Func<byte[], byte[], bool> Verify) EcKey()
    {
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (ec.ExportPkcs8PrivateKeyPem(), (input, sig) => ec.VerifyData(input, sig, HashAlgorithmName.SHA256));
    }

    private static (string Pem, Func<byte[], byte[], bool> Verify) RsaKey()
    {
        var rsa = RSA.Create(2048);
        return (rsa.ExportPkcs8PrivateKeyPem(), (input, sig) => rsa.VerifyData(input, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    private static byte[] Unb64(string s)
    {
        string p = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(p + ((p.Length % 4) switch { 2 => "==", 3 => "=", _ => string.Empty }));
    }

    /// <summary>t14: the signed request is one member, under the caller's algorithm, with fresh jti — EdDSA, ES256 and PS256.</summary>
    [Fact]
    public async Task T14_TheSignedRequestIsOneMemberWithTheRegisteredAlg()
    {
        AxiamClient client = Client();
        MapInitiate(Secrets.Fresh());
        foreach ((CibaSigningAlg alg, string jose, (string Pem, Func<byte[], byte[], bool> Verify) key) in new[]
                 {
                     (CibaSigningAlg.EdDSA, "EdDSA", EdKey()),
                     (CibaSigningAlg.ES256, "ES256", EcKey()),
                     (CibaSigningAlg.PS256, "PS256", RsaKey()),
                 })
        {
            _handler.Requests.Clear();
            CibaRequestSigner signer = CibaRequestSigner.FromPem(alg, Sensitive<string>.Wrap(key.Pem), kid: "k-" + jose);
            string notification = Secrets.Fresh();
            var request = new CibaInitiateParams
            {
                Scope = "openid",
                Hint = CibaUserHint.LoginHint("alice"),
                BindingMessage = "Pay 42",
                RequestedExpiry = 120,
                Delivery = CibaDelivery.Ping(Sensitive<string>.Wrap(notification)),
                Signer = signer,
            };
            await client.CibaInitiateAsync(request);
            await client.CibaInitiateAsync(request);

            var jtis = new List<string>();
            foreach (CapturingHandler.Captured sent in _handler.To(BcPath))
            {
                Dictionary<string, string> form = sent.Form();
                Assert.Equal(new[] { "client_id", "client_secret", "request" }, form.Keys.OrderBy(k => k, StringComparer.Ordinal));
                string[] parts = form["request"].Split('.');
                using JsonDocument header = JsonDocument.Parse(Unb64(parts[0]));
                using JsonDocument claims = JsonDocument.Parse(Unb64(parts[1]));
                Assert.Equal(jose, header.RootElement.GetProperty("alg").GetString());
                Assert.Equal("k-" + jose, header.RootElement.GetProperty("kid").GetString());
                Assert.True(key.Verify(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), Unb64(parts[2])), $"{jose} signature verifies with the public key");

                JsonElement c = claims.RootElement;
                Assert.Equal(ClientId, c.GetProperty("iss").GetString());
                Assert.Equal(Origin, c.GetProperty("aud").GetString());
                long iat = c.GetProperty("iat").GetInt64();
                long nbf = c.GetProperty("nbf").GetInt64();
                long exp = c.GetProperty("exp").GetInt64();
                Assert.Equal(iat, nbf);
                Assert.True(exp - nbf is > 0 and <= 3600);
                Assert.True(Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - iat) < 60);
                Assert.Equal(JsonValueKind.Number, c.GetProperty("requested_expiry").ValueKind);
                Assert.Equal(120, c.GetProperty("requested_expiry").GetInt32());
                Assert.Equal("openid", c.GetProperty("scope").GetString());
                Assert.Equal("alice", c.GetProperty("login_hint").GetString());
                Assert.Equal("Pay 42", c.GetProperty("binding_message").GetString());
                Assert.Equal(notification, c.GetProperty("client_notification_token").GetString());
                string jti = c.GetProperty("jti").GetString()!;
                Assert.True(jti.Length >= 32);
                jtis.Add(jti);
            }

            Assert.Equal(2, jtis.Distinct().Count());
            Assert.Equal(alg, signer.Alg);
        }
    }

    /// <summary>t15: no key, or a key for another algorithm, is refused before any request.</summary>
    [Fact]
    public void T15_NoKeyOrAKeyForAnotherAlgIsRefused()
    {
        foreach (CibaSigningAlg alg in Enum.GetValues<CibaSigningAlg>())
        {
            Assert.Throws<ValidationError>(() => CibaRequestSigner.FromPem(alg, Sensitive<string>.Wrap(string.Empty)));
            Assert.Throws<ValidationError>(() => CibaRequestSigner.FromPem(alg, default));
            Assert.Throws<ValidationError>(() => CibaRequestSigner.FromPem(alg, Sensitive<string>.Wrap("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")));
        }

        Assert.Throws<ValidationError>(() => CibaRequestSigner.FromPem(CibaSigningAlg.ES256, Sensitive<string>.Wrap(RsaKey().Pem)));
        Assert.Throws<ValidationError>(() => CibaRequestSigner.FromPem(CibaSigningAlg.EdDSA, Sensitive<string>.Wrap(EcKey().Pem)));
        Assert.Throws<ValidationError>(() => CibaRequestSigner.FromPem(CibaSigningAlg.PS256, Sensitive<string>.Wrap(EdKey().Pem)));
        Assert.Throws<ValidationError>(() => CibaRequestSigner.FromPem(CibaSigningAlg.PS256, Sensitive<string>.Wrap(RSA.Create(1024).ExportPkcs8PrivateKeyPem())));
        Assert.Throws<ValidationError>(() => CibaRequestSigner.FromPem(CibaSigningAlg.ES256, Sensitive<string>.Wrap(ECDsa.Create(ECCurve.NamedCurves.nistP384).ExportPkcs8PrivateKeyPem())));
        Assert.Throws<ValidationError>(() => CibaRequestSigner.FromPem((CibaSigningAlg)42, Sensitive<string>.Wrap(EcKey().Pem)));
        Assert.Empty(_handler.Requests);
        // No algorithm default: FromPem takes the algorithm as a required argument.
        Assert.All(typeof(CibaRequestSigner).GetMethod("FromPem")!.GetParameters().Take(2), p => Assert.False(p.HasDefaultValue));
    }

    /// <summary>t16: the key material and the request string appear in no rendering.</summary>
    [Fact]
    public async Task T16_TheKeyAndTheRequestAppearInNoRendering()
    {
        AxiamClient client = Client();
        (string pem, _) = EcKey();
        string keyBody = pem.Replace("-----BEGIN PRIVATE KEY-----", string.Empty).Replace("-----END PRIVATE KEY-----", string.Empty).Replace("\n", string.Empty);
        CibaRequestSigner signer = CibaRequestSigner.FromPem(CibaSigningAlg.ES256, Sensitive<string>.Wrap(pem));
        _handler.Map("POST", BcPath, _ => OAuth(400, "invalid_request", "request refused"));
        var request = new CibaInitiateParams { Scope = "openid", Hint = CibaUserHint.LoginHint("alice"), Signer = signer };
        OAuthProtocolError e = await Assert.ThrowsAsync<OAuthProtocolError>(() => client.CibaInitiateAsync(request));
        string sentRequest = _handler.To(BcPath)[0].Form()["request"];
        string signature = sentRequest.Split('.')[2];

        foreach ((string label, string rendering) in new[]
                 {
                     ("signer ToString", signer.ToString()),
                     ("signer Json", JsonSerializer.Serialize(signer)),
                     ("params ToString", request.ToString()!),
                     ("error", e.ToString()),
                 })
        {
            Secrets.AssertAbsent(rendering, keyBody, label);
            Secrets.AssertAbsent(rendering, signature, label);
        }

        Assert.Contains("ES256", signer.ToString(), StringComparison.Ordinal);
    }

    // ── Discovery and §21.3.1 ────────────────────────────────────────────────

    /// <summary>No backchannel endpoint in discovery → AuthError, nothing sent; the four members decode.</summary>
    [Fact]
    public async Task AServerWithoutCibaIsReportedAndTheDiscoveryMembersDecode()
    {
        AxiamClient client = Client();
        OidcConfiguration configuration = await client.OidcDiscoverAsync();
        Assert.Equal($"{Origin}{BcPath}", configuration.BackchannelAuthenticationEndpoint);
        Assert.Equal(new[] { "poll", "ping" }, configuration.BackchannelTokenDeliveryModesSupported);
        Assert.Equal(new[] { "PS256", "ES256", "EdDSA" }, configuration.BackchannelAuthenticationRequestSigningAlgValuesSupported);
        Assert.False(configuration.BackchannelUserCodeParameterSupported);

        OidcConfiguration withoutCiba = JsonSerializer.Deserialize<OidcConfiguration>(Discovery(ciba: false))!;
        AuthError err = await Assert.ThrowsAsync<AuthError>(() => client.CibaInitiateAsync(new CibaInitiateParams
        {
            Scope = "openid",
            Hint = CibaUserHint.LoginHint("alice"),
            Configuration = withoutCiba,
        }));
        Assert.Contains("does not support CIBA", err.Message, StringComparison.Ordinal);
        Assert.Empty(_handler.To(BcPath));
    }

    /// <summary>&#167;21.3.1 vector A: an mTLS CIBA call goes to the alias; a non-mTLS one does not.</summary>
    [Fact]
    public async Task OnMtlsTheBackchannelEndpointIsTheAlias()
    {
        var aliases = new JsonObject
        {
            ["token_endpoint"] = $"https://mtls.axiam.test{TokenPath}",
            ["backchannel_authentication_endpoint"] = $"https://mtls.axiam.test{BcPath}?tenant_id={OidcTestKit.TenantGuid}",
        };
        _handler.Map("GET", "/.well-known/openid-configuration", _ => CapturingHandler.Json(200, Discovery(aliases)));
        MapInitiate(Secrets.Fresh());
        ScriptToken(() => CapturingHandler.Json(200, Tokens()));

        AxiamClient mtls = Client(mtls: true);
        CibaInitiateResponse initiated = await mtls.CibaInitiateAsync(Request());
        await mtls.CibaPollAsync(new CibaPollParams(initiated.AuthReqId));
        Assert.Equal("mtls.axiam.test", _handler.To(BcPath)[0].Uri.Host);
        Assert.Equal($"?tenant_id={OidcTestKit.TenantGuid}", _handler.To(BcPath)[0].Uri.Query);
        Assert.Equal("mtls.axiam.test", _handler.To(TokenPath)[0].Uri.Host);

        _handler.Requests.Clear();
        AxiamClient plain = Client();
        await plain.CibaInitiateAsync(Request());
        Assert.Equal("axiam.test", _handler.To(BcPath)[0].Uri.Host);
    }

    /// <summary>
    /// R-16 / CS-01 (CONTRACT.md &#167;34.2 P11, &#167;33.4, &#167;33.7 rule 1): under a tenant-path
    /// issuer the endpoints are <c>/t/{tenant_id}/oauth2/…</c>, and a <c>401</c> there with a live
    /// session is no session expiry either. It must not enter the &#167;9 guard — which would
    /// refresh and <b>re-send</b> the initiate — nor, on the CIBA grant, refresh anything.
    /// </summary>
    [Fact]
    public async Task ATenantPath401NeverEntersTheRefreshGuardOrResendsTheInitiate()
    {
        string tenantBc = $"/t/{OidcTestKit.TenantGuid}{BcPath}";
        string tenantToken = $"/t/{OidcTestKit.TenantGuid}{TokenPath}";
        JsonObject doc = JsonNode.Parse(Discovery())!.AsObject();
        doc["issuer"] = $"{Origin}/t/{OidcTestKit.TenantGuid}";
        doc["token_endpoint"] = $"{Origin}{tenantToken}";
        doc["backchannel_authentication_endpoint"] = $"{Origin}{tenantBc}";
        _handler.Map("GET", "/.well-known/openid-configuration", _ => CapturingHandler.Json(200, doc.ToJsonString()));
        _handler.Map("POST", tenantBc, _ => OAuth(401, "invalid_client", "client authentication failed"));
        _handler.Map("POST", tenantToken, _ => OAuth(401, "invalid_client", "client authentication failed"));
        // A refresh that succeeds: were the 401 to enter §9, the handler would re-send.
        _handler.Map("POST", "/api/v1/auth/refresh", _ => CapturingHandler.Json(200, "{}"));

        AxiamClient client = Client();
        SeedLiveSession(client);

        OAuthProtocolError initiate = await Assert.ThrowsAsync<OAuthProtocolError>(() => client.CibaInitiateAsync(Request()));
        Assert.Equal("invalid_client", initiate.Error);
        Assert.Single(_handler.To(tenantBc));

        OAuthProtocolError poll = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.CibaPollAsync(new CibaPollParams(Sensitive<string>.Wrap(Secrets.Fresh()))));
        Assert.Equal("invalid_client", poll.Error);
        Assert.Single(_handler.To(tenantToken));

        Assert.Empty(_handler.To("/api/v1/auth/refresh"));
    }

    /// <summary>Seeds a live, resolvable session cookie, the condition under which a non-exempt 401 refreshes.</summary>
    private static void SeedLiveSession(AxiamClient client)
    {
        FieldInfo field = typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var container = (CookieContainer)field.GetValue(client)!;
        static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string header = B64(Encoding.UTF8.GetBytes("""{"alg":"none"}"""));
        string body = B64(JsonSerializer.SerializeToUtf8Bytes(new
        {
            tenant_id = OidcTestKit.TenantGuid,
            org_id = Guid.NewGuid().ToString(),
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
        }));
        container.Add(OidcTestKit.BaseUrl, new Cookie("axiam_access", $"{header}.{body}.unsigned"));
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "CONTRACT.md")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("repository root (CONTRACT.md) not found");
    }

    /// <summary>A transport that counts every call — a call is a test failure.</summary>
    private sealed class TripwireHandler : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException("the ping helper must not touch the network");
        }
    }
}

/// <summary>A CIBA clock that records the sleeps and moves time by them, without waiting.</summary>
public sealed class ManualCibaClock : ICibaClock
{
    /// <summary>A clock starting now, or at <paramref name="start"/>.</summary>
    public ManualCibaClock(DateTimeOffset? start = null) => UtcNow = start ?? DateTimeOffset.UtcNow;

    /// <inheritdoc />
    public DateTimeOffset UtcNow { get; private set; }

    /// <summary>Every sleep, in order.</summary>
    public List<TimeSpan> Sleeps { get; } = new();

    /// <summary>Runs before each sleep is recorded.</summary>
    public Action? OnSleep { get; set; }

    /// <inheritdoc />
    public Task SleepAsync(TimeSpan duration, CancellationToken cancellationToken)
    {
        OnSleep?.Invoke();
        Sleeps.Add(duration);
        UtcNow += duration;
        return Task.CompletedTask;
    }
}
