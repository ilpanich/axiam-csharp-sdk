using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;37 (contract 1.65) &#8212; native sign-in with a provider ID token. The test names
/// are &#167;37.9's, in this language's casing, so the eleven SDKs' suites can be compared.
/// </summary>
[Trait("Category", "Fast")]
public class NativeLoginTests
{
    private const string TokenPath = "/oauth2/token";
    private const string Grant = "urn:axiam:params:oauth:grant-type:provider-id-token";
    private const string FixtureNonce = "n-0S6_WzA2Mj";
    private const string FixtureNonceHash = "0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19";

    // Distinctive fixtures for the §37.2 rule 12 scan: neither may ever show up outside the request.
    private const string FixtureIdToken = "PROVIDER-ID-TOKEN-FIXTURE-aaa.bbb.ccc";
    private const string FixtureRawNonce = "RAW-NONCE-FIXTURE-0123456789";

    private static readonly OidcConfiguration Config = new(
        Issuer: "https://axiam.test",
        AuthorizationEndpoint: "https://axiam.test/oauth2/authorize",
        TokenEndpoint: "https://axiam.test/oauth2/token",
        UserinfoEndpoint: "https://axiam.test/oauth2/userinfo",
        JwksUri: "https://axiam.test/oauth2/jwks",
        RevocationEndpoint: "https://axiam.test/oauth2/revoke",
        IntrospectionEndpoint: "https://axiam.test/oauth2/introspect",
        ResponseTypesSupported: new[] { "code" },
        SubjectTypesSupported: new[] { "public" },
        IdTokenSigningAlgValuesSupported: new[] { "EdDSA" },
        ScopesSupported: new[] { "openid" },
        TokenEndpointAuthMethodsSupported: new[] { "client_secret_post" },
        ClaimsSupported: new[] { "sub" },
        GrantTypesSupported: new[] { "authorization_code", Grant });

    private static Sensitive<string> S(string value) => Sensitive<string>.Wrap(value);

    private static AxiamClient PublicClient(RoutingHandler handler, string tenantId = OidcTestKit.TenantGuid, TelemetryHook? hook = null) =>
        OidcTestKit.Client(handler, new AxiamClientOptions
        {
            BaseUrl = OidcTestKit.BaseUrl,
            TenantId = tenantId,
            OidcClientId = OidcTestKit.ClientId,
            OidcClientSecret = null,
            TelemetryHook = hook,
        }, tenantId);

    private static AxiamClient ConfidentialClient(RoutingHandler handler, TelemetryHook? hook = null) =>
        OidcTestKit.Client(handler, new AxiamClientOptions
        {
            BaseUrl = OidcTestKit.BaseUrl,
            TenantId = OidcTestKit.TenantGuid,
            OidcClientId = OidcTestKit.ClientId,
            OidcClientSecret = OidcTestKit.ClientSecret,
            TelemetryHook = hook,
        });

    private static void MapOk(RoutingHandler handler, string accessToken = "native-access", string? refresh = null, string? idToken = null, string tokenType = "Bearer") =>
        handler.Map(TokenPath, _ => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson(accessToken, refresh, idToken, tokenType)));

    private static HttpRequestMessage TheTokenRequest(RoutingHandler handler) =>
        handler.Requests.Single(r => r.RequestUri!.AbsolutePath == TokenPath);

    // -----------------------------------------------------------------
    // 1. request_body_exact
    // -----------------------------------------------------------------

    [Fact]
    public async Task RequestBodyExact()
    {
        using var handler = new RoutingHandler();
        MapOk(handler);
        using AxiamClient client = PublicClient(handler);

        await client.LoginWithProviderIdTokenAsync(
            "corp-okta", S("the.id.token"), S("raw-nonce"),
            scopes: new[] { "openid", "profile" }, resource: "https://api.example/", configuration: Config);

        HttpRequestMessage request = TheTokenRequest(handler);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("application/x-www-form-urlencoded", request.Content!.Headers.ContentType!.MediaType);
        Assert.Equal($"tenant_id={OidcTestKit.TenantGuid}", request.RequestUri!.Query.TrimStart('?'));
        Assert.False(request.Headers.Contains("Authorization"));
        Assert.False(request.Headers.Contains("Cookie"));
        Assert.False(request.Headers.Contains("X-CSRF-Token"));

        Dictionary<string, string> form = OidcTestKit.ReadForm(request);
        Assert.Equal(
            new[] { "client_id", "grant_type", "id_token", "nonce", "provider", "resource", "scope" },
            form.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray());
        Assert.Equal(Grant, form["grant_type"]);
        Assert.Equal(OidcTestKit.ClientId, form["client_id"]);
        Assert.Equal("corp-okta", form["provider"]);
        Assert.Equal("the.id.token", form["id_token"]);
        Assert.Equal("raw-nonce", form["nonce"]);
        Assert.Equal("openid profile", form["scope"]);
        Assert.Equal("https://api.example/", form["resource"]);
    }

    [Fact]
    public async Task RequestBodyExact_NoScopesNoResource_SendsNeitherKeyAndAddsNoOpenid()
    {
        using var handler = new RoutingHandler();
        MapOk(handler);
        using AxiamClient client = PublicClient(handler);

        await client.LoginWithProviderIdTokenAsync("corp-okta", S("the.id.token"), S("raw-nonce"), configuration: Config);

        string body = OidcTestKit.ReadRawBody(TheTokenRequest(handler));
        Dictionary<string, string> form = OidcTestKit.ReadForm(TheTokenRequest(handler));
        Assert.Equal(
            new[] { "client_id", "grant_type", "id_token", "nonce", "provider" },
            form.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray());
        Assert.DoesNotContain("openid", body);
        Assert.DoesNotContain("scope", body);

        // An empty list is "no scopes" too, and is never sent as `scope=`.
        using var handler2 = new RoutingHandler();
        MapOk(handler2);
        using AxiamClient client2 = PublicClient(handler2);
        await client2.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n"), scopes: Array.Empty<string>(), resource: "", configuration: Config);
        Assert.DoesNotContain("scope", OidcTestKit.ReadForm(TheTokenRequest(handler2)).Keys);
        Assert.DoesNotContain("resource", OidcTestKit.ReadForm(TheTokenRequest(handler2)).Keys);
    }

    // -----------------------------------------------------------------
    // 2. raw_nonce_sent_not_hash
    // -----------------------------------------------------------------

    [Fact]
    public async Task RawNonceSentNotHash()
    {
        using var handler = new RoutingHandler();
        // A fixture token whose payload carries the HASH, as the provider's token does.
        string payload = Convert.ToBase64String(Encoding.UTF8.GetBytes($$"""{"nonce":"{{FixtureNonceHash}}"}""")).TrimEnd('=');
        string idToken = $"e30.{payload}.c2ln";
        MapOk(handler);
        using AxiamClient client = PublicClient(handler);

        await client.LoginWithProviderIdTokenAsync("corp-okta", S(idToken), S(FixtureNonce), configuration: Config);

        HttpRequestMessage request = TheTokenRequest(handler);
        Assert.Equal(FixtureNonce, OidcTestKit.ReadForm(request)["nonce"]);
        string body = OidcTestKit.ReadRawBody(request);
        Assert.DoesNotContain(FixtureNonceHash, body, StringComparison.OrdinalIgnoreCase);
        // The only occurrence of the hash is inside the id_token's own (encoded) payload, never as a field.
        Assert.DoesNotContain("nonce=" + FixtureNonceHash, body, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(FixtureNonceHash, AxiamClient.HashNonce(FixtureNonce));
    }

    // -----------------------------------------------------------------
    // 3. provider_sent_verbatim
    // -----------------------------------------------------------------

    [Theory]
    [InlineData("0b5c2c1a-3a3c-4d7e-9a7f-5d1c1d9c4a11")]
    [InlineData("Corp-Okta")]
    [InlineData("google")]
    public async Task ProviderSentVerbatim(string provider)
    {
        using var handler = new RoutingHandler();
        MapOk(handler);
        using AxiamClient client = PublicClient(handler);

        await client.LoginWithProviderIdTokenAsync(provider, S("t"), S("n"), configuration: Config);

        Assert.Equal(provider, OidcTestKit.ReadForm(TheTokenRequest(handler))["provider"]);
        // One request in total: no sso_providers lookup, no discovery fetch.
        Assert.Single(handler.Requests);
    }

    // -----------------------------------------------------------------
    // 4. public_client_sends_client_id_only / confidential_client_sends_its_credential
    // -----------------------------------------------------------------

    [Fact]
    public async Task PublicClientSendsClientIdOnly()
    {
        using var handler = new RoutingHandler();
        MapOk(handler);
        using AxiamClient client = PublicClient(handler);

        await client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n"), configuration: Config);

        HttpRequestMessage request = TheTokenRequest(handler);
        Dictionary<string, string> form = OidcTestKit.ReadForm(request);
        Assert.Equal(OidcTestKit.ClientId, form["client_id"]);
        Assert.DoesNotContain("client_secret", form.Keys);
        Assert.DoesNotContain("client_assertion", form.Keys);
        Assert.False(request.Headers.Contains("Authorization"));
    }

    [Theory]
    [InlineData("client_secret_post")]
    [InlineData("client_secret_basic")]
    public async Task ConfidentialClientSendsItsCredential(string advertisedMethod)
    {
        using var handler = new RoutingHandler();
        MapOk(handler);
        using AxiamClient client = ConfidentialClient(handler);
        OidcConfiguration config = Config with { TokenEndpointAuthMethodsSupported = new[] { advertisedMethod } };

        await client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n"), configuration: config);

        HttpRequestMessage request = TheTokenRequest(handler);
        Assert.Equal(OidcTestKit.ClientSecret, OidcTestKit.ReadForm(request)["client_secret"]);
        // Never a Basic header, whichever method the mock names (§12.1 rule 3).
        Assert.False(request.Headers.Contains("Authorization"));
    }

    // -----------------------------------------------------------------
    // 5. empty_inputs_refused_locally
    // -----------------------------------------------------------------

    [Theory]
    [InlineData("", "t", "n")]
    [InlineData("p", "", "n")]
    [InlineData("p", "t", "")]
    public async Task EmptyInputsRefusedLocally(string provider, string idToken, string nonce)
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapOk(handler);
        using AxiamClient client = PublicClient(handler);

        // No Configuration passed: even the discovery fetch must not happen.
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.LoginWithProviderIdTokenAsync(provider, S(idToken), S(nonce)));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task EmptyInputsRefusedLocally_SlugOnlyClient()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        MapOk(handler);
        using AxiamClient client = PublicClient(handler, tenantId: "acme");

        await Assert.ThrowsAsync<AuthError>(() =>
            client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n")));

        Assert.Empty(handler.Requests);
    }

    // -----------------------------------------------------------------
    // 6. generic_invalid_grant_mapped
    // -----------------------------------------------------------------

    [Fact]
    public async Task GenericInvalidGrantMapped()
    {
        using var handler = new RoutingHandler();
        handler.Map(TokenPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.BadRequest,
            OidcTestKit.OAuth2ErrorJson("invalid_grant", "the provider ID token is not acceptable")));
        using AxiamClient client = PublicClient(handler);

        OAuthProtocolError ex = await Assert.ThrowsAsync<OAuthProtocolError>(() =>
            client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n"), configuration: Config));

        Assert.Equal("invalid_grant", ex.Error);
        Assert.Equal("the provider ID token is not acceptable", ex.ErrorDescription);
        Assert.Equal("invalid_grant: the provider ID token is not acceptable", ex.Message);
        // Exactly one request: no retry, no refresh, no re-send with a regenerated nonce.
        Assert.Equal(1, handler.CountFor(TokenPath));
        Assert.Single(handler.Requests);
        Assert.Equal(0, handler.CountFor("/api/v1/auth/refresh"));
    }

    // -----------------------------------------------------------------
    // 7. consent_required_mapped
    // -----------------------------------------------------------------

    [Fact]
    public async Task ConsentRequiredMapped()
    {
        using var handler = new RoutingHandler();
        handler.Map(TokenPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.BadRequest,
            OidcTestKit.OAuth2ErrorJson("consent_required", "the requested scope needs consent")));
        using AxiamClient client = PublicClient(handler);

        OAuthProtocolError ex = await Assert.ThrowsAsync<OAuthProtocolError>(() =>
            client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n"), scopes: new[] { "openid", "address" }, configuration: Config));

        Assert.Equal("consent_required", ex.Error);
        Assert.Single(handler.Requests); // nothing falls back to another grant
    }

    // -----------------------------------------------------------------
    // 8. client_and_scope_refusals_surfaced
    // -----------------------------------------------------------------

    [Theory]
    [InlineData(400, "unauthorized_client")]
    [InlineData(401, "invalid_client")]
    [InlineData(400, "invalid_scope")]
    [InlineData(400, "invalid_target")]
    public async Task ClientAndScopeRefusalsSurfaced(int status, string error)
    {
        using var handler = new RoutingHandler();
        handler.Map(TokenPath, _ =>
        {
            HttpResponseMessage response = OidcTestKit.JsonStatus((HttpStatusCode)status, OidcTestKit.OAuth2ErrorJson(error, "refused"));
            if (status == 401)
            {
                response.Headers.TryAddWithoutValidation("WWW-Authenticate", "Basic realm=\"axiam\"");
            }
            return response;
        });
        using AxiamClient client = PublicClient(handler);

        OAuthProtocolError ex = await Assert.ThrowsAsync<OAuthProtocolError>(() =>
            client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n"), scopes: new[] { "openid", "wide" }, configuration: Config));

        Assert.Equal(error, ex.Error);
        // One request each: invalid_scope is not narrowed and re-sent; the 401 does not enter §9.
        Assert.Single(handler.Requests);
        Assert.Equal(0, handler.CountFor("/api/v1/auth/refresh"));
    }

    // -----------------------------------------------------------------
    // 9. rate_limit_with_retry_after_mapped
    // -----------------------------------------------------------------

    [Fact]
    public async Task RateLimitWithRetryAfterMapped()
    {
        using var handler = new RoutingHandler();
        handler.Map(TokenPath, _ =>
        {
            HttpResponseMessage response = OidcTestKit.JsonStatus(
                (HttpStatusCode)429, OidcTestKit.OAuth2ErrorJson("rate_limit_exceeded", "slow down"));
            response.Headers.TryAddWithoutValidation("Retry-After", "7");
            return response;
        });
        using AxiamClient client = PublicClient(handler);

        OAuthProtocolError ex = await Assert.ThrowsAsync<OAuthProtocolError>(() =>
            client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n"), configuration: Config));

        Assert.Equal("rate_limit_exceeded", ex.Error);
        Assert.Equal(TimeSpan.FromSeconds(7), ex.RetryAfter);
        Assert.Equal(429, ex.HttpStatus);
        Assert.Single(handler.Requests);
    }

    // -----------------------------------------------------------------
    // 10. server_error_not_retried
    // -----------------------------------------------------------------

    [Fact]
    public async Task ServerErrorNotRetried()
    {
        // 500 WITH a well-formed body: dispatched on the body.
        using (var handler = new RoutingHandler())
        {
            handler.Map(TokenPath, _ => OidcTestKit.JsonStatus(
                HttpStatusCode.InternalServerError, OidcTestKit.OAuth2ErrorJson("server_error", "datastore unavailable")));
            using AxiamClient client = PublicClient(handler);

            OAuthProtocolError ex = await Assert.ThrowsAsync<OAuthProtocolError>(() =>
                client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n"), configuration: Config));
            Assert.Equal("server_error", ex.Error);
            Assert.Single(handler.Requests);
        }

        // 500 with no body: NetworkError.
        using (var handler = new RoutingHandler())
        {
            handler.Map(TokenPath, _ => OidcTestKit.Empty(HttpStatusCode.InternalServerError));
            using AxiamClient client = PublicClient(handler);

            await Assert.ThrowsAsync<NetworkError>(() =>
                client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n"), configuration: Config));
            Assert.Single(handler.Requests);
        }

        // A transport failure after the request is sent: NetworkError, one request.
        using (var handler = new RoutingHandler())
        {
            handler.Map(TokenPath, _ => throw new HttpRequestException("connection reset"));
            using AxiamClient client = PublicClient(handler);

            await Assert.ThrowsAsync<NetworkError>(() =>
                client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n"), configuration: Config));
            Assert.Single(handler.Requests);
        }
    }

    // -----------------------------------------------------------------
    // 11. result_is_the_ordinary_token_set
    // -----------------------------------------------------------------

    private static string SignedIdToken(JwksFixture fixture, string nonceClaim) =>
        fixture.SignIdToken(new
        {
            iss = OidcTestKit.BaseUrl.ToString().TrimEnd('/'),
            sub = "user-1",
            aud = OidcTestKit.ClientId,
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            nonce = nonceClaim,
        });

    [Fact]
    public async Task ResultIsTheOrdinaryTokenSet()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        var fixture = new JwksFixture();
        OidcTestKit.MapJwks(handler, fixture);
        // AXIAM's own ID token carries the request's nonce AS SENT: the raw value.
        handler.Map(TokenPath, _ => OidcTestKit.JsonOk(
            JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["access_token"] = "native-access",
                ["token_type"] = "DPoP",
                ["expires_in"] = 900,
                ["refresh_token"] = "native-refresh",
                ["id_token"] = SignedIdToken(fixture, FixtureNonce),
                ["scope"] = "openid profile",
            })));
        using AxiamClient client = ConfidentialClient(handler);
        string? accessBefore = ReadAccessCookie(client);

        OidcTokenSet result = await client.LoginWithProviderIdTokenAsync(
            "corp-okta", S("t"), S(FixtureNonce), scopes: new[] { "openid", "profile" });

        Assert.Equal("native-access", result.AccessToken.Reveal());
        Assert.Equal("DPoP", result.TokenType); // read, not assumed
        Assert.Equal("openid profile", result.Scope);
        Assert.Equal("native-refresh", result.RefreshToken!.Value.Reveal());
        Assert.NotNull(result.IdToken);
        Assert.Equal("user-1", result.IdClaims!.Sub);
        Assert.Equal("[SENSITIVE]", result.AccessToken.ToString());
        Assert.Equal("[SENSITIVE]", result.RefreshToken.Value.ToString());
        Assert.Equal("[SENSITIVE]", result.IdToken.Value.ToString());

        // This port's adoption posture (§37.2 rule 9, as login_client_credentials): it never
        // adopts the result as the client's own credential, so nothing changed.
        Assert.Equal(accessBefore, ReadAccessCookie(client));
    }

    [Fact]
    public async Task ResultIsTheOrdinaryTokenSet_NonceMismatchIsAnAuthError()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        var fixture = new JwksFixture();
        OidcTestKit.MapJwks(handler, fixture);
        // The HASH in the claim: the AXIAM token carries the raw nonce, so this must not match.
        MapOk(handler, idToken: SignedIdToken(fixture, FixtureNonceHash));
        using AxiamClient client = PublicClient(handler);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() =>
            client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S(FixtureNonce), scopes: new[] { "openid" }));
        Assert.Equal(IdTokenFailureReasons.NonceMismatch, ex.Reason);
    }

    [Fact]
    public async Task ResultIsTheOrdinaryTokenSet_WithoutRefreshAndIdTokenDecodesBothAbsent()
    {
        using var handler = new RoutingHandler();
        MapOk(handler, refresh: null, idToken: null);
        using AxiamClient client = PublicClient(handler);

        OidcTokenSet result = await client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n"), configuration: Config);

        Assert.Equal("native-access", result.AccessToken.Reveal());
        Assert.Null(result.RefreshToken);
        Assert.Null(result.IdToken);
        Assert.Null(result.IdClaims);
    }

    [Fact]
    public async Task ResultIsNotAdoptedAsTheClientsCredential()
    {
        using var handler = new RoutingHandler();
        MapOk(handler);
        using AxiamClient client = PublicClient(handler);

        await client.LoginWithProviderIdTokenAsync("corp-okta", S("t"), S("n"), configuration: Config);

        // §37.2 rule 9: no adoption, and no adoptAsCredential parameter to ask for it.
        Assert.Null(ReadAccessCookie(client));
        Assert.DoesNotContain(
            typeof(AxiamClient).GetMethod(nameof(AxiamClient.LoginWithProviderIdTokenAsync))!.GetParameters(),
            p => p.Name == "adoptAsCredential");
    }

    private static string? ReadAccessCookie(AxiamClient client) =>
        typeof(AxiamClient).GetMethod("ReadCookie", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?.Invoke(client, new object?[] { "axiam_access" }) as string;

    // -----------------------------------------------------------------
    // 12. no_secret_in_logs_or_errors
    // -----------------------------------------------------------------

    [Fact]
    public async Task NoSecretInLogsOrErrors()
    {
        var telemetry = new List<string>();
        TelemetryHook hook = e => { lock (telemetry) { telemetry.Add(e.ToString()); } };

        var failures = new (string Name, Func<RoutingHandler, HttpResponseMessage> Respond)[]
        {
            ("invalid_grant", _ => OidcTestKit.JsonStatus(HttpStatusCode.BadRequest, OidcTestKit.OAuth2ErrorJson("invalid_grant", "the provider ID token is not acceptable"))),
            ("consent_required", _ => OidcTestKit.JsonStatus(HttpStatusCode.BadRequest, OidcTestKit.OAuth2ErrorJson("consent_required", "needs consent"))),
            ("invalid_client", _ => OidcTestKit.JsonStatus(HttpStatusCode.Unauthorized, OidcTestKit.OAuth2ErrorJson("invalid_client", "bad client"))),
            ("invalid_scope", _ => OidcTestKit.JsonStatus(HttpStatusCode.BadRequest, OidcTestKit.OAuth2ErrorJson("invalid_scope", "no"))),
            ("rate_limit", _ => OidcTestKit.JsonStatus((HttpStatusCode)429, OidcTestKit.OAuth2ErrorJson("rate_limit_exceeded", "slow"))),
            ("server_error", _ => OidcTestKit.JsonStatus(HttpStatusCode.InternalServerError, OidcTestKit.OAuth2ErrorJson("server_error", "boom"))),
            ("500_no_body", _ => OidcTestKit.Empty(HttpStatusCode.InternalServerError)),
            ("transport", _ => throw new HttpRequestException("connection reset")),
            ("success", _ => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("native-access"))),
        };

        var rendered = new List<string>();
        foreach ((string name, Func<RoutingHandler, HttpResponseMessage> respond) in failures)
        {
            using var handler = new RoutingHandler();
            handler.Map(TokenPath, _ => respond(handler));
            using AxiamClient client = PublicClient(handler, hook: hook);
            try
            {
                OidcTokenSet ok = await client.LoginWithProviderIdTokenAsync(
                    "corp-okta", S(FixtureIdToken), S(FixtureRawNonce), configuration: Config);
                rendered.Add(ok.ToString()!);
            }
            catch (Exception ex)
            {
                for (Exception? e = ex; e is not null; e = e.InnerException)
                {
                    rendered.Add(e.Message);
                    rendered.Add(e.ToString());
                    rendered.AddRange(e.Data.Values.Cast<object?>().Select(v => v?.ToString() ?? string.Empty));
                }
            }
        }

        // The local refusals, which never reach the wire, are scanned too (a refused empty provider
        // must not echo the token or nonce it was called with).
        using (var handler = new RoutingHandler())
        {
            using AxiamClient client = PublicClient(handler, hook: hook);
            ArgumentException ex = await Assert.ThrowsAsync<ArgumentException>(() =>
                client.LoginWithProviderIdTokenAsync("", S(FixtureIdToken), S(FixtureRawNonce), configuration: Config));
            rendered.Add(ex.ToString());
        }

        ProviderNonce pair = AxiamClient.NativeNonce();
        rendered.Add(pair.ToString());
        rendered.Add(JsonSerializer.Serialize(pair));
        rendered.Add($"{pair}");
        // §19 telemetry attributes (the OAuth2 form POSTs emit none today; scanned so a future event cannot leak).
        rendered.AddRange(telemetry);

        foreach (string text in rendered)
        {
            Assert.DoesNotContain(FixtureIdToken, text);
            Assert.DoesNotContain(FixtureRawNonce, text);
            Assert.DoesNotContain(pair.Raw.Expose(), text);
        }
    }

    // -----------------------------------------------------------------
    // 13. native_nonce_pair
    // -----------------------------------------------------------------

    [Fact]
    public void NativeNoncePair()
    {
        ProviderNonce pair = AxiamClient.NativeNonce();

        string raw = pair.Raw.Expose();
        Assert.Matches("^[A-Za-z0-9_-]+$", raw); // base64url, no padding
        Assert.DoesNotContain('=', raw);
        byte[] decoded = Convert.FromBase64String(raw.Replace('-', '+').Replace('_', '/') + new string('=', (4 - raw.Length % 4) % 4));
        Assert.True(decoded.Length >= 32);

        Assert.Equal(64, pair.Hashed.Length);
        Assert.Matches("^[0-9a-f]{64}$", pair.Hashed); // lower-case hexadecimal
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(raw))), pair.Hashed);

        // The fixed vector pins the hashing step.
        Assert.Equal(FixtureNonceHash, AxiamClient.HashNonce(FixtureNonce));

        // Two calls, two different pairs.
        ProviderNonce second = AxiamClient.NativeNonce();
        Assert.NotEqual(raw, second.Raw.Expose());
        Assert.NotEqual(pair.Hashed, second.Hashed);

        // raw is wrapped; hashed is a plain string.
        Assert.Equal("[SENSITIVE]", pair.Raw.ToString());
        Assert.IsType<string>(pair.Hashed);
        Assert.DoesNotContain(raw, pair.ToString());
    }

    [Fact]
    public void NativeNonce_HasNoAsyncSuffix_AndIsPureLocal()
    {
        Assert.Null(typeof(AxiamClient).GetMethod("NativeNonceAsync"));
        Assert.NotNull(typeof(AxiamClient).GetMethod("NativeNonce"));
        Assert.NotNull(typeof(AxiamClient).GetMethod("LoginWithProviderIdTokenAsync"));
    }
}
