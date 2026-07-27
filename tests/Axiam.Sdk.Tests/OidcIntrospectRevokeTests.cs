using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// <see cref="AxiamClient.IntrospectAsync"/> / <see cref="AxiamClient.RevokeAsync"/>
/// (CONTRACT.md &#167;12.1 notes 4/5, &#167;12.3 rule 3): confidential-client-only,
/// idempotent revoke, and — the CI-gate-relevant assertion — a <c>401</c> from either MUST
/// NOT enter the &#167;9 single-flight refresh guard.
/// </summary>
[Trait("Category", "Fast")]
public class OidcIntrospectRevokeTests
{
    private static (RoutingHandler Handler, AxiamClient Client) SetUp()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        return (handler, client);
    }

    /// <summary>
    /// Seeds a valid, non-expired <c>axiam_access</c> session cookie directly into the
    /// client's shared cookie jar — so a test proving "the §9 refresh guard must NOT fire"
    /// is meaningful: without the &#167;12.1 note 4/&#167;12.3 rule 3 path-exemption, a
    /// present, resolvable session is EXACTLY the condition under which
    /// <c>AxiamHttpMessageHandler</c> would otherwise attempt a reactive refresh on a 401.
    /// Mirrors <c>AxiamClientAuthFlowTests.SeedCookie</c>.
    /// </summary>
    private static void SeedValidSession(AxiamClient client)
    {
        FieldInfo field = typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var container = (System.Net.CookieContainer)field.GetValue(client)!;
        string header = Base64Url(Encoding.UTF8.GetBytes("""{"alg":"none"}"""));
        string body = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new
        {
            tenant_id = OidcTestKit.TenantGuid,
            org_id = "33333333-3333-3333-3333-333333333333",
            exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
        }));
        container.Add(OidcTestKit.BaseUrl, new System.Net.Cookie("axiam_access", $"{header}.{body}.unsigned"));
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [Fact]
    public async Task IntrospectAsync_ActiveToken_ReturnsFullMetadata()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/introspect", req => OidcTestKit.JsonOk(
            """{"active":true,"sub":"user-1","client_id":"test-relying-party","scope":"openid","token_type":"Bearer","exp":1999999999,"iat":1999999000}"""));

        IntrospectionResult result = await client.IntrospectAsync(new IntrospectParams
        {
            Token = Sensitive<string>.Wrap("some-token"),
            TokenTypeHint = "access_token",
        });

        Assert.True(result.Active);
        Assert.Equal("user-1", result.Sub);
        Assert.Equal("test-relying-party", result.ClientId);
        Assert.Equal("openid", result.Scope);
        Assert.Equal("Bearer", result.TokenType);
        Assert.Equal(1999999999, result.Exp);
        Assert.Equal(1999999000, result.Iat);

        var request = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/oauth2/introspect");
        Dictionary<string, string> form = OidcTestKit.ReadForm(request);
        Assert.Equal("some-token", form["token"]);
        Assert.Equal(OidcTestKit.ClientId, form["client_id"]);
        Assert.Equal(OidcTestKit.ClientSecret, form["client_secret"]);
        Assert.Equal("access_token", form["token_type_hint"]);
        Assert.Equal($"tenant_id={OidcTestKit.TenantGuid}", request.RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task IntrospectAsync_InactiveToken_OnlyActiveFieldGuaranteed()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/introspect", _ => OidcTestKit.JsonOk("""{"active":false}"""));

        IntrospectionResult result = await client.IntrospectAsync(new IntrospectParams { Token = Sensitive<string>.Wrap("some-token") });

        Assert.False(result.Active);
        Assert.Null(result.Sub);
    }

    [Fact]
    public async Task IntrospectAsync_NoClientSecret_ThrowsAuthError_WithoutWireCall()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(clientSecret: null));

        await Assert.ThrowsAsync<AuthError>(() => client.IntrospectAsync(new IntrospectParams { Token = Sensitive<string>.Wrap("t") }));
        Assert.Equal(0, handler.CountFor("/oauth2/introspect"));
    }

    [Fact]
    public async Task IntrospectAsync_401_MapsToOAuthProtocolError()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/introspect", _ => OidcTestKit.JsonStatus(HttpStatusCode.Unauthorized, OidcTestKit.OAuth2ErrorJson("invalid_client", "client authentication failed")));

        OAuthProtocolError ex = await Assert.ThrowsAsync<OAuthProtocolError>(() => client.IntrospectAsync(new IntrospectParams { Token = Sensitive<string>.Wrap("t") }));

        Assert.Equal("invalid_client", ex.Error);
        Assert.Equal("client authentication failed", ex.ErrorDescription);
        Assert.Equal("invalid_client: client authentication failed", ex.Message);
    }

    [Fact]
    public async Task IntrospectAsync_401_DoesNotEnterRefreshGuard()
    {
        // §12.3 rule 3 / §12.1 note 4: a client-credential failure is not a session
        // expiry — retrying a cookie-session refresh cannot fix a bad client_secret, and
        // must never even be attempted.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        SeedValidSession(client);
        handler.Map("/oauth2/introspect", _ => OidcTestKit.JsonStatus(HttpStatusCode.Unauthorized, OidcTestKit.OAuth2ErrorJson("invalid_client", "bad secret")));
        handler.Map("/api/v1/auth/refresh", _ => throw new InvalidOperationException("the §9 refresh guard must never fire for an /oauth2/* 401"));

        await Assert.ThrowsAsync<OAuthProtocolError>(() => client.IntrospectAsync(new IntrospectParams { Token = Sensitive<string>.Wrap("t") }));

        Assert.Equal(0, handler.CountFor("/api/v1/auth/refresh"));
        // Exactly one attempt at /oauth2/introspect itself — no retry loop either.
        Assert.Equal(1, handler.CountFor("/oauth2/introspect"));
    }

    [Fact]
    public async Task RevokeAsync_401_DoesNotEnterRefreshGuard()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        SeedValidSession(client);
        handler.Map("/oauth2/revoke", _ => OidcTestKit.JsonStatus(HttpStatusCode.Unauthorized, OidcTestKit.OAuth2ErrorJson("invalid_client", "bad secret")));
        handler.Map("/api/v1/auth/refresh", _ => throw new InvalidOperationException("the §9 refresh guard must never fire for an /oauth2/* 401"));

        await Assert.ThrowsAsync<OAuthProtocolError>(() => client.RevokeAsync(new RevokeParams { Token = Sensitive<string>.Wrap("t") }));

        Assert.Equal(0, handler.CountFor("/api/v1/auth/refresh"));
    }

    [Fact]
    public async Task RevokeAsync_UnknownToken_IsIdempotent_NoErrorOn200()
    {
        // RFC 7009: the server answers 200 for unknown/expired/already-revoked tokens.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/revoke", _ => OidcTestKit.Empty(HttpStatusCode.OK));

        await client.RevokeAsync(new RevokeParams
        {
            Token = Sensitive<string>.Wrap("never-issued-token"),
            TokenTypeHint = "refresh_token",
        });
        // No exception == success.

        var request = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/oauth2/revoke");
        Dictionary<string, string> form = OidcTestKit.ReadForm(request);
        Assert.Equal("refresh_token", form["token_type_hint"]);
    }

    [Fact]
    public async Task RevokeAsync_5xx_IsStillNetworkError_NotSilentSuccess()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/revoke", _ => OidcTestKit.Empty(HttpStatusCode.InternalServerError));

        await Assert.ThrowsAsync<NetworkError>(() => client.RevokeAsync(new RevokeParams { Token = Sensitive<string>.Wrap("t") }));
    }

    [Fact]
    public async Task RevokeAsync_NoClientSecret_ThrowsAuthError_WithoutWireCall()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(clientSecret: null));

        await Assert.ThrowsAsync<AuthError>(() => client.RevokeAsync(new RevokeParams { Token = Sensitive<string>.Wrap("t") }));
        Assert.Equal(0, handler.CountFor("/oauth2/revoke"));
    }
}
