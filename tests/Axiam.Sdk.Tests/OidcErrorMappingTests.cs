using System.Net;
using System.Net.Http;
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
/// CONTRACT.md &#167;2/&#167;12.1/&#167;12.3 rule 3: an <c>OAuth2ErrorResponse</c> body maps to
/// <see cref="OAuthProtocolError"/> — a language-idiomatic sub-type of
/// <see cref="AuthError"/> — with <see cref="Exception.Message"/> exactly
/// <c>"&lt;error&gt;: &lt;error_description&gt;"</c>, and a <c>400</c> from
/// <c>/oauth2/token</c> MUST NOT collapse into the generic <c>400</c>&#8594;
/// <see cref="NetworkError"/> row.
/// </summary>
[Trait("Category", "Fast")]
public class OidcErrorMappingTests
{
    private static (RoutingHandler Handler, AxiamClient Client) SetUp()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);
        return (handler, client);
    }

    [Fact]
    public async Task OidcExchangeAsync_400_OAuth2Error_MapsToOAuthProtocolError_NotNetworkError()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/token", _ => OidcTestKit.JsonStatus(HttpStatusCode.BadRequest, OidcTestKit.OAuth2ErrorJson("invalid_grant", "authorization code is invalid or expired")));

        var ex = await Assert.ThrowsAsync<OAuthProtocolError>(() => client.OidcExchangeAsync(new OidcExchangeParams
        {
            Code = "bad-code",
            CodeVerifier = Sensitive<string>.Wrap("verifier"),
            RedirectUri = "https://app.example/callback",
            Nonce = "nonce",
        }));

        Assert.Equal("invalid_grant", ex.Error);
        Assert.Equal("authorization code is invalid or expired", ex.ErrorDescription);
        Assert.Equal("invalid_grant: authorization code is invalid or expired", ex.Message);
        // It IS an AuthError (backward-compatible sub-type — §12 port addendum item 17).
        Assert.IsAssignableFrom<AuthError>(ex);
        // Its ID-token Reason must stay null — that field is reserved for §12.4 failures.
        Assert.Null(ex.Reason);
    }

    [Fact]
    public async Task OidcExchangeAsync_400_MalformedBody_FallsBackToNetworkError()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/token", _ => OidcTestKit.JsonStatus(HttpStatusCode.BadRequest, "not-json-at-all"));

        await Assert.ThrowsAsync<NetworkError>(() => client.OidcExchangeAsync(new OidcExchangeParams
        {
            Code = "bad-code",
            CodeVerifier = Sensitive<string>.Wrap("verifier"),
            RedirectUri = "https://app.example/callback",
            Nonce = "nonce",
        }));
    }

    [Fact]
    public async Task OidcExchangeAsync_500_IsNetworkError()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/token", _ => OidcTestKit.Empty(HttpStatusCode.InternalServerError));

        await Assert.ThrowsAsync<NetworkError>(() => client.OidcExchangeAsync(new OidcExchangeParams
        {
            Code = "bad-code",
            CodeVerifier = Sensitive<string>.Wrap("verifier"),
            RedirectUri = "https://app.example/callback",
            Nonce = "nonce",
        }));
    }

    [Fact]
    public void OAuthProtocolError_IsCatchableAsExistingAuthError_BackwardCompatible()
    {
        // §12 port addendum item 17: existing `catch (AuthError)` call sites must keep
        // working unchanged against an OAuthProtocolError value.
        Exception thrown = new OAuthProtocolError("invalid_client", "bad credentials");

        try
        {
            throw thrown;
        }
        catch (AuthError caught)
        {
            Assert.Same(thrown, caught);
            return;
        }
#pragma warning disable CS0162
        Assert.Fail("OAuthProtocolError was not caught by a plain `catch (AuthError)` block.");
#pragma warning restore CS0162
    }

    [Fact]
    public async Task OidcExchangeAsync_TransportThrows_WrapsInNetworkError()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map("/oauth2/token", _ => throw new HttpRequestException("simulated connection refused"));

        await Assert.ThrowsAsync<NetworkError>(() => client.OidcExchangeAsync(new OidcExchangeParams
        {
            Code = "code",
            CodeVerifier = Sensitive<string>.Wrap("verifier"),
            RedirectUri = "https://app.example/callback",
            Nonce = "nonce",
        }));
    }

    [Fact]
    public async Task OidcExchangeAsync_TenantSlugOnly_ResolvedFromSessionCookieClaim()
    {
        // §12.3 rule 4: when the client was constructed with a tenant SLUG, the tenant_id
        // UUID for the mandatory query parameter falls back to the one resolved from a
        // prior successful login's access-token claim.
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(tenantId: "acme"), tenantId: "acme");
        SeedSessionWithTenantClaim(client, OidcTestKit.TenantGuid);
        handler.Map("/oauth2/token", _ => OidcTestKit.JsonOk(OidcTestKit.TokenResponseJson("access-1")));

        OidcTokenSet result = await client.OidcRefreshAsync(new OidcRefreshParams { RefreshToken = Sensitive<string>.Wrap("r") });

        Assert.Equal("access-1", result.AccessToken.Reveal());
        var tokenRequest = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/oauth2/token");
        Assert.Equal($"tenant_id={OidcTestKit.TenantGuid}", tokenRequest.RequestUri!.Query.TrimStart('?'));
    }

    private static void SeedSessionWithTenantClaim(AxiamClient client, string tenantGuid)
    {
        FieldInfo field = typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var container = (System.Net.CookieContainer)field.GetValue(client)!;
        string header = Base64Url(Encoding.UTF8.GetBytes("""{"alg":"none"}"""));
        string body = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new { tenant_id = tenantGuid, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds() }));
        container.Add(OidcTestKit.BaseUrl, new System.Net.Cookie("axiam_access", $"{header}.{body}.unsigned"));
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [Fact]
    public async Task OidcExchangeAsync_TenantSlugOnly_NoResolvableTenantUuid_ThrowsAuthError_WithoutWireCall()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        // Constructed with a SLUG, not a UUID, and no prior login to resolve one from.
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options(tenantId: "acme"), tenantId: "acme");

        await Assert.ThrowsAsync<AuthError>(() => client.OidcExchangeAsync(new OidcExchangeParams
        {
            Code = "code",
            CodeVerifier = Sensitive<string>.Wrap("verifier"),
            RedirectUri = "https://app.example/callback",
            Nonce = "nonce",
        }));
        Assert.Equal(0, handler.CountFor("/oauth2/token"));
    }
}
