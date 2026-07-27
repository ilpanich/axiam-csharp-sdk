using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.Options;

namespace Axiam.Sdk.Tests.Fixtures;

/// <summary>
/// Shared constants/builders for the CONTRACT.md &#167;12 OIDC test suites — mirrors the
/// TypeScript reference's <c>oidcTestKit.ts</c> role for this port: one place that knows
/// the discovery-document shape, default client id/secret/tenant, and how to wire an
/// <see cref="AxiamClient"/> against a fake <see cref="RoutingHandler"/> transport.
/// </summary>
public static class OidcTestKit
{
    public const string ClientId = "test-relying-party";
    public const string ClientSecret = "test-client-secret";
    public const string TenantGuid = "22222222-2222-2222-2222-222222222222";

    public static readonly Uri BaseUrl = new("https://axiam.test");

    /// <summary>Builds a well-formed <c>OidcDiscoveryDocument</c> JSON body for
    /// <paramref name="baseUrl"/>, with <c>issuer</c> equal to the base URL (tests that
    /// need a mismatched issuer build their own document).</summary>
    public static string DiscoveryJson(Uri baseUrl, string? issuer = null)
    {
        string origin = baseUrl.ToString().TrimEnd('/');
        var document = new
        {
            issuer = issuer ?? origin,
            authorization_endpoint = $"{origin}/oauth2/authorize",
            token_endpoint = $"{origin}/oauth2/token",
            userinfo_endpoint = $"{origin}/oauth2/userinfo",
            jwks_uri = $"{origin}/oauth2/jwks",
            revocation_endpoint = $"{origin}/oauth2/revoke",
            introspection_endpoint = $"{origin}/oauth2/introspect",
            response_types_supported = new[] { "code" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "EdDSA" },
            scopes_supported = new[] { "openid" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post" },
            claims_supported = new[] { "sub" },
            grant_types_supported = new[] { "authorization_code", "refresh_token", "client_credentials" },
        };
        return JsonSerializer.Serialize(document);
    }

    /// <summary>Registers the <c>GET /.well-known/openid-configuration</c> route on
    /// <paramref name="handler"/>, serving <see cref="DiscoveryJson"/> for
    /// <paramref name="baseUrl"/> (defaulting to <see cref="BaseUrl"/>).</summary>
    public static void MapDiscovery(RoutingHandler handler, Uri? baseUrl = null, string? issuer = null) =>
        handler.Map("/.well-known/openid-configuration", _ => JsonOk(DiscoveryJson(baseUrl ?? BaseUrl, issuer)));

    /// <summary>Registers the <c>GET /oauth2/jwks</c> route, serving
    /// <paramref name="fixture"/>'s JWKS document.</summary>
    public static void MapJwks(RoutingHandler handler, JwksFixture fixture) =>
        handler.Map("/oauth2/jwks", _ => JsonOk(fixture.BuildJwksDocument()));

    public static AxiamClientOptions Options(string? clientSecret = ClientSecret, string tenantId = TenantGuid) => new()
    {
        BaseUrl = BaseUrl,
        TenantId = tenantId,
        OidcClientId = ClientId,
        OidcClientSecret = clientSecret,
    };

    public static AxiamClient Client(HttpMessageHandler handler, AxiamClientOptions? options = null, string tenantId = TenantGuid) =>
        AxiamClient.CreateForTesting(BaseUrl, tenantId, options ?? Options(tenantId: tenantId), handler);

    public static HttpResponseMessage JsonOk(string json) =>
        new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage JsonStatus(HttpStatusCode status, string json) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Empty(HttpStatusCode status) => new(status);

    /// <summary>Builds a <c>TokenResponse</c> body, optionally carrying an <c>id_token</c>.</summary>
    public static string TokenResponseJson(string accessToken, string? refreshToken = null, string? idToken = null, string tokenType = "Bearer", long expiresIn = 900)
    {
        var body = new Dictionary<string, object?>
        {
            ["access_token"] = accessToken,
            ["token_type"] = tokenType,
            ["expires_in"] = expiresIn,
        };
        if (refreshToken is not null)
        {
            body["refresh_token"] = refreshToken;
        }
        if (idToken is not null)
        {
            body["id_token"] = idToken;
        }
        return JsonSerializer.Serialize(body);
    }

    public static string OAuth2ErrorJson(string error, string description) =>
        JsonSerializer.Serialize(new { error, error_description = description });

    /// <summary>Reads a form-urlencoded request body into a dictionary, for asserting the
    /// exact fields an SDK operation sent.</summary>
    public static Dictionary<string, string> ReadForm(HttpRequestMessage request)
    {
        string body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
        var result = new Dictionary<string, string>();
        foreach (string pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] kv = pair.Split('=', 2);
            // application/x-www-form-urlencoded (unlike a URL query string) encodes a
            // literal space as '+', which Uri.UnescapeDataString does NOT decode back to
            // a space on its own — swap it in before unescaping.
            string key = Uri.UnescapeDataString(kv[0].Replace('+', ' '));
            string value = kv.Length > 1 ? Uri.UnescapeDataString(kv[1].Replace('+', ' ')) : string.Empty;
            result[key] = value;
        }
        return result;
    }
}
