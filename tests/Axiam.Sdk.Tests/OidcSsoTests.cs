using System.Net;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// <see cref="AxiamClient.SsoStartAsync"/> / <see cref="AxiamClient.SsoCompleteAsync"/>
/// (CONTRACT.md &#167;12.1 notes 6/7, &#167;5.1, &#167;12 port addendum item 12).
/// </summary>
[Trait("Category", "Fast")]
public class OidcSsoTests
{
    [Fact]
    public async Task SsoStartAsync_UsesClientTenantAndOrg_WhenNotOverridden()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/federation/oidc/start", req => OidcTestKit.JsonOk(
            """{"authorize_url":"https://idp.example/authorize?x=1","state":"fed-state-1","expires_in_secs":600}"""));
        var options = OidcTestKit.Options() with { OrgId = Guid.Parse("33333333-3333-3333-3333-333333333333") };
        AxiamClient client = OidcTestKit.Client(handler, options);

        SsoStartResult result = await client.SsoStartAsync(new SsoStartParams
        {
            FederationConfigId = "44444444-4444-4444-4444-444444444444",
            RedirectUri = "https://app.example/after-sso",
        });

        Assert.Equal("https://idp.example/authorize?x=1", result.AuthorizeUrl);
        Assert.Equal("fed-state-1", result.State);
        Assert.Equal(600, result.ExpiresInSecs);

        var request = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/api/v1/auth/federation/oidc/start");
        string body = await request.Content!.ReadAsStringAsync();
        Assert.Contains(OidcTestKit.TenantGuid, body);
        Assert.Contains("33333333-3333-3333-3333-333333333333", body);
        Assert.Contains("44444444-4444-4444-4444-444444444444", body);
    }

    [Fact]
    public async Task SsoStartAsync_UsesOrgSlugFallback_AndTenantSlugFallback_WhenClientHasNoUuidTenant()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/federation/oidc/start", req => OidcTestKit.JsonOk(
            """{"authorize_url":"https://idp.example/authorize","state":"fed-state-2","expires_in_secs":600}"""));
        // Client constructed with a SLUG tenant and OrgSlug (never OrgId/TenantId UUID) —
        // exercises both self-fallback branches (tenant_slug AND org_slug body fields).
        var options = new AxiamClientOptions { BaseUrl = OidcTestKit.BaseUrl, TenantId = "acme", OidcClientId = OidcTestKit.ClientId, OrgSlug = "acme-org" };
        AxiamClient client = OidcTestKit.Client(handler, options, tenantId: "acme");

        SsoStartResult result = await client.SsoStartAsync(new SsoStartParams
        {
            FederationConfigId = "44444444-4444-4444-4444-444444444444",
            RedirectUri = "https://app.example/after-sso",
        });

        Assert.Equal("fed-state-2", result.State);
        var request = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == "/api/v1/auth/federation/oidc/start");
        string body = await request.Content!.ReadAsStringAsync();
        Assert.Contains("\"tenant_slug\":\"acme\"", body);
        Assert.Contains("\"org_slug\":\"acme-org\"", body);
    }

    [Fact]
    public async Task SsoStartAsync_NoOrgContext_ThrowsAuthError_WithoutWireCall()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/federation/oidc/start", _ => throw new InvalidOperationException("must not call the wire when org context is unresolvable"));
        // No OrgId/OrgSlug configured anywhere.
        var options = new AxiamClientOptions { BaseUrl = OidcTestKit.BaseUrl, TenantId = OidcTestKit.TenantGuid };
        AxiamClient client = OidcTestKit.Client(handler, options);

        await Assert.ThrowsAsync<AuthError>(() => client.SsoStartAsync(new SsoStartParams
        {
            FederationConfigId = "44444444-4444-4444-4444-444444444444",
            RedirectUri = "https://app.example/after-sso",
        }));
    }

    [Fact]
    public async Task SsoStartAsync_401_FallsThroughToGenericMapping_NeverParsedAsOAuth2Error()
    {
        // §12 port addendum item 12: the federation error body shape is undocumented.
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/federation/oidc/start", _ => OidcTestKit.Empty(HttpStatusCode.Unauthorized));
        var options = OidcTestKit.Options() with { OrgId = Guid.Parse("33333333-3333-3333-3333-333333333333") };
        AxiamClient client = OidcTestKit.Client(handler, options);

        Exception ex = await Assert.ThrowsAsync<AuthError>(() => client.SsoStartAsync(new SsoStartParams
        {
            FederationConfigId = "44444444-4444-4444-4444-444444444444",
            RedirectUri = "https://app.example/after-sso",
        }));

        Assert.IsNotType<OAuthProtocolError>(ex);
    }

    [Fact]
    public async Task SsoCompleteAsync_HappyPath_ReturnsResult_NoIdTokenValidationApplies()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/federation/oidc/callback", req => OidcTestKit.JsonOk(
            """{"user_id":"55555555-5555-5555-5555-555555555555","session_id":"66666666-6666-6666-6666-666666666666","expires_in":900,"redirect_uri":"https://app.example/dashboard"}"""));
        AxiamClient client = OidcTestKit.Client(handler);

        SsoCompleteResult result = await client.SsoCompleteAsync(new SsoCompleteParams { State = "fed-state-1", Code = "fed-code-1" });

        Assert.Equal("55555555-5555-5555-5555-555555555555", result.UserId);
        Assert.Equal("66666666-6666-6666-6666-666666666666", result.SessionId);
        Assert.Equal(900, result.ExpiresIn);
        Assert.Equal("https://app.example/dashboard", result.RedirectUri);
    }

    [Fact]
    public async Task SsoCompleteAsync_NonOkResponse_ThrowsMappedError()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/federation/oidc/callback", _ => OidcTestKit.Empty(HttpStatusCode.Unauthorized));
        AxiamClient client = OidcTestKit.Client(handler);

        await Assert.ThrowsAsync<AuthError>(() => client.SsoCompleteAsync(new SsoCompleteParams { State = "s", Code = "c" }));
    }
}
