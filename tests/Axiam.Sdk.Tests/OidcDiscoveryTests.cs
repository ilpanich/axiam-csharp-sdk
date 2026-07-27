using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// <see cref="AxiamClient.OidcDiscoverAsync"/> — CONTRACT.md &#167;12.3 rule 6: &#8805;5
/// minute cache TTL, single-flight de-duplication of concurrent callers, and a cache that
/// is per-client-instance (never process-global) so two clients against different origins
/// never share a document.
/// </summary>
[Trait("Category", "Fast")]
public class OidcDiscoveryTests
{
    [Fact]
    public async Task OidcDiscoverAsync_FetchesAndReturnsDocument()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);

        OidcConfiguration configuration = await client.OidcDiscoverAsync();

        Assert.Equal("https://axiam.test", configuration.Issuer);
        Assert.Equal("https://axiam.test/oauth2/token", configuration.TokenEndpoint);
        Assert.Equal("https://axiam.test/oauth2/jwks", configuration.JwksUri);
        Assert.Equal(1, handler.CountFor("/.well-known/openid-configuration"));
    }

    [Fact]
    public async Task OidcDiscoverAsync_CachesWithinTtl_NoSecondFetch()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);

        await client.OidcDiscoverAsync();
        await client.OidcDiscoverAsync();
        await client.OidcDiscoverAsync();

        Assert.Equal(1, handler.CountFor("/.well-known/openid-configuration"));
    }

    [Fact]
    public async Task OidcDiscoverAsync_DefaultTtlIsFloored_AtFiveMinutes()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        // A configured TTL smaller than the §12.3 rule 6 floor MUST be raised to it.
        var options = OidcTestKit.Options() with { OidcDiscoveryTtl = TimeSpan.FromSeconds(1) };
        AxiamClient client = OidcTestKit.Client(handler, options);

        await client.OidcDiscoverAsync();
        await Task.Delay(TimeSpan.FromSeconds(2));
        await client.OidcDiscoverAsync();

        // Even though the configured TTL (1s) elapsed, the floored 5-minute TTL keeps the
        // cache warm — still exactly one fetch.
        Assert.Equal(1, handler.CountFor("/.well-known/openid-configuration"));
    }

    [Fact]
    public async Task OidcDiscoverAsync_ConcurrentBurst_CollapsesToExactlyOneFetch()
    {
        using var handler = new RoutingHandler();
        var gate = new SemaphoreSlim(0);
        int hitCount = 0;
        handler.Map("/.well-known/openid-configuration", _ =>
        {
            Interlocked.Increment(ref hitCount);
            // Force every concurrent caller to actually overlap in-flight before any of
            // them completes, proving the single-flight guard (not mere luck/ordering).
            gate.Wait(TimeSpan.FromSeconds(5));
            return OidcTestKit.JsonOk(OidcTestKit.DiscoveryJson(OidcTestKit.BaseUrl));
        });
        AxiamClient client = OidcTestKit.Client(handler);

        const int concurrency = 10;
        Task<OidcConfiguration>[] tasks = Enumerable.Range(0, concurrency)
            .Select(_ => client.OidcDiscoverAsync())
            .ToArray();

        // Release the single in-flight fetch once all callers have had a chance to queue.
        await Task.Delay(TimeSpan.FromMilliseconds(200));
        gate.Release(concurrency);

        OidcConfiguration[] results = await Task.WhenAll(tasks);

        Assert.All(results, r => Assert.Equal("https://axiam.test", r.Issuer));
        Assert.Equal(1, hitCount);
    }

    [Fact]
    public async Task OidcDiscoverAsync_DifferentClientInstances_NeverShareCache_PerOrigin()
    {
        using var handlerA = new RoutingHandler();
        OidcTestKit.MapDiscovery(handlerA, new Uri("https://a.axiam.test"));
        using var handlerB = new RoutingHandler();
        OidcTestKit.MapDiscovery(handlerB, new Uri("https://b.axiam.test"));

        AxiamClient clientA = AxiamClient.CreateForTesting(
            new Uri("https://a.axiam.test"), OidcTestKit.TenantGuid,
            new AxiamClientOptions { BaseUrl = new Uri("https://a.axiam.test"), TenantId = OidcTestKit.TenantGuid, OidcClientId = OidcTestKit.ClientId },
            handlerA);
        AxiamClient clientB = AxiamClient.CreateForTesting(
            new Uri("https://b.axiam.test"), OidcTestKit.TenantGuid,
            new AxiamClientOptions { BaseUrl = new Uri("https://b.axiam.test"), TenantId = OidcTestKit.TenantGuid, OidcClientId = OidcTestKit.ClientId },
            handlerB);

        OidcConfiguration configA = await clientA.OidcDiscoverAsync();
        OidcConfiguration configB = await clientB.OidcDiscoverAsync();

        Assert.Equal("https://a.axiam.test", configA.Issuer);
        Assert.Equal("https://b.axiam.test", configB.Issuer);
        Assert.Equal(1, handlerA.CountFor("/.well-known/openid-configuration"));
        Assert.Equal(1, handlerB.CountFor("/.well-known/openid-configuration"));
    }

    [Fact]
    public async Task OidcDiscoverAsync_ReturnsAllDocumentFields()
    {
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler);

        OidcConfiguration configuration = await client.OidcDiscoverAsync();

        Assert.Equal("https://axiam.test/oauth2/authorize", configuration.AuthorizationEndpoint);
        Assert.Equal("https://axiam.test/oauth2/userinfo", configuration.UserinfoEndpoint);
        Assert.Equal("https://axiam.test/oauth2/revoke", configuration.RevocationEndpoint);
        Assert.Equal("https://axiam.test/oauth2/introspect", configuration.IntrospectionEndpoint);
        Assert.Equal(new[] { "code" }, configuration.ResponseTypesSupported);
        Assert.Equal(new[] { "public" }, configuration.SubjectTypesSupported);
        Assert.Equal(new[] { "EdDSA" }, configuration.IdTokenSigningAlgValuesSupported);
        Assert.Equal(new[] { "openid" }, configuration.ScopesSupported);
        Assert.Equal(new[] { "client_secret_post" }, configuration.TokenEndpointAuthMethodsSupported);
        Assert.Equal(new[] { "sub" }, configuration.ClaimsSupported);
        Assert.Contains("authorization_code", configuration.GrantTypesSupported);
    }

    [Fact]
    public async Task OidcDiscoverAsync_TransportFailure_ThrowsNetworkError()
    {
        using var handler = new RoutingHandler();
        handler.Map("/.well-known/openid-configuration", _ => throw new HttpRequestException("simulated connection refused"));
        AxiamClient client = OidcTestKit.Client(handler);

        await Assert.ThrowsAsync<NetworkError>(() => client.OidcDiscoverAsync());
    }

    [Fact]
    public async Task OidcDiscoverAsync_NonOkResponse_ThrowsMappedError()
    {
        using var handler = new RoutingHandler();
        handler.Map("/.well-known/openid-configuration", _ => OidcTestKit.Empty(System.Net.HttpStatusCode.InternalServerError));
        AxiamClient client = OidcTestKit.Client(handler);

        await Assert.ThrowsAsync<NetworkError>(() => client.OidcDiscoverAsync());
    }

    [Fact]
    public async Task OidcDiscoverAsync_IssuerDifferentFromBaseUrl_IsNotRejected()
    {
        // §12.3 rule 6 / addendum item 8: the discovery document's own issuer is
        // authoritative and may legitimately differ from the client's base URL (proxy
        // deployments) — never rejected on mismatch.
        using var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler, issuer: "https://public-issuer.example");
        AxiamClient client = OidcTestKit.Client(handler);

        OidcConfiguration configuration = await client.OidcDiscoverAsync();

        Assert.Equal("https://public-issuer.example", configuration.Issuer);
    }
}
