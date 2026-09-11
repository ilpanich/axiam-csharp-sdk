using System.Net;
using System.Net.Http;
using System.Web;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;12.3 rule 4 — the <c>?tenant_id=</c> query parameter on the
/// <c>/oauth2</c> endpoints, when the discovery document <b>already carries one</b>.
/// </summary>
/// <remarks>
/// <para>
/// Contract 1.42's server scopes the endpoints it advertises: a discovery request that
/// names a tenant — or a deployment with <c>oauth2_default_tenant_id</c> set — gets
/// <c>token_endpoint</c>, <c>revocation_endpoint</c>, <c>introspection_endpoint</c>,
/// <c>device_authorization_endpoint</c>, <c>pushed_authorization_request_endpoint</c> and
/// <c>authorization_endpoint</c> back with <c>?tenant_id=&lt;uuid&gt;</c> already on them.
/// <c>userinfo_endpoint</c> and <c>jwks_uri</c> are deliberately never scoped.
/// </para>
/// <para>
/// This SDK used to <i>append</i> its own copy, producing
/// <c>?tenant_id=A&amp;tenant_id=B</c> — two values for one parameter, resolved by
/// whichever deserialiser reads them first. It now replaces: exactly one <c>tenant_id</c>
/// reaches the wire, it is the resolved one, and every other parameter the endpoint
/// carried survives (RFC 6749 &#167;3.1/&#167;3.2 require a client to retain an endpoint's
/// own query component).
/// </para>
/// </remarks>
[Trait("Category", "Fast")]
public class OidcTenantScopedEndpointTests
{
    private const string RevokePath = "/oauth2/revoke";

    /// <summary>A tenant the SERVER published, different from the one the client resolves,
    /// so "which value won" is observable rather than a coincidence.</summary>
    private const string PublishedTenant = "99999999-9999-9999-9999-999999999999";

    private static async Task<(RoutingHandler Handler, AxiamClient Client, OidcConfiguration Config)> SetUpAsync()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        handler.Map(RevokePath, _ => OidcTestKit.Empty(HttpStatusCode.OK));
        AxiamClient client = OidcTestKit.Client(handler);
        OidcConfiguration config = await client.OidcDiscoverAsync();
        return (handler, client, config);
    }

    private static async Task<Uri> RevokeAgainstAsync(string revocationEndpoint)
    {
        (RoutingHandler handler, AxiamClient client, OidcConfiguration config) = await SetUpAsync();
        using (handler)
        using (client)
        {
            await client.RevokeAsync(new RevokeParams
            {
                Token = Sensitive<string>.Wrap("some-token"),
                Configuration = config with { RevocationEndpoint = revocationEndpoint },
            });

            return handler.Requests.Single(r => r.RequestUri!.AbsolutePath == RevokePath).RequestUri!;
        }
    }

    /// <summary>Counts how many times <paramref name="name"/> appears as a query parameter
    /// NAME. <see cref="HttpUtility.ParseQueryString"/> collapses repeats into one
    /// comma-joined entry, so counting through it would report a doubled parameter as
    /// present-once and pass a test written to catch exactly that.</summary>
    private static int CountQueryParameter(Uri uri, string name) =>
        uri.Query.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Count(pair => Uri.UnescapeDataString(pair.Split('=', 2)[0]) == name);

    [Fact]
    public async Task AnEndpointThatAlreadyCarriesTheTenant_IsNotGivenASecondCopy()
    {
        Uri sent = await RevokeAgainstAsync($"https://axiam.test{RevokePath}?tenant_id={PublishedTenant}");

        Assert.Equal(1, CountQueryParameter(sent, "tenant_id"));
        // The resolved value wins: it is the tenant the caller (or the current session's
        // access token) actually authenticated against, and a silent dependence on which
        // copy the server's deserialiser reads first is worse than a deterministic answer.
        Assert.Equal(OidcTestKit.TenantGuid, HttpUtility.ParseQueryString(sent.Query)["tenant_id"]);
    }

    [Fact]
    public async Task AnExplicitTenantStillWins_OverTheOneTheEndpointPublished()
    {
        var other = Guid.Parse("44444444-4444-4444-4444-444444444444");
        (RoutingHandler handler, AxiamClient client, OidcConfiguration config) = await SetUpAsync();
        using (handler)
        using (client)
        {
            await client.RevokeAsync(new RevokeParams
            {
                Token = Sensitive<string>.Wrap("some-token"),
                TenantId = other,
                Configuration = config with
                {
                    RevocationEndpoint = $"https://axiam.test{RevokePath}?tenant_id={PublishedTenant}",
                },
            });

            Uri sent = handler.Requests.Single(r => r.RequestUri!.AbsolutePath == RevokePath).RequestUri!;
            Assert.Equal(1, CountQueryParameter(sent, "tenant_id"));
            Assert.Equal(other.ToString(), HttpUtility.ParseQueryString(sent.Query)["tenant_id"]);
        }
    }

    [Fact]
    public async Task EveryOtherQueryParameterTheEndpointCarried_Survives()
    {
        Uri sent = await RevokeAgainstAsync(
            $"https://axiam.test{RevokePath}?audience=legacy&tenant_id={PublishedTenant}&trace=abc");

        Assert.Equal(1, CountQueryParameter(sent, "tenant_id"));
        System.Collections.Specialized.NameValueCollection query = HttpUtility.ParseQueryString(sent.Query);
        Assert.Equal(OidcTestKit.TenantGuid, query["tenant_id"]);
        // RFC 6749 §3.1/§3.2: an endpoint's own query component is the server's, and a
        // client retains it. Dropping it was never the fix for the doubled parameter.
        Assert.Equal("legacy", query["audience"]);
        Assert.Equal("abc", query["trace"]);
    }

    [Fact]
    public async Task ABareEndpoint_StillGetsTheTenantAppended()
    {
        Uri sent = await RevokeAgainstAsync($"https://axiam.test{RevokePath}");

        Assert.Equal(1, CountQueryParameter(sent, "tenant_id"));
        Assert.Equal(OidcTestKit.TenantGuid, HttpUtility.ParseQueryString(sent.Query)["tenant_id"]);
    }

    [Fact]
    public async Task AFragmentIsNotWhereAQueryParameterGoes()
    {
        // Not a shape AXIAM publishes, but a URL a third-party OP may: appending after
        // the '#' would put the tenant somewhere no server ever reads.
        Uri sent = await RevokeAgainstAsync($"https://axiam.test{RevokePath}#section");

        Assert.Equal(1, CountQueryParameter(sent, "tenant_id"));
        Assert.Equal(OidcTestKit.TenantGuid, HttpUtility.ParseQueryString(sent.Query)["tenant_id"]);
    }
}
