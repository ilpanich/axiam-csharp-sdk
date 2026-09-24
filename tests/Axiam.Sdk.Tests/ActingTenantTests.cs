using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;5.2 rule 1 (contract 1.51): the acting-tenant header,
/// <c>X-Axiam-Tenant</c>. Every &#167;8 rule 7 test this port ships for it, observed at
/// the BOTTOM of the transport pipeline — the fake <see cref="RoutingHandler"/> is the
/// innermost handler, reached only after <c>HttpClient.DefaultRequestHeaders</c> have
/// already merged and <c>AxiamHttpMessageHandler</c> has already run — never at a layer
/// above where the header is actually attached (the axiam-typescript-sdk lesson: a mock
/// that intercepts above the cookie-jar/header-attachment layer passes even when the
/// behaviour it claims to test is removed).
/// </summary>
[Trait("Category", "Fast")]
public sealed class ActingTenantTests
{
    private static readonly Uri BaseUrl = new("https://axiam.test");
    private const string TenantGuid = "22222222-2222-2222-2222-222222222222";
    private static readonly Guid OtherTenant = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid ThirdTenant = Guid.Parse("55555555-5555-5555-5555-555555555555");

    private static AxiamClient Client(RoutingHandler handler, AxiamClientOptions? options = null) =>
        AxiamClient.CreateForTesting(
            BaseUrl, TenantGuid, options ?? new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantGuid }, handler);

    private static HttpResponseMessage JsonOk(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    /// <summary>A <c>POST /api/v1/auth/login</c> response carrying a <c>user</c> object,
    /// so <c>ReadLoginScopeAsync</c> resolves the &#167;5.2 gate to a KNOWN value.</summary>
    private static HttpResponseMessage LoginResponse(bool organizationLevel, IReadOnlyList<Guid>? reachable = null)
    {
        var user = new Dictionary<string, object?>
        {
            ["id"] = Guid.NewGuid().ToString(),
            ["organization_level"] = organizationLevel,
        };
        if (reachable is not null)
        {
            user["reachable_tenant_ids"] = reachable.Select(g => g.ToString()).ToArray();
        }
        string body = JsonSerializer.Serialize(new Dictionary<string, object?> { ["user"] = user });
        return JsonOk(body);
    }

    // ---- §8 rule 7: sent when set, absent when not (the I4 twin) ----------------------

    [Fact]
    public async Task ActingTenant_SendsTheHeaderOnAManagementCall()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        using AxiamClient original = Client(handler);
        SeedAccessTokenCookie(original);
        using AxiamClient acting = original.ActingTenant(OtherTenant);

        await acting.Management.Resources.ListAsync();

        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.True(req.Headers.TryGetValues("X-Axiam-Tenant", out IEnumerable<string>? values));
        Assert.Equal(OtherTenant.ToString(), values!.Single());
    }

    [Fact]
    public async Task ANonActingClientSendsNoActingTenantHeaderAtAll_I4Twin()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        using AxiamClient original = Client(handler);
        SeedAccessTokenCookie(original);

        await original.Management.Resources.ListAsync();

        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.False(req.Headers.Contains("X-Axiam-Tenant"));
    }

    [Fact]
    public async Task ActingTenant_SendsTheHeaderOnCheckAccess()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/authz/check", _ => JsonOk("""{"allowed":true}"""));
        using AxiamClient original = Client(handler);
        using AxiamClient acting = original.ActingTenant(OtherTenant);

        await acting.Authz.CheckAccessAsync("users:get", Guid.NewGuid());

        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/authz/check");
        Assert.Equal(OtherTenant.ToString(), req.Headers.GetValues("X-Axiam-Tenant").Single());
    }

    [Fact]
    public async Task ClearActingTenant_RemovesTheHeaderAgain()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        using AxiamClient original = Client(handler);
        SeedAccessTokenCookie(original);
        using AxiamClient acting = original.ActingTenant(OtherTenant);
        using AxiamClient cleared = acting.ClearActingTenant();

        await cleared.Management.Resources.ListAsync();

        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.False(req.Headers.Contains("X-Axiam-Tenant"));
    }

    [Fact]
    public async Task TheConstructionTimeOptionSendsTheHeaderFromTheFirstRequest()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        var options = new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantGuid, ActingTenant = OtherTenant };
        using AxiamClient client = Client(handler, options);
        SeedAccessTokenCookie(client);

        await client.Management.Resources.ListAsync();

        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.Equal(OtherTenant.ToString(), req.Headers.GetValues("X-Axiam-Tenant").Single());
    }

    // ---- Gating (§5.2 rule 1's "gate it on what the SDK knows") -----------------------

    [Fact]
    public async Task ActingTenant_RefusesClientSideWhenTheLastLoginReportedOrganizationLevelFalse()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", _ => LoginResponse(organizationLevel: false));
        using AxiamClient original = Client(handler);
        await original.LoginAsync("alice@example.com", "pw");
        handler.Requests.Clear();

        Assert.Throws<AuthzError>(() => original.ActingTenant(OtherTenant));
        // Zero wire calls: the refusal happened before any request was built.
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ActingTenant_RefusesATenantOutsideReachableTenantIds()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", _ => LoginResponse(organizationLevel: true, reachable: new[] { ThirdTenant }));
        using AxiamClient original = Client(handler);
        await original.LoginAsync("alice@example.com", "pw");
        handler.Requests.Clear();

        Assert.Throws<AuthzError>(() => original.ActingTenant(OtherTenant));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ActingTenant_SucceedsForAnOrganizationLevelPrincipalWithinItsReach()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", _ => LoginResponse(organizationLevel: true, reachable: new[] { OtherTenant, ThirdTenant }));
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        using AxiamClient original = Client(handler);
        await original.LoginAsync("alice@example.com", "pw");
        SeedAccessTokenCookie(original); // the fake transport does not process Set-Cookie

        using AxiamClient acting = original.ActingTenant(OtherTenant);
        await acting.Management.Resources.ListAsync();

        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.Equal(OtherTenant.ToString(), req.Headers.GetValues("X-Axiam-Tenant").Single());
    }

    [Fact]
    public async Task ActingTenant_IsNotGatedWhenNoLoginResultIsHeld_SendsTheHeaderAndLetsTheServerAnswer()
    {
        // A service account / injected-token client, or one that has not logged in at
        // all: organization_level is unknown, not false, so ActingTenant does not
        // refuse client-side — it sends the header and the server's own 403 answers.
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/resources", _ => new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent("""{"error":"authorization_denied"}""", Encoding.UTF8, "application/json"),
        });
        using AxiamClient original = Client(handler);
        SeedAccessTokenCookie(original); // a session/token is held, but no LOGIN RESULT — no `user` object was ever parsed

        using AxiamClient acting = original.ActingTenant(OtherTenant);
        await Assert.ThrowsAsync<AuthzError>(() => acting.Management.Resources.ListAsync());

        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.Equal(OtherTenant.ToString(), req.Headers.GetValues("X-Axiam-Tenant").Single());
    }

    [Fact]
    public async Task LogoutResetsTheGateToUnknown_APreviouslyRefusedTenantIsNoLongerRefusedClientSide()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", _ => LoginResponse(organizationLevel: false));
        handler.Map("/api/v1/auth/logout", _ => JsonOk("{}"));
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        using AxiamClient original = Client(handler);
        var loginResult = await original.LoginAsync("alice@example.com", "pw");
        Assert.False(loginResult.OrganizationLevel);
        Assert.Throws<AuthzError>(() => original.ActingTenant(OtherTenant));

        // Seed a token so LogoutAsync (which reads jti off the current access token) has
        // something to log out.
        SeedAccessTokenCookie(original);
        await original.LogoutAsync();

        // The gate is unknown again — no client-side refusal; the request reaches the
        // (fake) wire, where the server would decide.
        using AxiamClient acting = original.ActingTenant(OtherTenant);
        await acting.Management.Resources.ListAsync();
        Assert.Contains(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
    }

    // ---- §17 addendum: a memoized decision for one tenant is not served for another ---

    [Fact]
    public async Task ADecisionMemoizedForOneActingTenantIsNotServedForAnother()
    {
        int callCount = 0;
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/authz/check", _ =>
        {
            callCount++;
            return JsonOk("""{"allowed":true}""");
        });
        var options = new AxiamClientOptions
        {
            BaseUrl = BaseUrl,
            TenantId = TenantGuid,
            DecisionMemoTtl = TimeSpan.FromSeconds(5),
        };
        using AxiamClient original = Client(handler, options);
        using AxiamClient tenantA = original.ActingTenant(OtherTenant);
        using AxiamClient tenantB = original.ActingTenant(ThirdTenant);

        Guid resourceId = Guid.NewGuid();
        await tenantA.Authz.CheckAccessAsync("users:get", resourceId);
        Assert.Equal(1, callCount);

        // Same (subject, resource, action, scope) key, but a DIFFERENT acting tenant —
        // MUST NOT hit the memo (the mutation this test exists to catch: dropping the
        // acting tenant from the memo key would make this a memo hit, callCount staying 1).
        await tenantB.Authz.CheckAccessAsync("users:get", resourceId);
        Assert.Equal(2, callCount);

        // Repeating tenantA's own check DOES hit the memo.
        await tenantA.Authz.CheckAccessAsync("users:get", resourceId);
        Assert.Equal(2, callCount);
    }

    // ---- Two handles over one session never rewrite each other's header ---------------

    [Fact]
    public async Task TwoActingTenantHandlesOverOneSessionNeverMixUpTheirHeaders()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        using AxiamClient original = Client(handler);
        SeedAccessTokenCookie(original);
        using AxiamClient tenantA = original.ActingTenant(OtherTenant);
        using AxiamClient tenantB = original.ActingTenant(ThirdTenant);

        // Interleaved, not sequential: both handles' requests are in flight before either
        // completes, which is exactly the scenario a header stored on the shared
        // transport (rather than attached per-handle) would get wrong.
        Task a = tenantA.Management.Resources.ListAsync();
        Task b = tenantB.Management.Resources.ListAsync();
        await Task.WhenAll(a, b);

        List<HttpRequestMessage> requests = handler.Requests
            .Where(r => r.RequestUri!.AbsolutePath == "/api/v1/resources")
            .ToList();
        Assert.Equal(2, requests.Count);
        Assert.Contains(requests, r => r.Headers.GetValues("X-Axiam-Tenant").Single() == OtherTenant.ToString());
        Assert.Contains(requests, r => r.Headers.GetValues("X-Axiam-Tenant").Single() == ThirdTenant.ToString());
    }

    [Fact]
    public void ActingTenantIsATypedGuid_ANonUuidCannotBeExpressedAtAll()
    {
        // §5.2 rule 1: "the value is a Uuid, so the client refuses a non-UUID at compile
        // time" — there is no string overload of ActingTenant/AxiamClientOptions.ActingTenant
        // to call with a malformed value in the first place. This test documents that
        // guarantee rather than exercising a runtime check (there is none to exercise).
        Assert.Equal(typeof(Guid), typeof(AxiamClient).GetMethod(nameof(AxiamClient.ActingTenant))!.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(Guid?), typeof(AxiamClientOptions).GetProperty(nameof(AxiamClientOptions.ActingTenant))!.PropertyType);
    }

    private static void SeedAccessTokenCookie(AxiamClient client)
    {
        System.Reflection.FieldInfo field =
            typeof(AxiamClient).GetField("_cookieContainer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        var container = (CookieContainer)field.GetValue(client)!;
        string header = Convert.ToBase64String(Encoding.UTF8.GetBytes("""{"alg":"none"}""")).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string body = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $$"""{"jti":"{{Guid.NewGuid()}}","tenant_id":"{{TenantGuid}}","exp":{{DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds()}}}"""))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        container.Add(BaseUrl, new Cookie("axiam_access", $"{header}.{body}.unsigned"));
    }

    private static HttpResponseMessage Ok() =>
        new(HttpStatusCode.OK) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };

    private sealed class RoutingHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, Func<HttpRequestMessage, HttpResponseMessage>> _routes = new();

        public List<HttpRequestMessage> Requests { get; } = new();

        public void Map(string path, Func<HttpRequestMessage, HttpResponseMessage> responder) => _routes[path] = responder;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            lock (Requests)
            {
                Requests.Add(request);
            }
            string path = request.RequestUri!.AbsolutePath;
            if (_routes.TryGetValue(path, out Func<HttpRequestMessage, HttpResponseMessage>? responder))
            {
                return Task.FromResult(responder(request));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
