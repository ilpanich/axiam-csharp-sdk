using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
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

    // ---- N5.6 (CONTRACT 1.52, C-12), "Every SDK — N5.6, check explicitly" -------------
    //
    // Tenant ids compare as UUIDs, never as strings — case and formatting MUST NOT decide
    // reach. Three SDKs (Swift, PHP, TypeScript) and Python compared reachable_tenant_ids
    // as strings, and test fixtures using all-digit UUIDs (where case cannot differ) hid
    // it twice. This SDK's gate (AxiamClient.cs's GateActingTenant) already uses a typed
    // comparison: `_session.ReachableTenantIds` is `IReadOnlyList<Guid>` (parsed via
    // `Guid.TryParse`, AxiamClient.cs's ReadLoginScopeAsync), and the check is
    // `List<Guid>.Contains(Guid tenantId)` — structural equality on 128-bit values, with
    // no string comparison anywhere in the path. This test pins that: a UUID with hex
    // letters (a-f), where a naive string compare WOULD see a mismatch, upper-case on the
    // wire (deliberately adversarial — a real AXIAM server sends lower-case, but nothing
    // requires it, and RFC 4122 treats hex case as insignificant) against the SAME value
    // the caller holds — case is not even an observable property of a `Guid` value, only
    // of a string, which is exactly why the typed comparison conforms unconditionally.

    [Fact]
    public async Task ActingTenant_ReachComparisonIsCaseInsensitive_TypedGuidComparisonConforms()
    {
        Guid tenant = Guid.Parse("aabbccdd-eeff-40ab-8cde-1234567890ab");
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", _ => JsonOk(
            $"{{\"user\":{{\"id\":\"{Guid.NewGuid()}\",\"organization_level\":true,\"reachable_tenant_ids\":[\"{tenant.ToString().ToUpperInvariant()}\"]}}}}"));
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        using AxiamClient original = Client(handler);
        await original.LoginAsync("alice@example.com", "pw");
        SeedAccessTokenCookie(original); // the fake transport does not process Set-Cookie

        // Must NOT throw AuthzError even though the server's reachable_tenant_ids entry
        // was upper-case and the caller's Guid is whatever case-agnostic CLR value it is.
        using AxiamClient acting = original.ActingTenant(tenant);
        await acting.Management.Resources.ListAsync();

        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.Equal(tenant.ToString(), req.Headers.GetValues("X-Axiam-Tenant").Single());
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

    // ---- An SSO completion resets the gate too (§5.2 rule 1 "For C-12" item 5) --------
    //
    // Each of the three federation completions establishes a session, possibly as a
    // DIFFERENT principal than whatever this client last held — the same reasoning
    // LoginAsync/LogoutAsync already apply. None of their success responses carries a
    // LoginUserInfo/user object, so the gate lands on "unknown" (not repopulated),
    // exactly like LogoutAsync above.

    [Fact]
    public async Task SsoCompleteAsync_ResetsTheGate_APreviouslyRefusedTenantIsNoLongerRefusedClientSide()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", _ => LoginResponse(organizationLevel: false));
        handler.Map("/api/v1/auth/federation/oidc/callback", _ => JsonOk(
            """{"user_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","expires_in":900,"redirect_uri":"https://app.example/dashboard"}"""));
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        using AxiamClient original = Client(handler);
        await original.LoginAsync("alice@example.com", "pw");
        SeedAccessTokenCookie(original);
        Assert.Throws<AuthzError>(() => original.ActingTenant(OtherTenant));

        await original.SsoCompleteAsync(new SsoCompleteParams { State = "fed-state", Code = "fed-code" });

        using AxiamClient acting = original.ActingTenant(OtherTenant);
        await acting.Management.Resources.ListAsync();
        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.Equal(OtherTenant.ToString(), req.Headers.GetValues("X-Axiam-Tenant").Single());
    }

    [Fact]
    public async Task SsoCompleteOauth2Async_ResetsTheGate_APreviouslyRefusedTenantIsNoLongerRefusedClientSide()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", _ => LoginResponse(organizationLevel: false));
        handler.Map("/api/v1/auth/federation/oauth2/callback", _ => JsonOk(
            """{"user_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","expires_in":900,"redirect_uri":"https://app.example/dashboard"}"""));
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        using AxiamClient original = Client(handler);
        await original.LoginAsync("alice@example.com", "pw");
        SeedAccessTokenCookie(original);
        Assert.Throws<AuthzError>(() => original.ActingTenant(OtherTenant));

        await original.SsoCompleteOauth2Async(new SsoCompleteOauth2Params { State = "fed-state", Code = "fed-code" });

        using AxiamClient acting = original.ActingTenant(OtherTenant);
        await acting.Management.Resources.ListAsync();
        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.Equal(OtherTenant.ToString(), req.Headers.GetValues("X-Axiam-Tenant").Single());
    }

    [Fact]
    public async Task SsoCompleteHandoffAsync_ResetsTheGate_APreviouslyRefusedTenantIsNoLongerRefusedClientSide()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", _ => LoginResponse(organizationLevel: false));
        handler.Map("/api/v1/auth/federation/handoff", _ => JsonOk(
            """{"user_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","expires_in":900,"redirect_uri":"https://app.example/dashboard"}"""));
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        using AxiamClient original = Client(handler);
        await original.LoginAsync("alice@example.com", "pw");
        SeedAccessTokenCookie(original);
        Assert.Throws<AuthzError>(() => original.ActingTenant(OtherTenant));

        await original.SsoCompleteHandoffAsync(new SsoCompleteHandoffParams { Code = "fed-code" });

        using AxiamClient acting = original.ActingTenant(OtherTenant);
        await acting.Management.Resources.ListAsync();
        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.Equal(OtherTenant.ToString(), req.Headers.GetValues("X-Axiam-Tenant").Single());
    }

    /// <summary>
    /// I4 twin of the three tests above: the reset happens BEFORE the wire call (exactly
    /// where every other credential-changing method places it — see
    /// <c>OnCredentialChange</c>'s remarks), so an SSO completion that itself FAILS has
    /// already reset the gate by the time its exception propagates. This documents what
    /// the code actually does (an attempt already invalidates the previous state, not
    /// only a success) rather than assuming "failure leaves the gate untouched".
    /// </summary>
    [Fact]
    public async Task SsoCompleteAsync_ResetsTheGateEvenWhenTheCompletionItselfFails()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", _ => LoginResponse(organizationLevel: false));
        handler.Map("/api/v1/auth/federation/oidc/callback", _ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        using AxiamClient original = Client(handler);
        await original.LoginAsync("alice@example.com", "pw");
        Assert.Throws<AuthzError>(() => original.ActingTenant(OtherTenant));

        await Assert.ThrowsAsync<AuthError>(
            () => original.SsoCompleteAsync(new SsoCompleteParams { State = "fed-state", Code = "fed-code" }));

        // The gate was already reset before the failing request was even sent — it does
        // NOT still refuse on the stale organization_level:false.
        using AxiamClient acting = original.ActingTenant(OtherTenant);
        Assert.NotNull(acting);
    }

    // ---- Device login: the returned handle's gate starts unknown, independent of the --
    // ---- source client's own (possibly restrictive) prior login -----------------------

    [Fact]
    public async Task AuthenticateDeviceAsync_TheReturnedHandlesGateStartsUnknown_EvenWhenTheSourceWasRestrictivelyLoggedIn()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/login", _ => LoginResponse(organizationLevel: false));
        handler.Map("/api/v1/auth/device", _ => JsonOk("""{"access_token":"device-token","token_type":"Bearer","expires_in":900}"""));
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        var options = new AxiamClientOptions
        {
            BaseUrl = BaseUrl,
            TenantId = TenantGuid,
            ClientCertificatePem = System.Text.Encoding.ASCII.GetBytes(
                "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKZ0000000000MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n-----END CERTIFICATE-----\n"),
            ClientKeyPem = System.Text.Encoding.ASCII.GetBytes(
                "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n"),
        };
        using AxiamClient source = Client(handler, options);
        await source.LoginAsync("alice@example.com", "pw"); // organization_level: false, on the SOURCE
        Assert.Throws<AuthzError>(() => source.ActingTenant(OtherTenant)); // the source itself is gated

        var deviceResult = await source.AuthenticateDeviceAsync();
        using AxiamClient device = deviceResult.Client;

        // The device handle's own gate is a FRESH SharedSession (never source's), so it
        // is unknown, not "organization_level: false" — ActingTenant on it is allowed.
        using AxiamClient acting = device.ActingTenant(OtherTenant);
        await acting.Management.Resources.ListAsync();
        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.Equal(OtherTenant.ToString(), req.Headers.GetValues("X-Axiam-Tenant").Single());
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
