using System.Net.Http;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Options;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// CONTRACT.md &#167;27.4, &#167;27.5 and &#167;27.2 semantics — the &#167;27.9 required
/// tests.
/// </summary>
/// <remarks>
/// Every assertion here exists because the thing it checks is easy to get wrong and
/// silent when wrong. Where &#167;27.9 says to assert on the request <em>path</em> rather
/// than on the arguments, these do.
/// </remarks>
[Trait("Category", "Fast")]
public sealed class ManagementSemanticsTests : ManagementTestBase
{
    /// <summary>&#167;27.4 rule 1: a management call with no session fails locally.</summary>
    [Fact]
    public async Task NoSessionMakesNoWireCall()
    {
        Route route = Mount("GET", "/api/v1/users", 200, PageOf(null));
        using AxiamClient anonymous = AnonymousClient();

        AuthError thrown = await Assert.ThrowsAsync<AuthError>(
            () => anonymous.Management.Users.ListAsync());

        Assert.Contains("no active session", thrown.Message, StringComparison.Ordinal);
        Assert.Equal(0, route.Calls);
    }

    /// <summary>&#167;27.4 rule 3: the client's org and tenant land in the path.</summary>
    [Fact]
    public async Task OrgAndTenantComeFromTheClientAndLandInThePath()
    {
        Route orgRoute = Mount("GET", $"/api/v1/organizations/{OrgId}/ca-certificates", 200, PageOf(null));
        Route tenantRoute = Mount("GET", $"/api/v1/tenants/{TenantId}/settings", 200, "{}");

        await Client.Management.CaCertificates.ListAsync();
        await Client.Management.Settings.GetTenantOverrideAsync();

        Assert.Equal(1, orgRoute.Calls);
        Assert.Equal(1, tenantRoute.Calls);
    }

    /// <summary>&#167;27.4 rule 3: no resolved tenant UUID means a local refusal, not a 404.</summary>
    [Fact]
    public async Task AClientWithNoResolvedTenantRefusesWithoutCalling()
    {
        Route route = Mount("GET", $"/api/v1/tenants/{TenantId}/settings", 200, "{}");
        SeedSession(OrgId.ToString(), tenantId: null);

        await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.Settings.GetTenantOverrideAsync());

        Assert.Equal(0, route.Calls);
    }

    /// <summary>&#167;27.4 rule 4: total is the whole set, not the page.</summary>
    [Fact]
    public async Task TotalIsTheWholeSetNotThePage()
    {
        Mount("GET", "/api/v1/users", 200,
            $$"""{"items":[{{UserBody(1)}}],"total":97,"offset":0,"limit":1}""");

        Page<UserResponse> page = await Client.Management.Users.ListAsync(PageRequest.Of(1));

        Assert.Single(page.Items);
        Assert.Equal(97, page.Total);
        Assert.False(page.IsLast);
    }

    /// <summary>&#167;27.4 rule 4: a bare-array read is a list, not a page.</summary>
    [Fact]
    public async Task ABareArrayOperationIsNotAPage()
    {
        Mount("GET", $"/api/v1/resources/{ExampleId}/scopes", 200,
            $$"""
              [{"id":"{{ExampleId}}","name":"draft","description":"Unpublished",
                "resource_id":"{{ExampleId}}","tenant_id":"{{TenantId}}",
                "created_at":"2026-08-26T00:00:00Z","updated_at":"2026-08-26T00:00:00Z"}]
              """);

        // The compiler is the assertion: an IReadOnlyList<Scope> has no .Total, and had
        // the generator modelled this as a page this line would not build.
        IReadOnlyList<Scope> scopes = await Client.Management.Scopes.ListAsync(ExampleId);

        Assert.Single(scopes);
    }

    /// <summary>&#167;27.4 rule 5: a sparse update sends exactly the key it was given.</summary>
    [Fact]
    public async Task ASparseUpdateSendsExactlyTheOneKeyItWasGiven()
    {
        Route route = Mount("PUT", $"/api/v1/users/{ExampleId}", 200, UserBody(1));

        await Client.Management.Users.UpdateAsync(
            ExampleId, new UpdateUserRequest { Email = "new@example.test" });

        Assert.Equal(new[] { "email" }, route.Last.Keys());
    }

    /// <summary>&#167;27.4 rule 5: a replacement body's initializer requires every field.</summary>
    [Fact]
    public async Task AReplacementBodyCannotBeBuiltHalfFilled()
    {
        Route route = Mount(
            "PUT",
            $"/api/v1/organizations/{OrgId}/ca-certificates/{ExampleId}/mtls-trust-anchor",
            200,
            $$"""
              {"ca_certificate_id":"{{ExampleId}}","mtls_trust_anchor":true,
               "message":"ok","restart_required":false}
              """);

        // SetMtlsTrustAnchor's property is `required`, so omitting it is a compile
        // error. That is the whole guarantee §27.4 rule 5 asks for on a replacement body.
        await Client.Management.CaCertificates.SetMtlsTrustAnchorAsync(
            ExampleId, new SetMtlsTrustAnchor { Enabled = true });

        Assert.Equal(new[] { "enabled" }, route.Last.Keys());
    }

    /// <summary>&#167;27.4 rule 7: 404 is a NotFoundError, and still an AuthzError.</summary>
    [Fact]
    public async Task NotFoundIsStillAnAuthzError()
    {
        Mount("GET", $"/api/v1/users/{ExampleId}", 404, """{"message":"no such user"}""");

        NotFoundError thrown = await Assert.ThrowsAsync<NotFoundError>(
            () => Client.Management.Users.GetAsync(ExampleId));

        Assert.IsAssignableFrom<AuthzError>(thrown);
        Assert.Contains("no such user", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>&#167;27.4 rules 7 and 8: 409 is a ConflictError, and the write goes out once.</summary>
    [Fact]
    public async Task AConflictIsNotRetried()
    {
        Route route = Mount("POST", "/api/v1/roles", 409, """{"message":"role name already taken"}""");

        ConflictError thrown = await Assert.ThrowsAsync<ConflictError>(
            () => Client.Management.Roles.CreateAsync(
                new CreateRoleRequest { Description = "Edits", IsGlobal = false, Name = "Editor" }));

        Assert.IsAssignableFrom<AuthzError>(thrown);
        Assert.Equal(1, route.Calls);
    }

    /// <summary>&#167;27.4 rule 7: 400 is a ValidationError with field detail.</summary>
    [Fact]
    public async Task ABadRequestCarriesFieldDetail()
    {
        Mount("POST", "/api/v1/users", 400,
            """{"message":"invalid","errors":[{"field":"email","message":"is not an address"}]}""");

        ValidationError thrown = await Assert.ThrowsAsync<ValidationError>(
            () => Client.Management.Users.CreateAsync(new CreateUserRequest
            {
                Email = "nope",
                Password = Sensitive<string>.Wrap("pw"),
                Username = "someone",
            }));

        Assert.IsAssignableFrom<NetworkError>(thrown);
        Assert.Single(thrown.Fields);
        Assert.Equal("email", thrown.Fields[0].Field);
    }

    /// <summary>&#167;27.4 rule 7: the object-keyed error shape is understood too.</summary>
    [Fact]
    public async Task UnprocessableCarriesObjectKeyedFieldDetail()
    {
        Mount("POST", "/api/v1/permissions", 422,
            """{"message":"invalid","errors":{"action":["must be namespaced"]}}""");

        ValidationError thrown = await Assert.ThrowsAsync<ValidationError>(
            () => Client.Management.Permissions.CreateAsync(
                new CreatePermissionRequest { Action = "read", Description = "Read" }));

        Assert.Equal("action", thrown.Fields[0].Field);
        Assert.Contains("namespaced", thrown.Fields[0].Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// &#167;27.4 rule 7's table, pinned whole.
    /// </summary>
    /// <remarks>
    /// Each sub-type keeps the parent &#167;2 already gave its status. Which status maps
    /// to which TYPE is asserted by the cases above; this pins the other half, the
    /// PARENT, which nothing else here would notice changing — 409 in particular looks
    /// like a transport concern and is not one.
    /// </remarks>
    [Fact]
    public void EveryClassificationKeepsTheParentSection2GaveIt()
    {
        Assert.True(typeof(AuthzError).IsAssignableFrom(typeof(NotFoundError)));
        Assert.False(typeof(NetworkError).IsAssignableFrom(typeof(NotFoundError)));
        Assert.True(typeof(AuthzError).IsAssignableFrom(typeof(ConflictError)));
        Assert.False(typeof(NetworkError).IsAssignableFrom(typeof(ConflictError)));
        Assert.True(typeof(NetworkError).IsAssignableFrom(typeof(ValidationError)));
        Assert.False(typeof(AuthzError).IsAssignableFrom(typeof(ValidationError)));
    }

    /// <summary>&#167;27 classifies three statuses and widens the taxonomy no further.</summary>
    [Fact]
    public async Task AnOrdinaryForbiddenStaysAPlainAuthzError()
    {
        Mount("GET", $"/api/v1/users/{ExampleId}", 403, """{"message":"nope"}""");

        AuthzError thrown = await Assert.ThrowsAsync<AuthzError>(
            () => Client.Management.Users.GetAsync(ExampleId));

        Assert.IsNotType<NotFoundError>(thrown);
        Assert.IsNotType<ConflictError>(thrown);
    }

    /// <summary>A second delete reports the 404 rather than absorbing it (&#167;27.4 rule 6).</summary>
    [Fact]
    public async Task ARepeatedDeleteIsNotSwallowedIntoSuccess()
    {
        Mount("DELETE", $"/api/v1/users/{ExampleId}", 404, """{"message":"already gone"}""");

        await Assert.ThrowsAsync<NotFoundError>(
            () => Client.Management.Users.DeleteAsync(ExampleId));
    }

    /// <summary>&#167;27.4 rule 8: a write is issued exactly once, even on a 503.</summary>
    [Fact]
    public async Task AWriteIsIssuedExactlyOnceOnAServerError()
    {
        Route route = Mount("POST", "/api/v1/roles", 503, """{"message":"try later"}""");

        await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.Roles.CreateAsync(
                new CreateRoleRequest { Description = "Edits", IsGlobal = false, Name = "Editor" }));

        Assert.Equal(1, route.Calls);
    }

    /// <summary>&#167;27.5: a returned one-time secret is readable once, and redacted otherwise.</summary>
    [Fact]
    public async Task AReturnedOneTimeSecretIsRedacted()
    {
        Mount("POST", "/api/v1/scim-tokens", 201,
            $$"""
              {"id":"{{ExampleId}}","name":"provisioning","provisioning_token":"tok-abcdef",
               "created_at":"2026-08-26T00:00:00Z","expires_at":"2027-08-26T00:00:00Z",
               "created_by":"{{ExampleId}}","user_id":"{{ExampleId}}","status":"active",
               "tenant_id":"{{TenantId}}"}
              """);

        CreateScimTokenResponse created = await Client.Management.ScimTokens.CreateAsync(
            new CreateScimTokenRequest { Name = "provisioning", UserId = ExampleId });

        Assert.Equal("tok-abcdef", created.ProvisioningToken.Expose());
        Assert.Equal("[SENSITIVE]", created.ProvisioningToken.ToString());
        Assert.DoesNotContain("tok-abcdef", created.ToString(), StringComparison.Ordinal);
    }

    /// <summary>&#167;27.5: a supplied password is redacted locally but still reaches the wire.</summary>
    [Fact]
    public async Task ASuppliedPasswordIsRedactedButStillSent()
    {
        Route route = Mount("POST", "/api/v1/users", 201, UserBody(1));
        var body = new CreateUserRequest
        {
            Email = "alice@example.test",
            Password = Sensitive<string>.Wrap("correct-horse-battery"),
            Username = "alice",
        };

        Assert.DoesNotContain("correct-horse", body.ToString(), StringComparison.Ordinal);
        await Client.Management.Users.CreateAsync(body);

        Assert.Equal(
            "correct-horse-battery",
            route.Last.Json().GetProperty("password").GetString());
    }

    /// <summary>&#167;27.2 rule 1: acquiring a handle performs no I/O.</summary>
    [Fact]
    public void AcquiringAHandlePerformsNoIo()
    {
        int before = TotalCalls();

        for (int i = 0; i < 5; i++)
        {
            _ = Client.Management.Users;
            _ = Client.Management.CaCertificates.InOrg(ExampleId);
        }

        Assert.Equal(before, TotalCalls());
    }

    /// <summary>&#167;18.1: use-after-dispose is an error, never a silent reconnect.</summary>
    [Fact]
    public async Task ADisposedClientRejectsEveryOperation()
    {
        Route route = Mount("GET", "/api/v1/users", 200, PageOf(null));
        AxiamClient closing = AnonymousClient();
        LogIn(closing);
        closing.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => closing.Management.Users.ListAsync());

        Assert.Equal(0, route.Calls);
    }

    /// <summary>A response that does not match its declared schema names the operation.</summary>
    [Fact]
    public async Task AResponseThatDoesNotMatchItsSchemaNamesTheOperation()
    {
        Mount("POST", "/api/v1/roles", 201, """{"id":"not-a-uuid"}""");

        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.Roles.CreateAsync(
                new CreateRoleRequest { Description = "Edits", IsGlobal = false, Name = "Editor" }));

        Assert.Contains("roles.create", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>A bare-array read that comes back as an object yields nothing, not a crash.</summary>
    [Fact]
    public async Task ABareArrayReadThatIsNotAnArrayIsEmpty()
    {
        Mount("GET", $"/api/v1/resources/{ExampleId}/scopes", 200, "{}");

        Assert.Empty(await Client.Management.Scopes.ListAsync(ExampleId));
    }

    /// <summary>A paginated read with no body at all is an empty page, not a null.</summary>
    [Fact]
    public async Task APaginatedReadWithNoBodyIsAnEmptyPage()
    {
        Mount("GET", "/api/v1/users", 204, string.Empty);

        Page<UserResponse> page = await Client.Management.Users.ListAsync();

        Assert.Empty(page.Items);
        Assert.Equal(0, page.Total);
    }

    /// <summary>An unparseable success body names the operation.</summary>
    [Fact]
    public async Task AnUnparseableSuccessBodyNamesTheOperation()
    {
        Mount("GET", "/api/v1/users", 200, "{not json");

        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.Users.ListAsync());

        Assert.Contains("users.list", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>&#167;27.4 rule 3: a configured OrgId outranks the token claim.</summary>
    [Fact]
    public async Task AConfiguredOrgIdOutranksTheTokenClaim()
    {
        var configured = Guid.Parse("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
        Route route = Mount(
            "GET", $"/api/v1/organizations/{configured}/ca-certificates", 200, PageOf(null));
        using AxiamClient scoped = AnonymousClient(new AxiamClientOptions
        {
            BaseUrl = new Uri("https://axiam.test"),
            TenantId = TenantSlug,
            OrgId = configured,
        });
        LogIn(scoped);

        await scoped.Management.CaCertificates.ListAsync();

        Assert.Equal(1, route.Calls);
    }

    /// <summary>&#167;27.4 rule 3: an unusable org claim refuses locally and says how to fix it.</summary>
    [Fact]
    public async Task AnOrgClaimThatIsNotAUuidRefusesWithoutCalling()
    {
        Route route = Mount(
            "GET", $"/api/v1/organizations/{OrgId}/ca-certificates", 200, PageOf(null));
        SeedSession("not-a-uuid", TenantId.ToString());

        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.CaCertificates.ListAsync());

        Assert.Contains("InOrg(", thrown.Message, StringComparison.Ordinal);
        Assert.Equal(0, route.Calls);
    }

    /// <summary>&#167;27.4 rule 3: the implicits are readable, for the routes that take them.</summary>
    [Fact]
    public void TheResolvedOrgAndTenantAreReadable()
    {
        Assert.Equal(OrgId, Client.ResolvedOrgId);
        Assert.Equal(TenantId, Client.ResolvedTenantId);

        using AxiamClient anonymous = AnonymousClient();
        Assert.Null(anonymous.ResolvedTenantId);
        Assert.Null(anonymous.ResolvedOrgId);
    }

    private static string UserBody(int index) =>
        $$"""
          {"id":"11111111-1111-4111-8111-00000000000{{index}}","username":"user{{index}}",
           "email":"user{{index}}@example.test","email_verified":true,
           "failed_login_attempts":0,"is_locked":false,"metadata":{},"mfa_enabled":false,
           "status":"Active","tenant_id":"{{TenantId}}","created_at":"2026-08-26T00:00:00Z",
           "updated_at":"2026-08-26T00:00:00Z"}
          """;
}
