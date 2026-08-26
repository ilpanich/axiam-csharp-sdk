using System.Text.Json;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// The CONTRACT.md &#167;27 core types, tested directly rather than through a route.
/// </summary>
/// <remarks>
/// <see cref="PageRequest"/> and <see cref="Page{T}"/> carry the arithmetic &#167;27.4
/// rule 4 depends on, the two <c>Sensitive</c> converters decide whether a secret reaches
/// a socket, and the validation layer refuses a manifest before the first request. Each
/// is cheaper and clearer to pin here than to reach through a mounted transport.
/// </remarks>
[Trait("Category", "Fast")]
public sealed class ManagementCoreTests : ManagementTestBase
{
    // ---- §27.4 rule 4: paging arithmetic --------------------------------

    /// <summary>A negative offset or a zero limit is a caller bug, caught at construction.</summary>
    [Fact]
    public void APageRequestRefusesNonsense()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new PageRequest(offset: -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new PageRequest(limit: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new PageRequest(limit: -5));
    }

    /// <summary>
    /// An unset limit is omitted, not sent as zero.
    /// </summary>
    /// <remarks>
    /// The server reads <c>limit=0</c> as "none" and answers with an empty page, so the
    /// difference between omitting the parameter and sending a zero is the difference
    /// between the server's default and no results at all.
    /// </remarks>
    [Fact]
    public void AnUnsetLimitIsOmittedRatherThanSentAsZero()
    {
        Assert.Null(PageRequest.First().Limit);
        Assert.Null(ManagementSupport.PageQuery(null, null)["limit"]);
        Assert.Equal("0", ManagementSupport.PageQuery(null, null)["offset"]);
        Assert.Equal("25", ManagementSupport.PageQuery(null, PageRequest.Of(25))["limit"]);
    }

    /// <summary>A manual walk advances by what it consumed.</summary>
    [Fact]
    public void NextAdvancesTheWindow()
    {
        PageRequest advanced = PageRequest.Of(2).Next(2);
        Assert.Equal(2, advanced.Offset);
        Assert.Equal(2, advanced.Limit);

        PageRequest unlimited = PageRequest.First().Next(5);
        Assert.Equal(5, unlimited.Offset);
        Assert.Null(unlimited.Limit);
    }

    /// <summary>A page knows whether it is the last one, and where the next one starts.</summary>
    [Fact]
    public void APageReportsWhereTheNextOneStarts()
    {
        var middle = new Page<string>(new[] { "a", "b" }, total: 5, offset: 0, limit: 2);
        Assert.False(middle.IsLast);
        Assert.Equal(2, middle.NextPage()!.Offset);

        var last = new Page<string>(new[] { "e" }, total: 5, offset: 4, limit: 2);
        Assert.True(last.IsLast);
        Assert.Null(last.NextPage());

        // An empty page ends the walk even when total disagrees, so a miscounting
        // server costs one wasted request rather than a loop.
        var lying = new Page<string>(Array.Empty<string>(), total: 900, offset: 0, limit: 2);
        Assert.True(lying.IsLast);
        Assert.Null(lying.NextPage());

        // A server that reported no limit must not produce a zero-limit next window,
        // which PageRequest would reject.
        var noLimit = new Page<string>(new[] { "a" }, total: 5, offset: 0, limit: 0);
        Assert.Null(noLimit.NextPage()!.Limit);

        Assert.True(Page<string>.Empty().IsLast);
    }

    // ---- §27.5: which writer exposes a secret ---------------------------

    /// <summary>
    /// An options-registered converter beats the type's own attribute.
    /// </summary>
    /// <remarks>
    /// The entire &#167;27.5 design rests on this precedence, and it is the OPPOSITE of
    /// Jackson's, where a class-level annotation wins over a module-registered
    /// serializer — the sibling Java SDK hit exactly that and needed a mixin. Pinning it
    /// here means a future <c>System.Text.Json</c> that reordered the rules would fail
    /// this test rather than start shipping <c>"[SENSITIVE]"</c> to the server as a
    /// password.
    /// </remarks>
    [Fact]
    public void TheWireWriterBeatsTheRedactingAttribute()
    {
        var body = new CreateUserRequest
        {
            Email = "alice@example.test",
            Password = Sensitive<string>.Wrap("correct-horse"),
            Username = "alice",
        };

        string wire = ManagementSupport.EncodeBody("users.create", body);
        Assert.Contains("correct-horse", wire, StringComparison.Ordinal);
        Assert.DoesNotContain("[SENSITIVE]", wire, StringComparison.Ordinal);

        // Everywhere else, the attribute still governs and the secret is redacted.
        string elsewhere = JsonSerializer.Serialize(body);
        Assert.DoesNotContain("correct-horse", elsewhere, StringComparison.Ordinal);
        Assert.Contains("[SENSITIVE]", elsewhere, StringComparison.Ordinal);
    }

    /// <summary>The wire writer omits an unset property and keeps a set one.</summary>
    [Fact]
    public void TheWireWriterOmitsWhatWasNeverNamed()
    {
        string text = ManagementSupport.EncodeBody(
            "users.update", new UpdateUserRequest { Email = "x@example.test" });

        JsonElement root = JsonDocument.Parse(text).RootElement;
        Assert.Equal(new[] { "email" }, root.EnumerateObject().Select(p => p.Name));
        Assert.Equal("x@example.test", root.GetProperty("email").GetString());
    }

    // ---- Enum wire spellings --------------------------------------------

    /// <summary>
    /// An enum round-trips through its wire spelling, and an unknown value throws.
    /// </summary>
    /// <remarks>
    /// Quietly reading an unrecognised status as whatever happens to be declared first
    /// would turn a new server state into a wrong one — and on this surface those states
    /// gate access.
    /// </remarks>
    [Fact]
    public void AnEnumRoundTripsItsWireSpellingAndRefusesAnUnknownOne()
    {
        var converter = new WireEnumConverter<ScimTokenStatus>();
        var options = new JsonSerializerOptions();
        options.Converters.Add(converter);

        Assert.Equal("\"active\"", JsonSerializer.Serialize(ScimTokenStatus.Active, options));
        Assert.Equal(
            ScimTokenStatus.Revoked,
            JsonSerializer.Deserialize<ScimTokenStatus>("\"revoked\"", options));

        NetworkError thrown = Assert.Throws<NetworkError>(
            () => JsonSerializer.Deserialize<ScimTokenStatus>("\"suspended\"", options));
        Assert.Contains("does not know", thrown.Message, StringComparison.Ordinal);
    }

    // ---- §27.6 rule 1: what validation refuses --------------------------

    /// <summary>A duplicate key is refused: two entries claiming one name cannot both win.</summary>
    [Fact]
    public async Task DuplicateKeysAreRefused()
    {
        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.Manifest.PlanAsync(new ManagementManifest
            {
                Roles = new[]
                {
                    new ManagementManifest.RoleSpec("editor", "Editor", "One"),
                    new ManagementManifest.RoleSpec("editor", "Editor", "Two"),
                },
                Permissions = new[]
                {
                    new ManagementManifest.PermissionSpec("read", "document:read", "A"),
                    new ManagementManifest.PermissionSpec("read", "document:read", "B"),
                },
            }));

        Assert.Contains("role key 'editor' is declared more than once", thrown.Message,
            StringComparison.Ordinal);
        Assert.Contains("permission key 'read' is declared more than once", thrown.Message,
            StringComparison.Ordinal);
    }

    /// <summary>A grant narrowed to a scope no resource declares is refused before calling.</summary>
    [Fact]
    public async Task AGrantNamingAnUnknownScopeIsRefused()
    {
        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.Manifest.PlanAsync(new ManagementManifest
            {
                Permissions = new[]
                {
                    new ManagementManifest.PermissionSpec("read", "document:read", "Read"),
                },
                Roles = new[]
                {
                    new ManagementManifest.RoleSpec(
                        "editor", "Editor", "Edits", false,
                        new[] { new ManagementManifest.GrantSpec("read", null, new[] { "ghost" }) }),
                },
            }));

        Assert.Contains("scope 'ghost'", thrown.Message, StringComparison.Ordinal);
        Assert.Equal(0, TotalCalls());
    }

    /// <summary>A user joining a group nothing declares, and holding an unknown role.</summary>
    [Fact]
    public async Task DanglingGroupAndUserReferencesAreRefused()
    {
        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.Manifest.PlanAsync(new ManagementManifest
            {
                Users = new[]
                {
                    new ManagementManifest.UserSpec(
                        "alice", "alice", "a@example.test", null,
                        Roles: new[] { "ghost-role" }, Groups: new[] { "ghost-group" }),
                },
            }));

        Assert.Contains("holds role 'ghost-role'", thrown.Message, StringComparison.Ordinal);
        Assert.Contains("joins group 'ghost-group'", thrown.Message, StringComparison.Ordinal);
    }

    // ---- §27.4 rule 7: what an odd error body does ----------------------

    /// <summary>An error body that is not JSON still yields a usable message.</summary>
    [Fact]
    public async Task ANonJsonErrorBodyIsQuotedRatherThanDropped()
    {
        Mount("POST", "/api/v1/roles", 409, "<html>gateway said no</html>");

        ConflictError thrown = await Assert.ThrowsAsync<ConflictError>(
            () => Client.Management.Roles.CreateAsync(
                new CreateRoleRequest { Description = "Edits", IsGlobal = false, Name = "Editor" }));

        Assert.Contains("gateway said no", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>An error body carrying <c>error</c> rather than <c>message</c> is understood.</summary>
    [Fact]
    public async Task AnErrorKeyedBodyIsUnderstood()
    {
        Mount("GET", $"/api/v1/users/{ExampleId}", 404, """{"error":"gone for good"}""");

        NotFoundError thrown = await Assert.ThrowsAsync<NotFoundError>(
            () => Client.Management.Users.GetAsync(ExampleId));

        Assert.Contains("gone for good", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>An empty error body leaves the operation name standing alone.</summary>
    [Fact]
    public async Task AnEmptyErrorBodyStillNamesTheOperation()
    {
        Mount("GET", $"/api/v1/users/{ExampleId}", 404, string.Empty);

        NotFoundError thrown = await Assert.ThrowsAsync<NotFoundError>(
            () => Client.Management.Users.GetAsync(ExampleId));

        Assert.Contains("users.get", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>A 400 with no <c>errors</c> key is still a ValidationError, with no fields.</summary>
    [Fact]
    public async Task AValidationErrorWithoutFieldDetailCarriesNone()
    {
        Mount("PUT", $"/api/v1/users/{ExampleId}", 400, """{"message":"nope"}""");

        ValidationError thrown = await Assert.ThrowsAsync<ValidationError>(
            () => Client.Management.Users.UpdateAsync(
                ExampleId, new UpdateUserRequest { Email = "x@example.test" }));

        Assert.Empty(thrown.Fields);
    }

    /// <summary>An <c>errors</c> array whose entries lack a field contributes nothing.</summary>
    [Fact]
    public async Task AFieldErrorWithoutAFieldNameIsSkipped()
    {
        Mount("PUT", $"/api/v1/users/{ExampleId}", 422,
            """{"message":"nope","errors":[{"detail":"unhelpful"},{"field":"email"}]}""");

        ValidationError thrown = await Assert.ThrowsAsync<ValidationError>(
            () => Client.Management.Users.UpdateAsync(
                ExampleId, new UpdateUserRequest { Email = "x@example.test" }));

        Assert.Single(thrown.Fields);
        Assert.Equal("email", thrown.Fields[0].Field);
        Assert.Equal("is invalid", thrown.Fields[0].Message);
    }

    // ---- §27.8: what goes on the socket ---------------------------------

    /// <summary>A DELETE carries no body.</summary>
    [Fact]
    public async Task ADeleteSendsNoBody()
    {
        Route route = Mount("DELETE", $"/api/v1/users/{ExampleId}", 204, string.Empty);

        await Client.Management.Users.DeleteAsync(ExampleId);

        Assert.Equal(string.Empty, route.Last.Body);
    }

    /// <summary>Query parameters are sorted, so a request is reproducible from its telemetry.</summary>
    [Fact]
    public async Task QueryParametersAreSentInAStableOrder()
    {
        Route route = Mount("GET", "/api/v1/users", 200, PageOf(null));

        await Client.Management.Users.ListAsync(new PageRequest(offset: 40, limit: 20));

        Assert.Equal(new Dictionary<string, string> { ["limit"] = "20", ["offset"] = "40" },
            route.Last.Query);
    }

    /// <summary>A null query filter is omitted rather than sent empty.</summary>
    [Fact]
    public async Task ANullQueryFilterIsOmitted()
    {
        Route route = Mount("DELETE", $"/api/v1/roles/{ExampleId}/users/{ExampleId}", 204, string.Empty);

        await Client.Management.Roles.UnassignFromUserAsync(ExampleId, ExampleId, null);

        Assert.DoesNotContain("resource_id", route.Last.Query.Keys, StringComparer.Ordinal);
    }

    /// <summary>
    /// An object-shaped read that answers 204 is an error, not a null model.
    /// </summary>
    /// <remarks>
    /// The other two shapes have an honest empty value — a page with no items, a list
    /// with none — but there is no empty <c>Role</c>. Manufacturing one with default
    /// fields would hand the caller a record of something that does not exist.
    /// </remarks>
    [Fact]
    public async Task AnObjectReadWithNoBodyIsAnErrorNotAnEmptyModel()
    {
        Mount("GET", $"/api/v1/roles/{ExampleId}", 204, string.Empty);

        NetworkError thrown = await Assert.ThrowsAsync<NetworkError>(
            () => Client.Management.Roles.GetAsync(ExampleId));

        Assert.Contains("roles.get", thrown.Message, StringComparison.Ordinal);
        Assert.Contains("no body", thrown.Message, StringComparison.Ordinal);
    }
}
