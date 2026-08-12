using System.Net;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// UMA 2.0 — CONTRACT.md &#167;20.7 required assertions.
/// </summary>
/// <remarks>
/// <para>Most of &#167;20, like &#167;15, is a list of things an SDK must
/// <i>not</i> helpfully do, so most of these tests assert an absence. The
/// centrepiece is &#167;20.2 rule 6: a permission ticket must never be
/// retried.</para>
///
/// <para>That rule is the one &#167;16 exception in the contract, and the only
/// way to assert it is to count requests. A ticket is consumed <i>before</i> the
/// request is evaluated, so a failed exchange has already spent it — and under
/// concurrency a retry is precisely the second redemption that
/// ilpanich/axiam#302's measured residual describes. "Exactly one request" is a
/// security assertion here, not a performance one.</para>
///
/// <para>Every test is named after the thing it stops.</para>
/// </remarks>
[Trait("Category", "Fast")]
public class OidcUmaTests
{
    private const string TokenPath = "/oauth2/token";
    private const string PermPath = "/uma2/perm";
    private const string RregPath = "/uma2/rreg/resource_set";
    private const string Pat = "pat-token-value";
    private const string Ticket = "ticket-value";
    private const string ClaimToken = "claim-token-value";

    private static readonly Guid ResourceId = Guid.Parse("99999999-8888-7777-6666-555555555555");

    private static (RoutingHandler Handler, AxiamClient Client) SetUp()
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(handler, OidcTestKit.Options());
        return (handler, client);
    }

    private static UmaExchangeTicketParams ExchangeParams() => new(
        Sensitive<string>.Wrap(Ticket),
        Sensitive<string>.Wrap(ClaimToken));

    private static string RptJson() =>
        """{"access_token":"rpt-value","token_type":"Bearer","expires_in":300}""";

    // -----------------------------------------------------------------------
    // §20.2 rule 6 — the ticket grant is never retried
    // -----------------------------------------------------------------------

    /// <summary>
    /// A <c>500</c> must not be retried. The ticket is spent whether or not the
    /// exchange succeeded, so a retry cannot succeed — and it is the concurrent
    /// redemption ilpanich/axiam#302 measures.
    /// </summary>
    [Fact]
    public async Task A5xxOnTheTicketGrant_IsNotRetried()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map(TokenPath, _ => new HttpResponseMessage(HttpStatusCode.InternalServerError));

        await Assert.ThrowsAnyAsync<Exception>(() => client.UmaExchangeTicketAsync(ExchangeParams()));

        Assert.Equal(1, handler.CountFor(TokenPath));
    }

    /// <summary>
    /// <c>invalid_grant</c> is what a replayed ticket gets, and it is not
    /// retried either.
    /// </summary>
    [Fact]
    public async Task AnInvalidGrantOnTheTicketGrant_IsNotRetried()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map(TokenPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.BadRequest,
            OidcTestKit.OAuth2ErrorJson(
                "invalid_grant", "permission ticket is invalid, expired, or already used")));

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.UmaExchangeTicketAsync(ExchangeParams()));

        Assert.Equal("invalid_grant", error.Error);
        Assert.Equal(1, handler.CountFor(TokenPath));
    }

    /// <summary>
    /// <c>access_denied</c> arrives as <b>403</b> on this grant (UMA 2.0
    /// &#167;3.3.6), unlike RFC 8628's, which is a 400. The SDK dispatches on
    /// the <c>error</c> field, so the code reaches the caller either way — and
    /// the refusal is not auto-narrowed into a smaller ticket request
    /// (&#167;20.2 rule 3).
    /// </summary>
    [Fact]
    public async Task AccessDenied_SurfacesAsItself_AndIsNotAutoNarrowed()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map(TokenPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.Forbidden,
            OidcTestKit.OAuth2ErrorJson(
                "access_denied",
                "the requesting party is not authorized for every requested permission")));

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.UmaExchangeTicketAsync(ExchangeParams()));

        Assert.Equal("access_denied", error.Error);
        Assert.Equal(1, handler.CountFor(TokenPath));
    }

    // -----------------------------------------------------------------------
    // The ticket grant's wire shape
    // -----------------------------------------------------------------------

    [Fact]
    public async Task TheGrant_SendsTheRequiredClaimTokenAndFormat()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        Dictionary<string, string>? captured = null;
        handler.Map(TokenPath, request =>
        {
            captured = OidcTestKit.ReadForm(request);
            return OidcTestKit.JsonOk(RptJson());
        });

        RequestingPartyToken rpt = await client.UmaExchangeTicketAsync(ExchangeParams());

        Dictionary<string, string> sent = captured!;
        Assert.Equal("urn:ietf:params:oauth:grant-type:uma-ticket", sent["grant_type"]);
        Assert.Equal(Ticket, sent["ticket"]);
        Assert.Equal(ClaimToken, sent["claim_token"]);
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", sent["claim_token_format"]);
        Assert.Equal("rpt-value", rpt.AccessToken.Reveal());
        Assert.Equal(300, rpt.ExpiresIn);
    }

    /// <summary>
    /// &#167;20.2 rule 5: the grant issues no refresh token, so the record has
    /// no component for one — an application that wants a fresh RPT re-runs the
    /// grant. Asserted structurally, because a property that does not exist
    /// cannot be populated by a server that sends one anyway.
    /// </summary>
    [Fact]
    public void TheRptRecord_CannotCarryARefreshToken()
    {
        Assert.DoesNotContain(
            typeof(RequestingPartyToken).GetProperties(),
            p => p.Name.Contains("refresh", StringComparison.OrdinalIgnoreCase));
    }

    // -----------------------------------------------------------------------
    // The Protection API
    // -----------------------------------------------------------------------

    /// <summary>
    /// The UMA <c>_id</c> <b>is</b> the AXIAM resource id — there is no parallel
    /// identifier to translate through.
    /// </summary>
    [Fact]
    public async Task ARegisteredId_IsUsableAsATicketResourceId()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map(RregPath, request => request.Method == HttpMethod.Post
            ? OidcTestKit.JsonStatus(HttpStatusCode.Created,
                $$"""{"_id":"{{ResourceId}}","name":"invoice-7","type":"document","resource_scopes":["view"]}""")
            : new HttpResponseMessage(HttpStatusCode.NotFound));

        string? permBody = null;
        handler.Map(PermPath, request =>
        {
            permBody = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            return OidcTestKit.JsonStatus(HttpStatusCode.Created, """{"ticket":"ticket-value"}""");
        });

        ResourceSet registered = await client.UmaRegisterResourceAsync(
            Sensitive<string>.Wrap(Pat),
            new ResourceSet("invoice-7", Type: "document", ResourceScopes: new[] { "view" }));

        Assert.Equal(ResourceId, registered.Id);

        Sensitive<string> ticket = await client.UmaRequestTicketAsync(
            Sensitive<string>.Wrap(Pat),
            new[] { new RequestedPermission(registered.Id!.Value, new[] { "view" }) });

        Assert.Equal(Ticket, ticket.Reveal());
        Assert.Contains(ResourceId.ToString(), permBody!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ThePat_IsSentAsABearerToken()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        string? auth = null;
        handler.Map(PermPath, request =>
        {
            auth = request.Headers.TryGetValues("Authorization", out IEnumerable<string>? values)
                ? values.FirstOrDefault()
                : null;
            return OidcTestKit.JsonStatus(HttpStatusCode.Created, """{"ticket":"ticket-value"}""");
        });

        await client.UmaRequestTicketAsync(
            Sensitive<string>.Wrap(Pat),
            new[] { new RequestedPermission(ResourceId, new[] { "view" }) });

        Assert.Equal($"Bearer {Pat}", auth);
    }

    /// <summary>
    /// &#167;20.2 rule 8: an update replaces the scope list. No GET is mapped,
    /// so a read-modify-write implementation would 404 here rather than pass
    /// quietly.
    /// </summary>
    [Fact]
    public async Task AnUpdate_SendsOnlyTheScopesGiven_AndDoesNotReadFirst()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        string? body = null;
        handler.Map($"{RregPath}/{ResourceId}", request =>
        {
            body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            return OidcTestKit.JsonOk(
                $$"""{"_id":"{{ResourceId}}","name":"invoice-7","resource_scopes":["view"]}""");
        });

        await client.UmaUpdateResourceAsync(
            Sensitive<string>.Wrap(Pat),
            ResourceId,
            new ResourceSet("invoice-7", Type: "document", ResourceScopes: new[] { "view" }));

        Assert.Equal(1, handler.CountFor($"{RregPath}/{ResourceId}"));
        Assert.Contains("\"view\"", body!, StringComparison.Ordinal);
    }

    /// <summary>
    /// Omitting the key would leave the server's copy untouched, which would
    /// make clearing a scope set impossible through the SDK.
    /// </summary>
    [Fact]
    public async Task AnUpdateThatDropsEveryScope_StillSendsTheKey()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        string? body = null;
        handler.Map($"{RregPath}/{ResourceId}", request =>
        {
            body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            return OidcTestKit.JsonOk(
                $$"""{"_id":"{{ResourceId}}","name":"invoice-7","resource_scopes":[]}""");
        });

        await client.UmaUpdateResourceAsync(
            Sensitive<string>.Wrap(Pat), ResourceId, new ResourceSet("invoice-7"));

        using JsonDocument parsed = JsonDocument.Parse(body!);
        Assert.True(parsed.RootElement.TryGetProperty("resource_scopes", out JsonElement scopes));
        Assert.Empty(scopes.EnumerateArray());
    }

    [Fact]
    public async Task ANonPatRefusal_ReachesTheCaller()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map(PermPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.Forbidden,
            """{"error":"authorization_denied","message":"the protection API requires the 'uma_protection' scope"}"""));

        await Assert.ThrowsAnyAsync<Exception>(() => client.UmaRequestTicketAsync(
            Sensitive<string>.Wrap("not-a-pat"),
            new[] { new RequestedPermission(ResourceId, new[] { "view" }) }));

        Assert.Equal(1, handler.CountFor(PermPath));
    }

    [Fact]
    public async Task TheListing_ReturnsIds()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map(RregPath, _ => OidcTestKit.JsonOk($$"""["{{ResourceId}}"]"""));

        IReadOnlyList<Guid> ids = await client.UmaListResourcesAsync(Sensitive<string>.Wrap(Pat));

        Assert.Equal(new[] { ResourceId }, ids);
    }

    // -----------------------------------------------------------------------
    // §20.3 the challenge helpers
    // -----------------------------------------------------------------------

    [Fact]
    public void ParsesAWellFormedChallenge()
    {
        UmaChallenge? parsed = UmaChallenge.Parse(
            $"UMA realm=\"example\", as_uri=\"https://id.example\", ticket=\"{Ticket}\"");

        Assert.NotNull(parsed);
        Assert.Equal("example", parsed!.Realm);
        Assert.Equal("https://id.example", parsed.AsUri);
        Assert.Equal(Ticket, parsed.Ticket!.Value.Reveal());
    }

    [Fact]
    public void RejectsASchemeThatMerelyStartsWithUma()
    {
        Assert.Null(UmaChallenge.Parse("Bearer realm=\"example\""));
        Assert.Null(UmaChallenge.Parse("UMAX realm=\"example\""));
    }

    [Fact]
    public void TheChallengeRoundTripsThroughTheEmitHalf()
    {
        string header = UmaChallenge.Header(
            "example", "https://id.example", Sensitive<string>.Wrap("tkt"));
        UmaChallenge? parsed = UmaChallenge.Parse(header);

        Assert.NotNull(parsed);
        Assert.Equal("https://id.example", parsed!.AsUri);
        Assert.Equal("tkt", parsed.Ticket!.Value.Reveal());
    }

    /// <summary>&#167;20.6: the ticket's 60-second life is exactly what invites logging it.</summary>
    [Fact]
    public void TheTicketIsRedactedInToString()
    {
        UmaChallenge? parsed = UmaChallenge.Parse("UMA ticket=\"super-secret-ticket\"");

        Assert.NotNull(parsed);
        Assert.DoesNotContain("super-secret-ticket", parsed!.ToString(), StringComparison.Ordinal);
    }
}
