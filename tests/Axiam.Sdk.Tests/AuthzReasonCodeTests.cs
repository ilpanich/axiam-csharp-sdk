using System.Net;
using System.Text;
using Axiam.Sdk.Core;
using Axiam.Sdk.Rest;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Decision reason codes — CONTRACT.md &#167;11 rule 9 (B1 deny-override).
/// </summary>
/// <remarks>
/// The rule exists because the two refusals mean <b>opposite things to the person on the other
/// end</b>: <c>no_grant</c> says <i>ask an admin for access</i>, <c>denied_by_rule</c> says <i>an
/// admin has already decided</i>. An application that cannot tell them apart sends users to raise
/// tickets that will be refused.
/// </remarks>
[Trait("Category", "Fast")]
public class AuthzReasonCodeTests
{
    private static readonly Uri BaseUrl = new("https://axiam.test");

    private static async Task<AccessDecision> CheckAsync(string json)
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        });
        var client = new AuthzRestClient(new HttpClient(handler) { BaseAddress = BaseUrl });
        return await client.CheckAccessDecisionAsync("users:get", Guid.NewGuid());
    }

    [Fact]
    public async Task AnAllow_SurfacesTheAllowedReasonCode()
    {
        AccessDecision decision = await CheckAsync("""{"allowed":true,"reason_code":"allowed"}""");

        Assert.True(decision.Allowed);
        Assert.Equal(AxiamReasonCode.Allowed, decision.ReasonCode);
    }

    [Fact]
    public async Task NoGrantAndDeniedByRule_AreNotCollapsed()
    {
        AccessDecision noGrant = await CheckAsync("""{"allowed":false,"reason_code":"no_grant"}""");
        AccessDecision byRule = await CheckAsync("""{"allowed":false,"reason_code":"denied_by_rule"}""");

        // Both are refusals…
        Assert.False(noGrant.Allowed);
        Assert.False(byRule.Allowed);
        // …and the SDK must not reduce them to that shared false.
        Assert.Equal(AxiamReasonCode.NoGrant, noGrant.ReasonCode);
        Assert.Equal(AxiamReasonCode.DeniedByRule, byRule.ReasonCode);
        Assert.NotEqual(noGrant.ReasonCode, byRule.ReasonCode);
    }

    [Fact]
    public async Task AnUnknownReasonCode_IsSurfacedVerbatimAndChangesNothing()
    {
        // §11 rule 9: an SDK that does not recognise a code MUST surface it unchanged and MUST NOT
        // let it affect the outcome, which `allowed` carries alone. This is what lets the server
        // add a fourth code without breaking every deployed SDK.
        AccessDecision denied = await CheckAsync("""{"allowed":false,"reason_code":"denied_by_some_future_thing"}""");
        Assert.False(denied.Allowed);
        Assert.Equal("denied_by_some_future_thing", denied.ReasonCode);

        AccessDecision allowed = await CheckAsync("""{"allowed":true,"reason_code":"something-unrecognised"}""");
        Assert.True(allowed.Allowed);
    }

    [Fact]
    public async Task AnOlderServerOmittingTheField_IsNotAnError()
    {
        // A newer SDK against an older server: the field is simply absent, and that MUST degrade to
        // today's behaviour rather than failing to parse.
        AccessDecision denied = await CheckAsync("""{"allowed":false}""");
        Assert.False(denied.Allowed);
        Assert.Null(denied.ReasonCode);

        AccessDecision allowed = await CheckAsync("""{"allowed":true,"reason":"role grants it"}""");
        Assert.True(allowed.Allowed);
        Assert.Null(allowed.ReasonCode);
        Assert.Equal("role grants it", allowed.Reason);
    }

    [Theory]
    [InlineData("no_grant")]
    [InlineData("denied_by_rule")]
    public async Task CheckAccessAsync_StillReturnsFalseForBothRefusals(string code)
    {
        // §11 rule 9 is about REPORTING, not enforcement: the bool-returning method answers false
        // identically for either refusal, and an SDK must not start varying enforcement on the code.
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($$"""{"allowed":false,"reason_code":"{{code}}"}""", Encoding.UTF8, "application/json"),
        });
        var client = new AuthzRestClient(new HttpClient(handler) { BaseAddress = BaseUrl });

        Assert.False(await client.CheckAccessAsync("users:get", Guid.NewGuid()));
        Assert.False(await client.CanAsync("users:get", Guid.NewGuid()));
    }

    [Fact]
    public async Task BatchCheckDecisionsAsync_SurfacesAReasonCodePerDecision()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """
                {"results":[
                  {"allowed":true,"reason_code":"allowed"},
                  {"allowed":false,"reason_code":"no_grant"},
                  {"allowed":false,"reason_code":"denied_by_rule"}
                ]}
                """,
                Encoding.UTF8,
                "application/json"),
        });
        var client = new AuthzRestClient(new HttpClient(handler) { BaseAddress = BaseUrl });

        IReadOnlyList<AccessDecision> decisions = await client.BatchCheckDecisionsAsync(new[]
        {
            new AuthzRestClient.AccessCheck("users:get", Guid.NewGuid()),
            new AuthzRestClient.AccessCheck("users:update", Guid.NewGuid()),
            new AuthzRestClient.AccessCheck("users:delete", Guid.NewGuid()),
        });

        Assert.Equal(3, decisions.Count);
        Assert.Equal(AxiamReasonCode.Allowed, decisions[0].ReasonCode);
        Assert.Equal(AxiamReasonCode.NoGrant, decisions[1].ReasonCode);
        Assert.Equal(AxiamReasonCode.DeniedByRule, decisions[2].ReasonCode);
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;

        public FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(_respond(request));
    }
}
