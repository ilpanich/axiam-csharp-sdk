using System.Net;
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Token Exchange (RFC 8693) — CONTRACT.md &#167;15.
/// </summary>
/// <remarks>
/// Most of &#167;15 is a list of things an SDK must <i>not</i> helpfully do, so most of these
/// tests assert an absence: no defaulted <c>ActorToken</c>, no auto-narrow after
/// <c>invalid_scope</c>, no synthesised refresh token, no adoption.
/// </remarks>
[Trait("Category", "Fast")]
public class OidcTokenExchangeTests
{
    private const string TokenPath = "/oauth2/token";
    private const string SubjectToken = "subject-token-value";
    private const string ActorToken = "actor-token-value";

    private static (RoutingHandler Handler, AxiamClient Client) SetUp(bool confidential = true)
    {
        var handler = new RoutingHandler();
        OidcTestKit.MapDiscovery(handler);
        AxiamClient client = OidcTestKit.Client(
            handler,
            confidential ? OidcTestKit.Options() : OidcTestKit.Options(clientSecret: null));
        return (handler, client);
    }

    private static Dictionary<string, string>? MapExchange(
        RoutingHandler handler, out Func<Dictionary<string, string>?> formAccessor, string? scope = "orders:read", string? refreshToken = null)
    {
        Dictionary<string, string>? captured = null;
        handler.Map(TokenPath, request =>
        {
            captured = OidcTestKit.ReadForm(request);
            return OidcTestKit.JsonOk(OidcTestKit.ExchangeResponseJson(scope, refreshToken));
        });
        formAccessor = () => captured;
        return captured;
    }

    [Fact]
    public async Task TokenExchangeAsync_SendsTheRfc8693Grant_AndAuthenticates()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapExchange(handler, out Func<Dictionary<string, string>?> form);

        ExchangedToken result = await client.TokenExchangeAsync(new TokenExchangeParams(
            Sensitive<string>.Wrap(SubjectToken),
            Scopes: new[] { "orders:read", "orders:write" },
            Audience: "orders-service"));

        Dictionary<string, string> sent = form()!;
        Assert.Equal("urn:ietf:params:oauth:grant-type:token-exchange", sent["grant_type"]);
        Assert.Equal(SubjectToken, sent["subject_token"]);
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", sent["subject_token_type"]);
        Assert.Equal("orders:read orders:write", sent["scope"]);
        Assert.Equal("orders-service", sent["audience"]);
        // §15.1: the exchanging client is confidential and authenticates.
        Assert.True(sent.ContainsKey("client_secret"));

        Assert.Equal(OidcTestKit.IssuedToken, result.AccessToken.Reveal());
        // §15.2 rule 6: issued_token_type is surfaced, not dropped.
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", result.IssuedTokenType);
        Assert.Equal(300, result.ExpiresIn);
    }

    [Fact]
    public async Task TokenExchangeAsync_PublicClient_FailsClientSideWithNoWireCall()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp(confidential: false);
        int calls = 0;
        handler.Map(TokenPath, _ =>
        {
            calls++;
            return OidcTestKit.JsonOk(OidcTestKit.ExchangeResponseJson());
        });

        await Assert.ThrowsAsync<AuthError>(
            () => client.TokenExchangeAsync(new TokenExchangeParams(Sensitive<string>.Wrap(SubjectToken))));

        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task TokenExchangeAsync_AbsentActorToken_IsNeverDefaulted()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapExchange(handler, out Func<Dictionary<string, string>?> form);

        await client.TokenExchangeAsync(new TokenExchangeParams(Sensitive<string>.Wrap(SubjectToken)));

        // §15.2 rule 1: passing none asks for IMPERSONATION. An SDK that helpfully substituted
        // its own session token would silently turn that into a delegation — a different
        // operation with different risk.
        Assert.False(form()!.ContainsKey("actor_token"));
        Assert.False(form()!.ContainsKey("actor_token_type"));
    }

    [Fact]
    public async Task TokenExchangeAsync_ActorTokenAndTypeAreSentAsAPair()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapExchange(handler, out Func<Dictionary<string, string>?> form);

        await client.TokenExchangeAsync(new TokenExchangeParams(
            Sensitive<string>.Wrap(SubjectToken),
            ActorToken: Sensitive<string>.Wrap(ActorToken)));

        Assert.Equal(ActorToken, form()!["actor_token"]);
        // RFC 8693 §2.1 requires the pair; the type alone is a malformed request.
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", form()!["actor_token_type"]);
    }

    [Theory]
    [InlineData("invalid_request")]
    [InlineData("invalid_grant")]
    [InlineData("invalid_scope")]
    [InlineData("invalid_target")]
    [InlineData("unauthorized_client")]
    public async Task TokenExchangeAsync_ErrorCodesReachTheCallerUnchanged_WithNoRetry(string code)
    {
        // Including cross-tenant, which the server deliberately collapses into invalid_grant —
        // the SDK must not re-derive the distinction it withheld (a tenant-enumeration signal).
        (RoutingHandler handler, AxiamClient client) = SetUp();
        int calls = 0;
        handler.Map(TokenPath, _ =>
        {
            calls++;
            return OidcTestKit.JsonStatus(HttpStatusCode.BadRequest, OidcTestKit.OAuth2ErrorJson(code, $"{code} description"));
        });

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.TokenExchangeAsync(new TokenExchangeParams(
                Sensitive<string>.Wrap(SubjectToken),
                Scopes: new[] { "orders:read", "orders:admin" })));

        Assert.Equal(code, error.Error);
        // §15.2 rules 2-3: no retry, no downgrade, no auto-narrowing. The server refuses rather
        // than silently narrowing precisely so the caller finds out HERE.
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task TokenExchangeAsync_ServerSentRefreshToken_IsNotSurfaced()
    {
        // Deliberately hostile fixture: RFC 8693 issues no refresh token, so the record has no
        // property for one and there is nothing to synthesise.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapExchange(handler, out _, refreshToken: "should-not-exist");

        ExchangedToken result = await client.TokenExchangeAsync(
            new TokenExchangeParams(Sensitive<string>.Wrap(SubjectToken)));

        Assert.DoesNotContain("should-not-exist", result.ToString(), StringComparison.Ordinal);
        Assert.Equal(OidcTestKit.IssuedToken, result.AccessToken.Reveal());
    }

    [Fact]
    public async Task TokenExchangeAsync_GrantedScopeIsReadableWhenNarrowerThanRequested()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapExchange(handler, out _, scope: "orders:read");

        ExchangedToken result = await client.TokenExchangeAsync(new TokenExchangeParams(
            Sensitive<string>.Wrap(SubjectToken),
            Scopes: new[] { "orders:read", "orders:write" }));

        // §15.2 rule 7: the response scope is the GRANTED set and may be narrower than requested
        // even on success.
        Assert.Equal("orders:read", result.Scope);
    }

    [Fact]
    public async Task TokenExchangeAsync_EmptyScopeList_IsOmittedRatherThanSentEmpty()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapExchange(handler, out Func<Dictionary<string, string>?> form, scope: null);

        ExchangedToken result = await client.TokenExchangeAsync(new TokenExchangeParams(
            Sensitive<string>.Wrap(SubjectToken),
            Scopes: Array.Empty<string>()));

        // §12.1: an absent optional field is omitted, never sent empty.
        Assert.False(form()!.ContainsKey("scope"));
        Assert.Null(result.Scope);
    }

    [Fact]
    public async Task TokenExchangeAsync_IssuedTokenIsRedacted()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapExchange(handler, out _);

        ExchangedToken result = await client.TokenExchangeAsync(
            new TokenExchangeParams(Sensitive<string>.Wrap(SubjectToken)));

        // §15.5: the issued token is a bearer credential and must not render.
        Assert.DoesNotContain(OidcTestKit.IssuedToken, result.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(OidcTestKit.IssuedToken, result.AccessToken.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task TokenExchangeAsync_FailedExchange_NeverEchoesTheSubjectOrActorToken()
    {
        // §15.5 calls this out specifically: an exchange failure is exactly when a naive
        // implementation logs the request body.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map(TokenPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.BadRequest, OidcTestKit.OAuth2ErrorJson("invalid_grant", "bad")));

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.TokenExchangeAsync(new TokenExchangeParams(
                Sensitive<string>.Wrap(SubjectToken),
                ActorToken: Sensitive<string>.Wrap(ActorToken))));

        Assert.DoesNotContain(SubjectToken, error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(ActorToken, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TokenExchangeAsync_ResourceIsSentWhenSupplied()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapExchange(handler, out Func<Dictionary<string, string>?> form);

        await client.TokenExchangeAsync(new TokenExchangeParams(
            Sensitive<string>.Wrap(SubjectToken),
            Resource: "https://orders.example.com"));

        // RFC 8707's synonym for audience; the server refuses the pair when they disagree, so
        // the SDK passes both through rather than choosing.
        Assert.Equal("https://orders.example.com", form()!["resource"]);
    }
}
