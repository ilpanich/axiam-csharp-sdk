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
            AxiamClient.AccessTokenType,
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
            () => client.TokenExchangeAsync(new TokenExchangeParams(Sensitive<string>.Wrap(SubjectToken), AxiamClient.AccessTokenType)));

        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task TokenExchangeAsync_AbsentActorToken_IsNeverDefaulted()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapExchange(handler, out Func<Dictionary<string, string>?> form);

        await client.TokenExchangeAsync(new TokenExchangeParams(Sensitive<string>.Wrap(SubjectToken), AxiamClient.AccessTokenType));

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
            AxiamClient.AccessTokenType,
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
                AxiamClient.AccessTokenType,
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
            new TokenExchangeParams(Sensitive<string>.Wrap(SubjectToken), AxiamClient.AccessTokenType));

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
            AxiamClient.AccessTokenType,
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
            AxiamClient.AccessTokenType,
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
            new TokenExchangeParams(Sensitive<string>.Wrap(SubjectToken), AxiamClient.AccessTokenType));

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
                AxiamClient.AccessTokenType,
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
            AxiamClient.AccessTokenType,
            Resource: "https://orders.example.com"));

        // RFC 8707's synonym for audience; the server refuses the pair when they disagree, so
        // the SDK passes both through rather than choosing.
        Assert.Equal("https://orders.example.com", form()!["resource"]);
    }

    // -----------------------------------------------------------------------------------
    // §15.7 — external-IdP subject tokens (X4)
    //
    // No new operation: the same TokenExchangeAsync carries a partner IdP's token. What
    // changes is which subject tokens the server accepts and what its refusals mean, so
    // these tests are about not getting in the way of either.
    // -----------------------------------------------------------------------------------

    /// <summary>
    /// A token minted by a partner's IdP. Opaque to the SDK — deliberately not a well-formed
    /// JWT, because nothing here may decode it.
    /// </summary>
    private const string ExternalSubjectToken = "partner-idp-subject-token";

    /// <summary>
    /// The one normative <c>error_description</c> (&#167;15.7). It means "fix the AXIAM trust
    /// configuration", not "fix your token".
    /// </summary>
    private const string IssuerNotConfigured =
        "the subject token's issuer is not configured for token exchange";

    [Fact]
    public async Task TokenExchangeAsync_ExternalSubjectTokenType_IsSentVerbatim()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapExchange(handler, out Func<Dictionary<string, string>?> form, scope: "read:orders");

        ExchangedToken result = await client.TokenExchangeAsync(new TokenExchangeParams(
            Sensitive<string>.Wrap(ExternalSubjectToken),
            SubjectTokenType: AxiamClient.JwtTokenType,
            Scopes: new[] { "read:orders" },
            Audience: "https://orders.internal"));

        Dictionary<string, string> sent = form()!;
        // The caller named …:jwt, so …:jwt goes on the wire. §15.7: the SDK must not inspect
        // the subject token to pick this, and must not override it.
        Assert.Equal("urn:ietf:params:oauth:token-type:jwt", sent["subject_token_type"]);
        Assert.Equal(ExternalSubjectToken, sent["subject_token"]);
        // Delegation across a trust boundary is unsupported; nothing may add one.
        Assert.False(sent.ContainsKey("actor_token"));

        // The cross-domain path is not a different result shape, and §15.2 rules 6-7 hold.
        Assert.Equal(OidcTestKit.IssuedToken, result.AccessToken.Reveal());
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", result.IssuedTokenType);
        Assert.Equal("read:orders", result.Scope);
    }

    [Fact]
    public async Task TokenExchangeAsync_SubjectTokenType_IsNeverInferredFromTheToken()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        MapExchange(handler, out Func<Dictionary<string, string>?> form);

        // A subject token that *looks* exactly like a JWT, presented as an access token. An SDK
        // that sniffed the token would "correct" this to …:jwt; §15.7 says it must not look, so
        // what the caller named is what goes out. Being able to hold this wrong is the point:
        // only the caller knows.
        const string jwtShaped =
            "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL3BhcnRuZXIuZXhhbXBsZS8ifQ.sig";
        await client.TokenExchangeAsync(new TokenExchangeParams(Sensitive<string>.Wrap(jwtShaped), AxiamClient.AccessTokenType));

        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", form()!["subject_token_type"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task TokenExchangeAsync_OmittedSubjectTokenType_NeverReachesTheWire(string? omitted)
    {
        // §15.1: the type is REQUIRED and has no default. The positional record makes leaving it
        // out a compile error, but a caller can still pass null or blank through a
        // nullable-oblivious call site — so the SDK refuses client-side, with no wire call,
        // rather than sending …:access_token on their behalf. For a caller who actually held a
        // refresh token, that default would trade the invalid_request that NAMES the type for a
        // generic invalid_grant.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        int calls = 0;
        handler.Map(TokenPath, _ =>
        {
            calls++;
            return OidcTestKit.JsonOk(OidcTestKit.ExchangeResponseJson(null, null));
        });

        AuthError error = await Assert.ThrowsAsync<AuthError>(
            () => client.TokenExchangeAsync(new TokenExchangeParams(
                Sensitive<string>.Wrap(SubjectToken),
                omitted!)));

        Assert.Equal(0, calls);
        // The message has to name the way out, or the caller has to go read §15.1 to find it.
        Assert.Contains("SubjectTokenType", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TokenExchangeAsync_ActorTokenWithExternalSubjectToken_IsRefusedWithoutRetry()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        int calls = 0;
        Dictionary<string, string>? captured = null;
        handler.Map(TokenPath, request =>
        {
            calls++;
            captured = OidcTestKit.ReadForm(request);
            return OidcTestKit.JsonStatus(
                HttpStatusCode.BadRequest,
                OidcTestKit.OAuth2ErrorJson(
                    "invalid_request",
                    "actor_token is not supported for an external subject token"));
        });

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.TokenExchangeAsync(new TokenExchangeParams(
                Sensitive<string>.Wrap(ExternalSubjectToken),
                SubjectTokenType: AxiamClient.JwtTokenType,
                ActorToken: Sensitive<string>.Wrap(ActorToken))));

        Assert.Equal("invalid_request", error.Error);
        // §15.7: no retry, and no rewriting. Dropping the actor token and re-sending would turn
        // a delegation the caller asked for into an impersonation they did not.
        Assert.Equal(1, calls);
        Assert.Equal(ActorToken, captured!["actor_token"]);
        Assert.Equal("urn:ietf:params:oauth:token-type:jwt", captured!["subject_token_type"]);
    }

    [Theory]
    [InlineData("urn:ietf:params:oauth:token-type:refresh_token")]
    [InlineData("urn:ietf:params:oauth:token-type:id_token")]
    public async Task TokenExchangeAsync_RefusedSubjectTokenType_IsNeverRetriedAsAnother(string refused)
    {
        // A refresh token is a re-authentication credential and an ID token is an assertion to a
        // client about a login; neither is a bearer credential for an API, so both are refused BY
        // NAME. Retrying as …:jwt would present one as if it were.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        int calls = 0;
        Dictionary<string, string>? captured = null;
        handler.Map(TokenPath, request =>
        {
            calls++;
            captured = OidcTestKit.ReadForm(request);
            return OidcTestKit.JsonStatus(
                HttpStatusCode.BadRequest,
                OidcTestKit.OAuth2ErrorJson("invalid_request", "unsupported subject_token_type"));
        });

        await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.TokenExchangeAsync(new TokenExchangeParams(
                Sensitive<string>.Wrap(ExternalSubjectToken),
                SubjectTokenType: refused)));

        Assert.Equal(1, calls);
        Assert.Equal(refused, captured!["subject_token_type"]);
    }

    [Fact]
    public async Task TokenExchangeAsync_IssuerNotConfiguredDescription_ReachesTheCallerIntact()
    {
        (RoutingHandler handler, AxiamClient client) = SetUp();
        handler.Map(TokenPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.BadRequest,
            OidcTestKit.OAuth2ErrorJson("invalid_grant", IssuerNotConfigured)));

        OAuthProtocolError error = await Assert.ThrowsAsync<OAuthProtocolError>(
            () => client.TokenExchangeAsync(new TokenExchangeParams(
                Sensitive<string>.Wrap(ExternalSubjectToken),
                SubjectTokenType: AxiamClient.JwtTokenType)));

        Assert.Equal("invalid_grant", error.Error);
        // This is the ONLY distinguishable external failure, and the whole point of it is that an
        // integrator can tell "fix the AXIAM trust config" from "fix your token". Truncating or
        // rewording it destroys that.
        Assert.Equal(IssuerNotConfigured, error.ErrorDescription);
    }

    [Fact]
    public async Task TokenExchangeAsync_NoHelperReExchanges_AnExternallyExchangedToken()
    {
        // Tokens minted from an external subject token carry ext_exchange, and BOTH exchange
        // paths refuse a subject token bearing it: exchanges do not compose. The SDK's part is to
        // never feed a result back in by itself.
        (RoutingHandler handler, AxiamClient client) = SetUp();
        int calls = 0;
        handler.Map(TokenPath, _ =>
        {
            calls++;
            return OidcTestKit.JsonOk(OidcTestKit.ExchangeResponseJson("read:orders", null));
        });

        ExchangedToken result = await client.TokenExchangeAsync(new TokenExchangeParams(
            Sensitive<string>.Wrap(ExternalSubjectToken),
            SubjectTokenType: AxiamClient.JwtTokenType));

        Assert.Equal(OidcTestKit.IssuedToken, result.AccessToken.Reveal());
        // Exactly one exchange happened: nothing looped the result back in. §15.2 rule 5 is what
        // stops it — had the result been adopted, the next exchange would carry it as a *subject*
        // token, which is exactly the re-exchange §15.7 forbids, arrived at by accident rather
        // than by decision.
        Assert.Equal(1, calls);
    }
}
