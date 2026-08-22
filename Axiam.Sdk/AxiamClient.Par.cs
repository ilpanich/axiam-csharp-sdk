using System.Net.Http;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;

namespace Axiam.Sdk;

// CONTRACT.md §26 — Pushed Authorization Requests (RFC 9126).
public sealed partial class AxiamClient
{
    /// <summary>
    /// <c>POST /oauth2/par</c> (CONTRACT.md &#167;26.1) — push the authorization request
    /// over the back channel and get an opaque handle to redirect with.
    /// </summary>
    /// <remarks>
    /// PAR moves the authorization request off the browser. Instead of putting
    /// <c>scope</c>, <c>redirect_uri</c>, <c>state</c> and the PKCE challenge into a URL
    /// the user agent carries, the client POSTs them straight to AXIAM over an
    /// authenticated channel and puts an opaque <c>request_uri</c> in the redirect. What
    /// travels through the browser is then a random string that cannot be edited into
    /// meaning something else.
    /// <para>
    /// <b>Required for a FAPI 2.0 client</b>: <c>profile: "fapi2"</c> refuses a
    /// registration that does not set <c>require_par</c>, so such a client cannot authorize
    /// any other way (&#167;21.1).
    /// </para>
    /// <para>
    /// Not retried on a <c>5xx</c> or a transport failure — it is a POST that creates
    /// server state, so it falls outside &#167;16.2's read-only eligibility exactly as
    /// <see cref="OidcExchangeAsync"/> does. The safe recovery is a fresh push, which costs
    /// one round trip and cannot double-consume anything (&#167;26.2 rule 4).
    /// </para>
    /// </remarks>
    /// <exception cref="AuthError">
    /// The discovery document advertises no PAR endpoint — raised client-side with no wire
    /// call, following &#167;12.7.2 rule 1's discipline: never synthesise the URL from the
    /// issuer.
    /// </exception>
    public async Task<PushedAuthorizationRequest> OidcParAsync(
        OidcParParams @params,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        ArgumentNullException.ThrowIfNull(@params);
        ArgumentException.ThrowIfNullOrWhiteSpace(@params.RedirectUri);

        OidcConfiguration configuration =
            await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        string clientId = RequireOidcClientId();

        if (string.IsNullOrEmpty(configuration.PushedAuthorizationRequestEndpoint))
        {
            throw new AuthError(
                "the authorization server's discovery document advertises no " +
                "pushed_authorization_request_endpoint: this server does not support RFC 9126 " +
                "(CONTRACT.md §26.1).");
        }

        // §26.2 rule 1: everything below was computed by OidcBegin. There is no second
        // generator here, and there must not be — two sources for state or the PKCE pair
        // are two things that can disagree.
        var form = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["response_type"] = "code",
            ["redirect_uri"] = @params.RedirectUri,
            ["scope"] = NormalizeScope(@params.Scope),
            ["state"] = @params.Request.State,
            ["nonce"] = @params.Request.Nonce,
            ["code_challenge"] = OidcPkce.ComputeCodeChallenge(@params.Request.CodeVerifier.Reveal()),
            ["code_challenge_method"] = OidcPkce.CodeChallengeMethodS256,
        };
        AppendOidcClientSecretIfConfigured(form);

        Guid tenantId = ResolveOidcTenantId(@params.TenantId);
        PushedAuthorizationResponseWire wire;

        // 201, not 200. RFC 9126 §2.2 specifies Created, and this is the one thing an
        // implementation of this section gets wrong: a success predicate written == 200
        // treats every successful push as a failure while passing every other assertion.
        // IsSuccessStatusCode admits both, which is the point.
        using (HttpResponseMessage response = await PostOAuth2FormAsync(
                   configuration.PushedAuthorizationRequestEndpoint, form, tenantId, cancellationToken).ConfigureAwait(false))
        {
            if (!response.IsSuccessStatusCode)
            {
                throw await MapOAuth2ErrorAsync(response, "pushed authorization request failed", cancellationToken)
                    .ConfigureAwait(false);
            }
            wire = await ReadOidcJsonAsync<PushedAuthorizationResponseWire>(response, cancellationToken).ConfigureAwait(false);
        }

        if (string.IsNullOrEmpty(wire.RequestUri))
        {
            throw NetworkError.FromException(
                new InvalidOperationException("request_uri missing"),
                "pushed authorization response carried no request_uri");
        }

        // §26.2 rule 2: exactly two query parameters. The server REFUSES a request carrying
        // both a request_uri and any inline authorization parameter rather than merging
        // them: an attacker supplies the inline value they want and lets the pushed copy
        // satisfy whichever check reads the other one. Re-adding them "for compatibility"
        // restores the attack — which is why any query the discovered endpoint already
        // carried is dropped here rather than preserved.
        if (!Uri.TryCreate(configuration.AuthorizationEndpoint, UriKind.Absolute, out Uri? authorizationEndpoint))
        {
            throw NetworkError.FromException(
                new InvalidOperationException(configuration.AuthorizationEndpoint),
                "discovery document authorization_endpoint is not a valid absolute URL");
        }

        string url = $"{authorizationEndpoint.GetLeftPart(UriPartial.Path)}" +
                     $"?{EncodeQueryParam("client_id", clientId)}" +
                     $"&{EncodeQueryParam("request_uri", wire.RequestUri)}";

        return new PushedAuthorizationRequest(
            url,
            Sensitive.Of(wire.RequestUri),
            wire.ExpiresIn,
            @params.Request.State,
            @params.Request.Nonce,
            @params.Request.CodeVerifier);
    }
}
