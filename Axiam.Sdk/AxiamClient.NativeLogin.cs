using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;

namespace Axiam.Sdk;

// CONTRACT.md §37 — native sign-in with a provider ID token (contract 1.65).
public sealed partial class AxiamClient
{
    /// <summary>The grant type of CONTRACT.md &#167;37.1.</summary>
    public const string ProviderIdTokenGrantType = "urn:axiam:params:oauth:grant-type:provider-id-token";

    /// <summary>
    /// <c>POST /oauth2/token</c> with <c>grant_type=urn:axiam:params:oauth:grant-type:provider-id-token</c>
    /// (CONTRACT.md &#167;37) &#8212; signs a user in with the ID token a Google, Apple or Facebook
    /// <i>native</i> SDK produced for the app, and returns the client's ordinary token set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is <b>not</b> token exchange (&#167;15): do not route one through the other.
    /// </para>
    /// <para>
    /// <b>Single use, never retried.</b> The provider's token is spent once the server has
    /// verified it, so this call is never retried &#8212; not by the SDK and not by a wrapper it
    /// ships (&#167;37.2 rule 10). <c>invalid_grant</c> is the server's single answer to every
    /// refusal of the provider token and is surfaced as received, never refined. The recovery
    /// is a <b>fresh</b> provider ID token with a <b>fresh</b> nonce (see <see cref="NativeNonce"/>).
    /// A <c>consent_required</c> answer has also spent the token; it is not turned into a browser
    /// flow on the caller's behalf (rule 11).
    /// </para>
    /// <para>
    /// <b>Secrets.</b> <paramref name="idToken"/> and <paramref name="nonce"/> are credentials. Neither
    /// is logged, stored, cached or placed in an error (rule 12); hold the raw nonce only for
    /// the length of the attempt.
    /// </para>
    /// <para>
    /// <b>Scopes.</b> Nothing is added: with no <paramref name="scopes"/> the server grants the
    /// empty set, so there is no <c>openid</c> and no ID token. Pass <c>openid</c> to receive
    /// <see cref="OidcTokenSet.IdClaims"/> (validated under &#167;12.4 with the raw
    /// <paramref name="nonce"/> as the expected nonce) (rule 7, rule 8).
    /// </para>
    /// <para>
    /// <b>Client authentication</b> is the client's registered method: a public client sends
    /// <c>client_id</c> alone; a client configured with
    /// <see cref="Options.AxiamClientOptions.OidcClientSecret"/> sends <c>client_secret</c>
    /// in the body (rule 5). This SDK generates no DPoP proofs (&#167;21.9), so for a DPoP-bound
    /// client the server's <c>401 invalid_client</c> is surfaced.
    /// </para>
    /// </remarks>
    /// <param name="provider">
    /// The provider's UUID or its <c>provider_slug</c> &#8212; sent verbatim. A provider <i>kind</i> name
    /// (<c>google</c>) is not accepted by the server unless the operator also chose it as the slug
    /// (rule 2). Never trimmed, case-folded or looked up.
    /// </param>
    /// <param name="idToken">The ID token the provider's SDK produced for the app.</param>
    /// <param name="nonce">
    /// The <b>raw</b> nonce whose SHA-256 (lower-case hexadecimal) the provider's SDK was given
    /// (rule 3). Sent byte for byte; never hashed, replaced or generated here.
    /// </param>
    /// <param name="scopes">Scopes to request, space-joined; omitted from the body when <see langword="null"/> or empty.</param>
    /// <param name="resource">An RFC 8707 <c>resource</c>; omitted from the body when <see langword="null"/> or empty.</param>
    /// <param name="tenantId">Tenant UUID for the <c>tenant_id</c> query parameter (&#167;12.3 rule 4).</param>
    /// <param name="configuration">A pre-fetched discovery document, or <see langword="null"/> to use the cached one.</param>
    /// <param name="adoptAsCredential">
    /// Mirrors <see cref="LoginClientCredentialsParams.AdoptAsCredential"/> and
    /// <see cref="DeviceLoginParams.AdoptAsCredential"/> (&#167;37.2 rule 9): this port does not adopt a
    /// returned token set as the client's credential and throws <see cref="NotSupportedException"/> when it is set.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="provider"/>, <paramref name="idToken"/> or <paramref name="nonce"/> is null or empty
    /// &#8212; a programming error, raised with <b>no request sent</b> (rule 4).
    /// </exception>
    /// <exception cref="InvalidOperationException">No <c>OidcClientId</c> is configured.</exception>
    /// <exception cref="AuthError">
    /// A slug-only client with no <paramref name="tenantId"/> (&#167;12.3 rule 4, no request sent), or an
    /// ID-token validation failure (&#167;12.4).
    /// </exception>
    /// <exception cref="OAuthProtocolError">
    /// Any well-formed <c>OAuth2ErrorResponse</c> at any status (&#167;37.3).
    /// </exception>
    /// <exception cref="NetworkError">
    /// A transport failure, or a <c>5xx</c> without an error body. Indeterminate: the token may have been spent.
    /// </exception>
    public async Task<OidcTokenSet> LoginWithProviderIdTokenAsync(
        string provider,
        Sensitive<string> idToken,
        Sensitive<string> nonce,
        IReadOnlyList<string>? scopes = null,
        string? resource = null,
        Guid? tenantId = null,
        OidcConfiguration? configuration = null,
        bool adoptAsCredential = false,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        if (adoptAsCredential)
        {
            throw new NotSupportedException(
                "LoginWithProviderIdTokenAsync's adoptAsCredential is not implemented in this SDK port (CONTRACT.md §37.2 rule 9 follows the §12.1 MAY; see CHANGELOG.md).");
        }

        // §37.2 rule 4: refused before any request, discovery included. The messages name the
        // parameter, never its value.
        if (string.IsNullOrEmpty(provider))
        {
            throw new ArgumentException("provider must not be empty (CONTRACT.md §37.2 rule 4).", nameof(provider));
        }
        string idTokenValue = idToken.Reveal();
        if (string.IsNullOrEmpty(idTokenValue))
        {
            throw new ArgumentException("idToken must not be empty (CONTRACT.md §37.2 rule 4).", nameof(idToken));
        }
        string rawNonce = nonce.Reveal();
        if (string.IsNullOrEmpty(rawNonce))
        {
            throw new ArgumentException("nonce must not be empty (CONTRACT.md §37.2 rule 4).", nameof(nonce));
        }

        string clientId = RequireOidcClientId();
        // A slug-only client raises here, before discovery: no wire call (§12.3 rule 4).
        Guid tenant = ResolveOidcTenantId(tenantId);
        OidcConfiguration config = await ResolveOidcConfigurationAsync(configuration, cancellationToken).ConfigureAwait(false);

        // §37.1: exactly this field set, and nothing outside it.
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = ProviderIdTokenGrantType,
            ["client_id"] = clientId,
            ["provider"] = provider,
            ["id_token"] = idTokenValue,
            ["nonce"] = rawNonce,
        };
        AppendOidcClientSecretIfConfigured(form);
        if (scopes is { Count: > 0 })
        {
            form["scope"] = string.Join(' ', scopes);
        }
        if (!string.IsNullOrEmpty(resource))
        {
            form["resource"] = resource;
        }

        TokenResponseWire wire;
        // Never retried (rule 10): a single send, with no retry-eligible marking.
        using (HttpResponseMessage response = await PostOAuth2FormAsync(
                   PreferredRequiredEndpoint(config, a => a.TokenEndpoint, config.TokenEndpoint),
                   form, tenant, cancellationToken).ConfigureAwait(false))
        {
            if (!response.IsSuccessStatusCode)
            {
                throw await MapNativeLoginErrorAsync(response, cancellationToken).ConfigureAwait(false);
            }
            wire = await ReadOidcJsonAsync<TokenResponseWire>(response, cancellationToken).ConfigureAwait(false);
        }

        // §37.2 rule 8: the AXIAM ID token carries the request's nonce as sent, so the RAW value
        // is the expected one.
        var expectations = new IdTokenExpectations(config.Issuer, clientId, HasNonce: true, rawNonce, _oidcClockSkewSeconds);
        return await ToTokenSetAsync(wire, config, expectations, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The error mapping of CONTRACT.md &#167;37.3: a well-formed <c>OAuth2ErrorResponse</c> is an
    /// <see cref="OAuthProtocolError"/> at <i>any</i> status (a <c>5xx</c> with a body included),
    /// carrying the status and <c>Retry-After</c>; anything else goes through the &#167;2 mapper.
    /// The error is built from the response only, never from the request.
    /// </summary>
    private static async Task<Exception> MapNativeLoginErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        Exception mapped = await MapOAuth2ErrorAnyStatusAsync(response, "native sign-in failed", cancellationToken).ConfigureAwait(false);
        return mapped is OAuthProtocolError protocolError
            ? new OAuthProtocolError(protocolError.Error, protocolError.ErrorDescription)
            {
                HttpStatus = (int)response.StatusCode,
                RetryAfter = response.StatusCode == (HttpStatusCode)429 ? NetworkError.ParseRetryAfter(response) : null,
            }
            : mapped;
    }

    /// <summary>
    /// Generates the nonce pair a native sign-in needs (CONTRACT.md &#167;37.4) &#8212; PURE LOCAL
    /// COMPUTATION, no network I/O, so no <c>Async</c> suffix and no client instance required.
    /// </summary>
    /// <remarks>
    /// Give <see cref="ProviderNonce.Hashed"/> to the provider's SDK as <i>its</i> nonce, and pass
    /// <see cref="ProviderNonce.Raw"/> to <see cref="LoginWithProviderIdTokenAsync"/>. Giving the
    /// provider the raw value, or a hash in another encoding, comes back as the same generic
    /// <c>invalid_grant</c> as every other refusal. Each call returns a fresh pair; nothing is stored.
    /// </remarks>
    /// <returns>A fresh <see cref="ProviderNonce"/>.</returns>
    public static ProviderNonce NativeNonce()
    {
        // 32 CSPRNG bytes, base64url without padding: 43 ASCII characters.
        string raw = OidcPkce.RandomUrlSafeToken();
        return new ProviderNonce(Sensitive<string>.Wrap(raw), HashNonce(raw));
    }

    /// <summary>
    /// SHA-256 of the UTF-8 bytes of <paramref name="raw"/>, as lower-case hexadecimal (&#167;37.4 rule 2).
    /// </summary>
    internal static string HashNonce(string raw) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
}
