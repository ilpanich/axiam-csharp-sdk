using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;

namespace Axiam.Sdk;

/// <summary>
/// The CONTRACT.md &#167;20 UMA 2.0 Protection API and ticket grant.
/// </summary>
/// <remarks>
/// <para>The resource-server side of User-Managed Access: register the resources
/// you guard, ask AXIAM what a caller would need, and exchange the resulting
/// permission ticket for a Requesting Party Token.</para>
///
/// <para><b>The rule this partial exists to not paper over:</b> a permission
/// ticket is single-use and is <b>not retryable</b> (&#167;20.2 rule 6). The
/// ticket is consumed <i>before</i> the request is evaluated, so a failed
/// exchange has already spent it — and under concurrency a retry is precisely
/// the second redemption that ilpanich/axiam#302's measured residual
/// describes.</para>
/// </remarks>
public sealed partial class AxiamClient
{
    /// <summary><c>grant_type</c> of the UMA ticket grant (UMA 2.0 &#167;3.3.1).</summary>
    private const string UmaTicketGrantType = "urn:ietf:params:oauth:grant-type:uma-ticket";

    /// <summary>The only <c>claim_token_format</c> AXIAM v1 accepts (&#167;20.2 rule 2).</summary>
    private const string UmaClaimTokenFormat = "urn:ietf:params:oauth:token-type:access_token";

    /// <summary>UMA 2.0 FedAuthz &#167;2.2 fixes this path at the host root.</summary>
    private const string RregPath = "/uma2/rreg/resource_set";

    /// <summary>
    /// <c>POST /uma2/rreg/resource_set</c> — registers a resource set (&#167;20.1).
    /// </summary>
    /// <remarks>
    /// The <paramref name="pat"/> is an explicit parameter, not this client's
    /// session. A Protection API Token must be a <b>client-credentials</b>
    /// token, because a ticket binds to the <c>client_id</c> that minted it —
    /// and this client's session is usually a <i>user</i> session, which names
    /// no client to bind to (&#167;20.2 rule 1).
    /// </remarks>
    /// <param name="pat">The Protection API Token.</param>
    /// <param name="resource">The resource set to register.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The registered set, carrying the server-assigned id.</returns>
    public async Task<ResourceSet> UmaRegisterResourceAsync(
        Sensitive<string> pat,
        ResourceSet resource,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);
        UmaResourceSetWire wire = await UmaProtectionAsync<UmaResourceSetWire>(
            HttpMethod.Post, RregPath, pat, UmaResourcePayload(resource),
            "uma resource registration failed", cancellationToken).ConfigureAwait(false);
        return FromWire(wire);
    }

    /// <summary><c>GET /uma2/rreg/resource_set/{id}</c> — reads a resource set (&#167;20.1).</summary>
    /// <param name="pat">The Protection API Token.</param>
    /// <param name="resourceId">The resource set id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The resource set.</returns>
    public async Task<ResourceSet> UmaReadResourceAsync(
        Sensitive<string> pat,
        Guid resourceId,
        CancellationToken cancellationToken = default)
    {
        UmaResourceSetWire wire = await UmaProtectionAsync<UmaResourceSetWire>(
            HttpMethod.Get, $"{RregPath}/{resourceId}", pat, null,
            "uma resource read failed", cancellationToken).ConfigureAwait(false);
        return FromWire(wire);
    }

    /// <summary>
    /// <c>PUT /uma2/rreg/resource_set/{id}</c> — replaces a resource set (&#167;20.1).
    /// </summary>
    /// <remarks>
    /// <b>The scope list is replaced, not merged</b> (&#167;20.2 rule 8).
    /// Whatever <c>resource.ResourceScopes</c> holds becomes the complete
    /// declared set; omitting a scope removes it, which is how a resource server
    /// drops an authority. This method performs no read-before-write.
    /// </remarks>
    /// <param name="pat">The Protection API Token.</param>
    /// <param name="resourceId">The resource set id.</param>
    /// <param name="resource">The new state.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The updated resource set.</returns>
    public async Task<ResourceSet> UmaUpdateResourceAsync(
        Sensitive<string> pat,
        Guid resourceId,
        ResourceSet resource,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resource);
        UmaResourceSetWire wire = await UmaProtectionAsync<UmaResourceSetWire>(
            HttpMethod.Put, $"{RregPath}/{resourceId}", pat, UmaResourcePayload(resource),
            "uma resource update failed", cancellationToken).ConfigureAwait(false);
        return FromWire(wire);
    }

    /// <summary><c>DELETE /uma2/rreg/resource_set/{id}</c> — deregisters (&#167;20.1).</summary>
    /// <param name="pat">The Protection API Token.</param>
    /// <param name="resourceId">The resource set id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the resource set is gone.</returns>
    public async Task UmaDeleteResourceAsync(
        Sensitive<string> pat,
        Guid resourceId,
        CancellationToken cancellationToken = default)
    {
        using HttpResponseMessage response = await UmaProtectionRequestAsync(
            HttpMethod.Delete, $"{RregPath}/{resourceId}", pat, null, cancellationToken)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await MapOAuth2ErrorAsync(response, "uma resource delete failed", cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>GET /uma2/rreg/resource_set</c> — lists the ids <b>this client</b>
    /// registered (&#167;20.1).
    /// </summary>
    /// <remarks>
    /// Not the tenant's whole resource tree: a protection scope does not entitle
    /// a caller to enumerate it.
    /// </remarks>
    /// <param name="pat">The Protection API Token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The registered resource set ids.</returns>
    public async Task<IReadOnlyList<Guid>> UmaListResourcesAsync(
        Sensitive<string> pat,
        CancellationToken cancellationToken = default)
    {
        List<Guid> ids = await UmaProtectionAsync<List<Guid>>(
            HttpMethod.Get, RregPath, pat, null, "uma resource list failed", cancellationToken)
            .ConfigureAwait(false);
        return ids;
    }

    /// <summary><c>POST /uma2/perm</c> — mints a permission ticket (&#167;20.1).</summary>
    /// <remarks>
    /// Scope names are validated <b>here</b>, against each resource's declared
    /// set. Asking for an undeclared scope is a <c>400</c>, not a denial — the
    /// two are different failures, and this SDK surfaces the distinction the
    /// server draws rather than flattening it.
    /// </remarks>
    /// <param name="pat">The Protection API Token.</param>
    /// <param name="permissions">The pairs the resource server requires.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The opaque ticket.</returns>
    public async Task<Sensitive<string>> UmaRequestTicketAsync(
        Sensitive<string> pat,
        IReadOnlyList<RequestedPermission> permissions,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(permissions);
        var body = permissions
            .Select(p => new UmaRequestedPermissionWire(p.ResourceId, p.ResourceScopes))
            .ToList();
        UmaTicketWire wire = await UmaProtectionAsync<UmaTicketWire>(
            HttpMethod.Post, "/uma2/perm", pat, body, "uma ticket request failed", cancellationToken)
            .ConfigureAwait(false);
        return Sensitive<string>.Wrap(wire.Ticket);
    }

    /// <summary>
    /// <c>POST /oauth2/token</c> with the uma-ticket grant (&#167;20.1) —
    /// exchanges a ticket for an RPT.
    /// </summary>
    /// <remarks>
    /// <para><b>This method never retries.</b> It issues exactly one request and
    /// is outside the &#167;16 retry policy — not on <c>5xx</c>, not on timeout,
    /// not on any transport failure (&#167;20.2 rule 6). The ticket is consumed
    /// <i>before</i> the request is evaluated, so a failed exchange has already
    /// spent it: a retry cannot succeed, and under concurrency it is precisely
    /// the second redemption that ilpanich/axiam#302's measured residual
    /// describes. On failure, request a <b>new</b> ticket.</para>
    ///
    /// <para>What this method deliberately does not do: no default
    /// <c>ClaimToken</c> (rule 2) — it is required; no auto-narrowing on
    /// <c>access_denied</c> (rule 3); and no adoption (rule 4) — the RPT is the
    /// <i>requesting party's</i> token.</para>
    ///
    /// <para>The four ticket refusals — unknown, expired, already used, wrong
    /// client — all answer <c>invalid_grant</c> with one message. This SDK does
    /// not try to tell them apart (&#167;20.4): the server collapses them so a
    /// caller cannot probe for live ticket handles.</para>
    /// </remarks>
    /// <param name="params">The ticket and the requesting party's token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The requesting party token.</returns>
    public async Task<RequestingPartyToken> UmaExchangeTicketAsync(
        UmaExchangeTicketParams @params,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);
        OidcConfiguration configuration =
            await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        string clientSecret = RequireOidcClientSecret(nameof(UmaExchangeTicketAsync));
        Guid tenantId = ResolveOidcTenantId(@params.TenantId);

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = UmaTicketGrantType,
            ["ticket"] = @params.Ticket.Reveal(),
            ["claim_token"] = @params.ClaimToken.Reveal(),
            ["claim_token_format"] = UmaClaimTokenFormat,
            ["client_id"] = RequireOidcClientId(),
            ["client_secret"] = clientSecret,
        };

        // One POST, no retry wrapper. See the rule-6 note above — this is the
        // §16 exception, and it is load-bearing rather than stylistic.
        using HttpResponseMessage response = await PostOAuth2FormAsync(
            configuration.TokenEndpoint, form, tenantId, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await MapUmaGrantErrorAsync(response, "uma ticket exchange request failed", cancellationToken)
                .ConfigureAwait(false);
        }

        UmaRptWire wire = await ReadOidcJsonAsync<UmaRptWire>(response, cancellationToken).ConfigureAwait(false);
        return new RequestingPartyToken(
            Sensitive<string>.Wrap(wire.AccessToken),
            wire.TokenType,
            wire.ExpiresIn);
    }

    /// <summary>
    /// Maps an error from the <b>uma-ticket grant</b>, where <c>access_denied</c>
    /// arrives as HTTP <b>403</b> (UMA 2.0 &#167;3.3.6) rather than the 400 every
    /// other OAuth2 error uses.
    /// </summary>
    /// <remarks>
    /// &#167;20.4 requires dispatching on the <c>error</c> field rather than the
    /// status, so the code reaches the caller whichever status carries it. This
    /// is kept local to the ticket grant on purpose:
    /// <c>MapOAuth2ErrorAsync</c> applies the OAuth2 mapping to 400/401 only,
    /// and widening that globally would change how every OAuth2 endpoint's 403
    /// is reported — a cross-cutting change this grant does not need. An
    /// ordinary REST 403 keeps mapping to <c>AuthzError</c>.
    /// </remarks>
    private static async Task<Exception> MapUmaGrantErrorAsync(
        HttpResponseMessage response,
        string context,
        CancellationToken cancellationToken)
    {
        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(body))
            {
                try
                {
                    OAuth2ErrorResponseWire? wire = JsonSerializer.Deserialize<OAuth2ErrorResponseWire>(body);
                    if (wire is { Error.Length: > 0 })
                    {
                        return new OAuthProtocolError(wire.Error, wire.ErrorDescription ?? string.Empty);
                    }
                }
                catch (JsonException)
                {
                    // Not a well-formed OAuth2ErrorResponse body — fall through
                    // rather than let a parse failure mask the real status.
                }
            }
        }
        return await MapOAuth2ErrorAsync(response, context, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The wire body for a register/update.
    /// </summary>
    /// <remarks>
    /// <c>resource_scopes</c> is always sent, even when empty: an update
    /// <b>replaces</b> the scope list, and omitting the key would leave the
    /// server's copy untouched (&#167;20.2 rule 8).
    /// </remarks>
    private static UmaResourceSetWire UmaResourcePayload(ResourceSet resource) =>
        new(null, resource.Name, resource.Type, resource.ResourceScopes ?? Array.Empty<string>());

    private static ResourceSet FromWire(UmaResourceSetWire wire) =>
        new(wire.Name, wire.Id, wire.Type, wire.ResourceScopes ?? Array.Empty<string>());

    private async Task<T> UmaProtectionAsync<T>(
        HttpMethod method,
        string path,
        Sensitive<string> pat,
        object? body,
        string fallbackMessage,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response =
            await UmaProtectionRequestAsync(method, path, pat, body, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await MapOAuth2ErrorAsync(response, fallbackMessage, cancellationToken).ConfigureAwait(false);
        }
        return await ReadOidcJsonAsync<T>(response, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// A PAT-authenticated Protection API request.
    /// </summary>
    /// <remarks>
    /// The PAT goes in <c>Authorization</c>. It is an explicit argument on every
    /// Protection API call rather than this client's own session, because a PAT
    /// must be a <b>client-credentials</b> token — a ticket binds to the
    /// <c>client_id</c> that minted it — and this client's session is usually a
    /// <i>user</i> session (&#167;20.2 rule 1).
    /// </remarks>
    private async Task<HttpResponseMessage> UmaProtectionRequestAsync(
        HttpMethod method,
        string path,
        Sensitive<string> pat,
        object? body,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pat);
        var request = new HttpRequestMessage(method, path);
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {pat.Reveal()}");
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, body.GetType());
        }
        return await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private sealed record UmaResourceSetWire(
        [property: JsonPropertyName("_id")] Guid? Id,
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("type")] string? Type,
        [property: JsonPropertyName("resource_scopes")] IReadOnlyList<string>? ResourceScopes);

    private sealed record UmaRequestedPermissionWire(
        [property: JsonPropertyName("resource_id")] Guid ResourceId,
        [property: JsonPropertyName("resource_scopes")] IReadOnlyList<string> ResourceScopes);

    private sealed record UmaTicketWire(
        [property: JsonPropertyName("ticket")] string Ticket);

    private sealed record UmaRptWire(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("token_type")] string TokenType,
        [property: JsonPropertyName("expires_in")] long ExpiresIn);
}
