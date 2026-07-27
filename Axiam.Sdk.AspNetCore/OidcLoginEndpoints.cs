using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// Configures <see cref="OidcLoginEndpointExtensions.MapAxiamOidcLogin"/>'s login-redirect
/// and callback endpoints (CONTRACT.md &#167;12). Both endpoints share one options value so
/// the two routes of a login flow cannot drift apart (same redirect URI, same scope).
/// </summary>
public sealed class AxiamOidcLoginOptions
{
    /// <summary>
    /// The relying party's redirect URI — the public URL of the callback route — replayed
    /// verbatim on the token exchange (the server compares the two). Required.
    /// </summary>
    /// <remarks>
    /// Mutable (<c>set</c>, not <c>init</c>) — mirrors <see cref="AxiamOptions"/>'s existing
    /// convention: the .NET options-callback pattern
    /// (<c>MapAxiamOidcLogin(loginPath, callbackPath, options =&gt; { &#8230; })</c>)
    /// configures an already-constructed instance through an <see cref="Action{T}"/>
    /// delegate, so properties must be settable after construction.
    /// </remarks>
    public required string RedirectUri { get; set; }

    /// <summary>The requested scope. <c>"openid"</c> is added automatically when absent
    /// (CONTRACT.md &#167;12.1 rule 4).</summary>
    public string? Scope { get; set; }

    /// <summary>
    /// Where to send the browser after a successful login. Falls back to the
    /// <see cref="OidcStateEntry.ReturnTo"/> captured at login time (from the
    /// <c>?return_to=</c> query parameter), then to a <c>200</c> JSON summary.
    /// </summary>
    public string? SuccessRedirect { get; set; }

    /// <summary>
    /// Called with the validated token set once the exchange succeeds — the hook where an
    /// application establishes its OWN session (sign a cookie, write a session row, &#8230;).
    /// This class deliberately does not do this for you: what a session means is the
    /// application's decision. Receives the consumed state entry too, so
    /// <see cref="OidcStateEntry.ReturnTo"/> and any other application data captured at
    /// login time is available. May be <c>null</c>.
    /// </summary>
    public Func<HttpContext, OidcTokenSet, OidcStateEntry, CancellationToken, Task>? OnSuccessAsync { get; set; }
}

/// <summary>
/// ASP.NET Core minimal-API endpoints implementing "Login with AXIAM" (CONTRACT.md
/// &#167;12) — <see cref="MapAxiamOidcLogin"/> wires the login-redirect and callback
/// endpoints into the existing middleware/DI pipeline, resolving the shared
/// <see cref="AxiamClient"/> and <see cref="IOidcStateStore"/> singletons
/// <see cref="ServiceCollectionExtensions.AddAxiam"/>/<see cref="ServiceCollectionExtensions.AddAxiamAspNetCore"/>
/// register.
/// </summary>
/// <remarks>
/// This class performs no token extraction, sets no cookie, and touches no
/// request/response object beyond what a minimal-API handler naturally does —
/// establishing the application's OWN session is deliberately left to
/// <see cref="AxiamOidcLoginOptions.OnSuccessAsync"/>, exactly as CONTRACT.md &#167;12
/// leaves "what a session means" to the application. The state store is what makes the two
/// HTTP requests of a redirect flow into one login: <c>OidcBegin</c> produces
/// <c>State</c>/<c>Nonce</c>/<c>CodeVerifier</c> in the login request, and only
/// <c>State</c> survives the round trip through the IdP, so the other two must be parked
/// somewhere the callback request can reach (&#167;12.3 rule 1 — the SDK's core &#167;12
/// operations store nothing themselves).
/// </remarks>
public static class OidcLoginEndpointExtensions
{
    /// <summary>
    /// Registers the "Login with AXIAM" login-redirect (<paramref name="loginPath"/>) and
    /// callback (<paramref name="callbackPath"/>) minimal-API endpoints.
    /// </summary>
    /// <remarks>
    /// Failure mapping (a login-glue convention, not itself contract-specified — CONTRACT.md
    /// &#167;12 T1 reference judgment call 19): <c>400 invalid_request</c> for a malformed
    /// callback; <c>401 authentication_failed</c> for an IdP error, an unknown/expired/
    /// already-used login state, an ID-token failure, or an OAuth2 protocol error;
    /// <c>503 oidc_unavailable</c> for a network failure reaching AXIAM (or any failure
    /// starting the flow). An optional <c>?return_to=</c> query parameter on the login
    /// request is captured with the state entry and used as the post-login destination when
    /// <see cref="AxiamOidcLoginOptions.SuccessRedirect"/> is unset — the caller (this
    /// application) owns the destination it names; that URL is never validated here
    /// (documented open-redirect responsibility of whoever populates <c>return_to</c>).
    /// </remarks>
    public static IEndpointRouteBuilder MapAxiamOidcLogin(
        this IEndpointRouteBuilder endpoints,
        string loginPath,
        string callbackPath,
        Action<AxiamOidcLoginOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(loginPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(callbackPath);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AxiamOidcLoginOptions { RedirectUri = string.Empty };
        configure(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.RedirectUri, $"{nameof(configure)}: {nameof(AxiamOidcLoginOptions.RedirectUri)}");

        endpoints.MapGet(loginPath, async (HttpContext context, AxiamClient client, IOidcStateStore store, CancellationToken cancellationToken) =>
        {
            AuthorizationRequest request;
            try
            {
                OidcConfiguration configuration = await client.OidcDiscoverAsync(cancellationToken).ConfigureAwait(false);
                request = client.OidcBegin(configuration, new OidcBeginParams { RedirectUri = options.RedirectUri, Scope = options.Scope });

                string? returnTo = context.Request.Query["return_to"];
                var entry = new OidcStateEntry(request.State, request.Nonce, request.CodeVerifier, options.RedirectUri, returnTo);
                await store.SaveAsync(entry, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception)
            {
                await WriteOidcErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "oidc_unavailable", "could not start the OIDC login flow").ConfigureAwait(false);
                return;
            }

            context.Response.Redirect(request.Url);
        });

        endpoints.MapGet(callbackPath, async (HttpContext context, AxiamClient client, IOidcStateStore store, CancellationToken cancellationToken) =>
        {
            IQueryCollection query = context.Request.Query;

            string? idpError = query["error"];
            if (!string.IsNullOrEmpty(idpError))
            {
                string? description = query["error_description"];
                string message = string.IsNullOrEmpty(description) ? idpError : $"{idpError}: {description}";
                await WriteOidcErrorAsync(context, StatusCodes.Status401Unauthorized, "authentication_failed", message).ConfigureAwait(false);
                return;
            }

            string? state = query["state"];
            string? code = query["code"];
            if (string.IsNullOrEmpty(state) || string.IsNullOrEmpty(code))
            {
                await WriteOidcErrorAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "callback is missing the state or code query parameter").ConfigureAwait(false);
                return;
            }

            // Single-use consume (§12.3 rule 1): a replayed callback finds nothing.
            // Unknown, already-consumed, and expired states are deliberately
            // indistinguishable to the caller.
            OidcStateEntry? entry = await store.ConsumeAsync(state, cancellationToken).ConfigureAwait(false);
            if (entry is null)
            {
                await WriteOidcErrorAsync(context, StatusCodes.Status401Unauthorized, "authentication_failed", "unknown, expired, or already-used login state").ConfigureAwait(false);
                return;
            }

            OidcTokenSet tokens;
            try
            {
                tokens = await client.OidcExchangeAsync(new OidcExchangeParams
                {
                    Code = code,
                    CodeVerifier = entry.CodeVerifier,
                    RedirectUri = entry.RedirectUri,
                    Nonce = entry.Nonce,
                }, cancellationToken).ConfigureAwait(false);
            }
            catch (NetworkError)
            {
                await WriteOidcErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "oidc_unavailable", "the AXIAM token endpoint is unreachable").ConfigureAwait(false);
                return;
            }
            catch (AuthError ex)
            {
                // Covers OAuthProtocolError and every §12.4 ID-token reason code too — a
                // login that cannot be proven is a failed login.
                await WriteOidcErrorAsync(context, StatusCodes.Status401Unauthorized, "authentication_failed", ex.Message).ConfigureAwait(false);
                return;
            }

            if (options.OnSuccessAsync is not null)
            {
                await options.OnSuccessAsync(context, tokens, entry, cancellationToken).ConfigureAwait(false);
            }

            string? destination = options.SuccessRedirect ?? entry.ReturnTo;
            if (!string.IsNullOrEmpty(destination))
            {
                context.Response.Redirect(destination);
                return;
            }

            var body = new Dictionary<string, object?> { ["authenticated"] = true, ["expires_in"] = tokens.ExpiresIn };
            if (tokens.IdClaims is { Sub.Length: > 0 } claims)
            {
                body["sub"] = claims.Sub;
            }
            await context.Response.WriteAsJsonAsync(body, cancellationToken).ConfigureAwait(false);
        });

        return endpoints;
    }

    private static Task WriteOidcErrorAsync(HttpContext context, int statusCode, string error, string message)
    {
        context.Response.StatusCode = statusCode;
        return context.Response.WriteAsJsonAsync(new { error, message });
    }
}
