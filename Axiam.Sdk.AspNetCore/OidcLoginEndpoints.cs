using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

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
    /// <c>?return_to=</c> query parameter) when that is a same-origin relative path (see
    /// <see cref="AllowReturnTo"/>), then to a <c>200</c> JSON summary.
    /// </summary>
    public string? SuccessRedirect { get; set; }

    /// <summary>
    /// Widens the <c>return_to</c> rule (CONTRACT.md &#167;12.8 rule 3; contract 1.68). By default a
    /// <c>return_to</c> is honoured only when it is a same-origin relative path: it starts with a single
    /// <c>/</c>, does not start with <c>//</c> or <c>/\</c>, and contains no backslash and no control
    /// character. Supply a predicate to accept more, for example an allowlist of the application's other
    /// origins; it is consulted, when the value is stored and again before it is followed, only for a value the
    /// default rule refuses, and a predicate that throws accepts nothing. <c>null</c> — the default — means
    /// the default rule alone decides. There is no built-in predicate that accepts absolute URLs.
    /// </summary>
    public Func<string, bool>? AllowReturnTo { get; set; }

    /// <summary>
    /// Called with the validated token set once the exchange succeeds — the hook where an
    /// application establishes its OWN session (sign a cookie, write a session row, &#8230;).
    /// This class deliberately does not do this for you: what a session means is the
    /// application's decision. Receives the consumed state entry too, so
    /// <see cref="OidcStateEntry.ReturnTo"/> and any other application data captured at
    /// login time is available. May be <c>null</c>.
    /// </summary>
    /// <remarks>
    /// The <see cref="HttpContext"/> is the request that completed the sign-in, so an application
    /// creates its session on it without ambient context. It runs only after the callback has proved
    /// it came from the browser that started the login (the binding cookie, CONTRACT.md &#167;12.8) and
    /// the code exchange and ID-token checks have succeeded.
    /// </remarks>
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
/// This class performs no token extraction and sets no application cookie — its one cookie is
/// the browser-binding cookie of CONTRACT.md &#167;12.8 (<c>__Host-axiam_oidc_bind</c>, or
/// <c>axiam_oidc_bind</c> on a plain-HTTP loopback <see cref="AxiamOidcLoginOptions.RedirectUri"/>),
/// set at login and cleared on every callback response. Establishing the application's OWN
/// session is deliberately left to
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
    /// <see cref="AxiamOidcLoginOptions.SuccessRedirect"/> is unset — but only a same-origin
    /// relative path is kept (CONTRACT.md &#167;12.8 rule 3; contract 1.68): an absolute URL, a
    /// scheme-relative one, a backslash form or a value with a control character is dropped at login
    /// and checked again before the redirect, and the flow falls back to the JSON summary.
    /// <para>
    /// <b>Browser binding (&#167;12.8 rule 1).</b> The login route sets a random binding cookie and stores
    /// its SHA-256 on the entry; the callback consumes the entry first and then refuses, with the same
    /// <c>401</c> it answers for an unknown state, unless the request presents the matching cookie — and
    /// in that case neither exchanges the code nor calls
    /// <see cref="AxiamOidcLoginOptions.OnSuccessAsync"/>. Every callback response clears the cookie.
    /// </para>
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
            string binding;
            try
            {
                OidcConfiguration configuration = await client.OidcDiscoverAsync(cancellationToken).ConfigureAwait(false);
                request = client.OidcBegin(configuration, new OidcBeginParams { RedirectUri = options.RedirectUri, Scope = options.Scope });

                // §12.8 rule 3: a return_to that is not a same-origin relative path (or allowed by the
                // integrator's predicate) is dropped; the entry is stored without it.
                string? returnTo = context.Request.Query["return_to"];
                if (!OidcLoginBinding.IsAcceptableReturnTo(returnTo, options.AllowReturnTo))
                {
                    returnTo = null;
                }

                // §12.8 rule 1: a fresh binding value every login (a cookie the request presents is never
                // reused); only its digest is stored.
                binding = OidcLoginBinding.NewValue();
                var entry = new OidcStateEntry(request.State, request.Nonce, request.CodeVerifier, options.RedirectUri, returnTo, OidcLoginBinding.Digest(binding));
                await store.SaveAsync(entry, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception)
            {
                await WriteOidcErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "oidc_unavailable", "could not start the OIDC login flow").ConfigureAwait(false);
                return;
            }

            OidcLoginBinding.Set(context.Response, options.RedirectUri, binding);
            context.Response.Redirect(request.Url);
        });

        endpoints.MapGet(callbackPath, async (HttpContext context, AxiamClient client, IOidcStateStore store, CancellationToken cancellationToken) =>
        {
            IQueryCollection query = context.Request.Query;

            // §12.8 rule 1 (d): every callback response — success, the uniform 401 and every other
            // error — clears the binding cookie. Set before anything can answer.
            string? presentedBinding = OidcLoginBinding.Presented(context.Request, options.RedirectUri);
            OidcLoginBinding.Clear(context.Response, options.RedirectUri);

            try
            {
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
                // §12.8 rule 1 (c): the entry is consumed FIRST, so the state stays single-use whatever
                // happens next; then the request must present the cookie the login set. A missing
                // cookie, an entry with no digest and a different digest get the same status and the same
                // body as an unknown state, and neither exchange the code nor call OnSuccessAsync.
                if (entry is null || !OidcLoginBinding.Matches(entry, presentedBinding))
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

                // §12.8 rule 3: a stored return_to is checked AGAIN here — the store may be the
                // integrator's, or the entry older glue's. A value that fails is not followed.
                string? destination = options.SuccessRedirect
                    ?? (OidcLoginBinding.IsAcceptableReturnTo(entry.ReturnTo, options.AllowReturnTo) ? entry.ReturnTo : null);
                if (!string.IsNullOrEmpty(destination))
                {
                    context.Response.Redirect(OidcLoginBinding.ToLocationHeader(destination));
                    return;
                }

                var body = new Dictionary<string, object?> { ["authenticated"] = true, ["expires_in"] = tokens.ExpiresIn };
                if (tokens.IdClaims is { Sub.Length: > 0 } claims)
                {
                    body["sub"] = claims.Sub;
                }
                await context.Response.WriteAsJsonAsync(body, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException && !context.Response.HasStarted)
            {
                // §12.8 rule 1 (d), "any other error": an exception from the store, the application's hook or the
                // exchange must not lose the clearing Set-Cookie to the host's exception handler (which resets the
                // response headers). Answer here and log the failure. Like that handler, drop every header set so far
                // (a session cookie the hook appended before it threw must not reach the browser: the throw aborts the
                // sign-in), then put the clearing cookie back.
                context.RequestServices.GetService<ILoggerFactory>()?.CreateLogger("Axiam.Sdk.AspNetCore.OidcLogin")
                    .LogError(ex, "the AXIAM OIDC login callback failed");
                context.Response.Clear();
                OidcLoginBinding.Clear(context.Response, options.RedirectUri);
                await WriteOidcErrorAsync(context, StatusCodes.Status500InternalServerError, "internal_error", "the login callback failed").ConfigureAwait(false);
            }
        });

        return endpoints;
    }

    private static Task WriteOidcErrorAsync(HttpContext context, int statusCode, string error, string message)
    {
        context.Response.StatusCode = statusCode;
        return context.Response.WriteAsJsonAsync(new { error, message });
    }
}
