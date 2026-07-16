using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// The CONTRACT.md &#167;11 outcomes <see cref="AxiamPolicyHandler"/> can signal to
/// <see cref="AxiamAuthorizationMiddlewareResultHandler"/> beyond a plain deny, via
/// <see cref="AxiamPolicyHandler.OutcomeItemKey"/>.
/// </summary>
internal enum AxiamAuthzOutcome
{
    /// <summary>The target resource id could not be resolved from the request (missing
    /// or non-UUID route value) — maps to 400 <c>invalid_request</c>.</summary>
    InvalidRequest,

    /// <summary>A <see cref="Axiam.Sdk.Core.NetworkError"/> occurred while calling the
    /// authz endpoint — maps to 503 <c>authz_unavailable</c> (fail-closed).</summary>
    AuthzUnavailable,
}

/// <summary>
/// Routes <c>[Authorize(Policy="resource:action")]</c> (e.g.
/// <c>"documents:read"</c>) into <c>AxiamClient.Authz.CheckAccessAsync</c> (D-08). No
/// direct Spring analog — Spring's sibling SDK uses method-security annotations rather
/// than an <see cref="IAuthorizationHandler"/>/policy-provider pair, so this is the most
/// novel file in the phase (built from RESEARCH.md Pattern 5, reusing the
/// <c>AuthzError</c>&#8594;403 JSON-body convention from
/// <c>AxiamAuthenticationFilter.java</c> lines 102-111).
/// </summary>
/// <remarks>
/// AXIAM's RBAC engine is additive-only (allow-wins, default-deny, SEC-040; project
/// constraint per CLAUDE.md) — this handler calls <c>CheckAccessAsync</c> FRESH on
/// every single evaluation (T-21-18). It NEVER caches an authorization decision beyond
/// the current request; a client-side cache or short-circuit could silently diverge
/// from the server's live additive-only decision, which this SDK must never risk.
/// </remarks>
public sealed class AxiamPolicyHandler : AuthorizationHandler<AxiamRequirement>
{
    /// <summary>
    /// Sentinel <see cref="AuthorizationFailureReason.Message"/> attached via
    /// <c>context.Fail(AuthorizationFailureReason)</c> to semantically mark WHY this
    /// requirement failed (400 <c>invalid_request</c> — CONTRACT.md &#167;11.2.3: a
    /// missing/unparseable resource route value is a programming error, never a silent
    /// allow, never a nil/empty-UUID fallback). This is NOT the channel
    /// <see cref="AxiamAuthorizationMiddlewareResultHandler"/> actually reads from — see
    /// <see cref="OutcomeItemKey"/>'s remarks for why — but is kept for diagnostic
    /// correctness (e.g. a consumer inspecting <c>PolicyAuthorizationResult</c> directly).
    /// </summary>
    internal const string InvalidRequestReason = "axiam_invalid_request";

    /// <summary>
    /// Sentinel <see cref="AuthorizationFailureReason.Message"/> attached via
    /// <c>context.Fail(AuthorizationFailureReason)</c> to semantically mark WHY this
    /// requirement failed (503 <c>authz_unavailable</c> fail-closed — CONTRACT.md
    /// &#167;11.2.5: a <see cref="NetworkError"/> while calling the authz endpoint denies
    /// rather than allows). See <see cref="InvalidRequestReason"/>'s remarks — the same
    /// caveat applies.
    /// </summary>
    internal const string AuthzUnavailableReason = "axiam_authz_unavailable";

    /// <summary>
    /// The AUTHORITATIVE channel <see cref="AxiamAuthorizationMiddlewareResultHandler"/>
    /// reads to distinguish the 400/503 outcomes below from a plain 403 deny. A
    /// reference-identity <see cref="HttpContext.Items"/> key (rather than a string) so
    /// it can never collide with another middleware's own entry.
    /// </summary>
    /// <remarks>
    /// Deliberately NOT read via <c>PolicyAuthorizationResult.AuthorizationFailure</c>
    /// (which is where the <see cref="AuthorizationFailureReason"/>s
    /// <see cref="InvalidRequestReason"/>/<see cref="AuthzUnavailableReason"/> above end
    /// up when <c>context.Fail(AuthorizationFailureReason)</c> is called): whether
    /// ASP.NET Core's internal policy evaluator surfaces a given failure as
    /// <c>PolicyAuthorizationResult.Forbid(failure)</c> (which carries that object) or
    /// <c>.Challenge()</c> (which does not) depends on framework-internal authentication
    /// bookkeeping this package does not control and should not depend on for a
    /// contract-mandated status code. <see cref="HttpContext.Items"/> is a plain,
    /// same-request dictionary this handler and the result handler both see
    /// unconditionally (the same <see cref="HttpContext"/> instance ASP.NET Core's
    /// endpoint-routed <c>AuthorizationMiddleware</c> already passes as
    /// <c>AuthorizationHandlerContext.Resource</c> — see the resource-resolution comment
    /// in <see cref="HandleRequirementAsync"/>), so it is used as the sole authoritative
    /// signal instead.
    /// </remarks>
    internal static readonly object OutcomeItemKey = new();

    private readonly AxiamClient _client;

    /// <summary>Constructs the handler over the shared <see cref="AxiamClient"/> registered by
    /// <see cref="ServiceCollectionExtensions.AddAxiamAspNetCore"/>.</summary>
    /// <param name="client">The shared client whose <c>Authz.CheckAccessAsync</c> this handler calls.</param>
    public AxiamPolicyHandler(AxiamClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    /// <summary>
    /// Resolves the caller's <c>user_id</c> claim and the target resource id (from
    /// <see cref="AxiamRequirement.ResourceRouteParam"/> route data), then calls
    /// <c>AxiamClient.Authz.CheckAccessAsync</c> fresh with
    /// <see cref="AxiamRequirement.Scope"/> — see the type-level remarks for why no
    /// decision is ever cached. Succeeds <paramref name="requirement"/> when allowed;
    /// otherwise leaves it unsatisfied (or fails it with a sentinel reason for the
    /// 400/503 cases below) so <see cref="AxiamAuthorizationMiddlewareResultHandler"/>
    /// can map the outcome to a standardized JSON body.
    /// </summary>
    /// <param name="context">The ASP.NET Core authorization evaluation context.</param>
    /// <param name="requirement">The parsed access-check requirement to evaluate.</param>
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AxiamRequirement requirement)
    {
        string? userIdClaim = context.User.FindFirst("user_id")?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out Guid subjectId))
        {
            // No verified identity (AxiamAuthMiddleware never ran, the request carried
            // no token, or the sub claim was not a GUID) — [Authorize] already 401s
            // upstream via AxiamAuthorizationMiddlewareResultHandler's Challenged
            // branch. Leave this requirement unsatisfied rather than throwing.
            return;
        }

        // ASP.NET Core's endpoint-routed AuthorizationMiddleware passes the current
        // HttpContext as `context.Resource` (learn.microsoft.com/aspnet/core/security/
        // authorization/resourcebased — "the resource is the current HttpContext" when
        // authorization runs via the Authorization Middleware with endpoint routing).
        // The compile-time policy/attribute itself carries no per-request resource
        // identifier, so route data (the value named by requirement.ResourceRouteParam,
        // "id" by default) is the idiomatic place to recover a concrete resource UUID
        // for a specific-instance check.
        HttpContext? httpContext = context.Resource as HttpContext;
        if (!TryResolveResourceId(httpContext, requirement.ResourceRouteParam, out Guid resourceId))
        {
            // CONTRACT.md §11.2.3: a missing or unparseable resource route value is a
            // PROGRAMMING error surfaced as 400 invalid_request — never a silent allow,
            // and never the Guid.Empty/nil-UUID fallback this handler used to apply.
            // See OutcomeItemKey's remarks for why HttpContext.Items, not the
            // AuthorizationFailureReason below, is the channel that actually reaches
            // AxiamAuthorizationMiddlewareResultHandler in this SDK's configuration.
            if (httpContext is not null)
            {
                httpContext.Items[OutcomeItemKey] = AxiamAuthzOutcome.InvalidRequest;
            }

            context.Fail(new AuthorizationFailureReason(this, InvalidRequestReason));
            return;
        }

        CancellationToken cancellationToken = httpContext?.RequestAborted ?? CancellationToken.None;

        bool allowed;
        try
        {
            // Server-side additive-only RBAC (allow-wins, default-deny, SEC-040) is the
            // sole source of truth — CheckAccessAsync is called FRESH every time, no
            // local decision cache (T-21-18). subjectId is the end-user identified by
            // AxiamAuthMiddleware's ClaimsPrincipal, checked "as" that user via the
            // check-as subject override (requires this handler's own AxiamClient
            // identity to hold authz:check_as server-side, per CONTRACT.md's authz/check
            // endpoint contract) — the shared AxiamClient checks access ON BEHALF OF the
            // incoming request's caller, never on behalf of itself.
            allowed = await _client.Authz
                .CheckAccessAsync(requirement.PolicyName, resourceId, requirement.Scope, subjectId: subjectId, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch (NetworkError)
        {
            // CONTRACT.md §11.2.5: fail CLOSED on transport failure — never allow just
            // because the authz endpoint could not be reached. Redaction (§11.2.8): the
            // caught NetworkError already carries no token material (Core/NetworkError.cs
            // redact-before-wrap); this handler adds nothing further to the response.
            if (httpContext is not null)
            {
                httpContext.Items[OutcomeItemKey] = AxiamAuthzOutcome.AuthzUnavailable;
            }

            context.Fail(new AuthorizationFailureReason(this, AuthzUnavailableReason));
            return;
        }
        catch (AuthzError)
        {
            // CONTRACT.md §11.2.5: a server-issued 403/409 on the check call itself maps
            // to the SAME deny outcome as an allowed=false body — 403 authorization_denied.
            // ErrorMapper turns HTTP 403/409 into AuthzError (Core/ErrorMapper.cs); the
            // openapi.json contract documents a 403 on /api/v1/authz/check for the
            // subject_id-override path this handler exercises. Leave the requirement
            // unsatisfied (exactly like the allowed=false branch below) so the result
            // handler writes the standardized 403 body — never let it escape as an
            // unhandled 500. The AuthzError carries no token material (Core redaction).
            return;
        }
        catch (AuthError)
        {
            // The check call's OWN identity — the application's shared AxiamClient service
            // session — failed to authenticate to the authz endpoint (HTTP 401 → AuthError),
            // e.g. its token expired or it lacks the session needed for the check-as subject
            // override. This is NOT the end user being unauthenticated (they already passed
            // the user_id claim check above); it is an inability to obtain an authoritative
            // decision, so fail CLOSED to 503 authz_unavailable rather than 401 — a 401 here
            // would wrongly tell the end user to re-authenticate. Consistent with the
            // NetworkError branch and §11.2.5's "couldn't decide → deny".
            if (httpContext is not null)
            {
                httpContext.Items[OutcomeItemKey] = AxiamAuthzOutcome.AuthzUnavailable;
            }

            context.Fail(new AuthorizationFailureReason(this, AuthzUnavailableReason));
            return;
        }

        if (allowed)
        {
            context.Succeed(requirement);
        }
        // else: leave unsatisfied — AxiamAuthorizationMiddlewareResultHandler maps an
        // unsatisfied/Forbidden requirement to a standardized 403 JSON body.
    }

    private static bool TryResolveResourceId(HttpContext? httpContext, string resourceRouteParam, out Guid resourceId)
    {
        resourceId = Guid.Empty;
        return httpContext is not null &&
            httpContext.Request.RouteValues.TryGetValue(resourceRouteParam, out object? routeValue) &&
            routeValue is not null &&
            Guid.TryParse(routeValue.ToString(), out resourceId);
    }
}

/// <summary>
/// Custom <see cref="IAuthorizationMiddlewareResultHandler"/> that writes the
/// standardized JSON error body (CONTRACT.md &#167;10/&#167;11, PATTERNS.md "Standardized
/// JSON error body") for every authorization outcome: an unauthenticated result (401), a
/// "lacks permission" result (403 — <c>AxiamPolicyHandler</c> left an
/// <see cref="AxiamRequirement"/> unsatisfied, i.e. <c>AuthzError</c>), an unresolvable
/// resource id (400 <c>invalid_request</c>, CONTRACT.md &#167;11.2.3), and a transport
/// failure while checking access (503 <c>authz_unavailable</c>, fail-closed per
/// CONTRACT.md &#167;11.2.5). On success, the pipeline continues exactly like the
/// framework default.
/// </summary>
/// <remarks>
/// This handler deliberately does NOT branch on
/// <see cref="PolicyAuthorizationResult.Forbidden"/>/<see cref="PolicyAuthorizationResult.Challenged"/>.
/// Neither this package nor a typical consumer registers an ASP.NET Core
/// authentication scheme (<c>AddAuthentication()</c>/<c>UseAuthentication()</c>) —
/// identity comes entirely from <see cref="AxiamAuthMiddleware"/> setting
/// <see cref="HttpContext.User"/> directly. Because of that,
/// <c>Microsoft.AspNetCore.Authorization.Policy.PolicyEvaluator</c>'s internal
/// authentication step always resolves to <c>AuthenticateResult.NoResult()</c>
/// (<c>Succeeded == false</c>) since the evaluated policy carries no
/// <c>AuthenticationSchemes</c> — which means EVERY non-success outcome, including an
/// authenticated-but-forbidden one, would surface as <c>Challenged</c>, never
/// <c>Forbidden</c>. Branching on <see cref="HttpContext.User"/>'s own
/// <c>Identity.IsAuthenticated</c> instead sidesteps that ambiguity entirely and is
/// the authoritative signal: <see cref="AxiamAuthMiddleware"/> is the only code path
/// that ever sets an authenticated identity, and it only does so after `JwksVerifier`
/// signature+tenant verification succeeds.
/// </remarks>
public sealed class AxiamAuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
    /// <summary>
    /// On success, continues the pipeline exactly like the framework default. On failure,
    /// writes a standardized JSON error body, checking
    /// <see cref="AxiamPolicyHandler.OutcomeItemKey"/> in <paramref name="context"/>'s
    /// <see cref="HttpContext.Items"/> FIRST — see that key's remarks for why this,
    /// rather than <paramref name="authorizeResult"/>'s own
    /// <see cref="PolicyAuthorizationResult.AuthorizationFailure"/>, is the channel
    /// <see cref="AxiamPolicyHandler"/> actually reaches this handler through: 503
    /// (<c>authz_unavailable</c>) for a transport failure while checking access, 400
    /// (<c>invalid_request</c>) for an unresolvable resource id. Absent either signal,
    /// falls back to the &#167;10 behavior: 403 (<c>authorization_denied</c>) when
    /// <see cref="HttpContext.User"/> is already authenticated (an <see cref="AxiamRequirement"/>
    /// was left unsatisfied by <see cref="AxiamPolicyHandler"/>), otherwise 401
    /// (<c>authentication_failed</c>). See the type-level remarks for why this branches on
    /// <c>User.Identity.IsAuthenticated</c> rather than <c>authorizeResult</c>'s own
    /// Forbidden/Challenged distinction.
    /// </summary>
    /// <param name="next">The next delegate in the pipeline; invoked only on success.</param>
    /// <param name="context">The current request's <see cref="HttpContext"/>.</param>
    /// <param name="policy">The policy that was evaluated.</param>
    /// <param name="authorizeResult">The outcome of evaluating <paramref name="policy"/>.</param>
    public Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(authorizeResult);

        if (authorizeResult.Succeeded)
        {
            return next(context);
        }

        if (context.Items.TryGetValue(AxiamPolicyHandler.OutcomeItemKey, out object? outcomeValue) && outcomeValue is AxiamAuthzOutcome outcome)
        {
            if (outcome == AxiamAuthzOutcome.AuthzUnavailable)
            {
                return WriteJsonAsync(context, StatusCodes.Status503ServiceUnavailable, "authz_unavailable", "authorization service unavailable");
            }

            if (outcome == AxiamAuthzOutcome.InvalidRequest)
            {
                return WriteJsonAsync(context, StatusCodes.Status400BadRequest, "invalid_request", "resource id could not be resolved from the request");
            }
        }

        bool isAuthenticated = context.User.Identity?.IsAuthenticated == true;
        return isAuthenticated
            ? WriteJsonAsync(context, StatusCodes.Status403Forbidden, "authorization_denied", "insufficient permissions")
            : WriteJsonAsync(context, StatusCodes.Status401Unauthorized, "authentication_failed", "authentication required");
    }

    private static Task WriteJsonAsync(HttpContext context, int statusCode, string error, string message)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        return context.Response.WriteAsJsonAsync(new { error, message });
    }
}
