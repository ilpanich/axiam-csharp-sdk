using Microsoft.AspNetCore.Authorization;

namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// Authorization requirement carrying everything <see cref="AxiamPolicyHandler"/> needs
/// to run a single AXIAM access check (CONTRACT.md &#167;11): the resource/action halves
/// (legacy <c>"resource:action"</c> policy-string form, e.g. <c>"documents:read"</c>, or
/// the structured <see cref="AxiamAccessAttribute"/> form — both funnel into this same
/// type), plus the optional <see cref="Scope"/> and the <see cref="ResourceRouteParam"/>
/// route value name used to resolve the target resource's UUID at request time. Built by
/// <see cref="AxiamPolicyProvider"/>.
/// </summary>
public sealed class AxiamRequirement : IAuthorizationRequirement
{
    /// <summary>The resource-type half of the policy name (e.g. <c>"documents"</c>).
    /// <c>null</c> when the requirement was built from an <see cref="AxiamAccessAttribute"/>
    /// with no <c>resource</c> argument — in that case <see cref="PolicyName"/> is
    /// <see cref="Action"/> alone.</summary>
    public string? Resource { get; }

    /// <summary>The action half of the policy name (e.g. <c>"read"</c>).</summary>
    public string Action { get; }

    /// <summary>Optional scope for sub-resource granularity (CONTRACT.md &#167;11.2.4),
    /// passed through to <c>CheckAccessAsync</c> verbatim. <c>null</c> when no scope was
    /// specified.</summary>
    public string? Scope { get; }

    /// <summary>The name of the route/path value whose UUID identifies the target
    /// resource (CONTRACT.md &#167;11.2.3b). Defaults to
    /// <see cref="AxiamAccessAttribute.DefaultResourceRouteParam"/> (<c>"id"</c>) for
    /// requirements built from the legacy <c>"resource:action"</c> policy-string form.</summary>
    public string ResourceRouteParam { get; }

    /// <summary>
    /// Constructs the requirement from the parsed halves of a policy name, plus the
    /// optional scope and route-parameter name.
    /// </summary>
    /// <param name="resource">The resource-type half of the policy name (e.g. <c>"documents"</c>).
    /// Optional — when <c>null</c>, <see cref="PolicyName"/> is <paramref name="action"/> alone.</param>
    /// <param name="action">The action half of the policy name (e.g. <c>"read"</c>). Required, non-blank.</param>
    /// <param name="scope">Optional scope for sub-resource granularity, passed through to
    /// <c>CheckAccessAsync</c> verbatim.</param>
    /// <param name="resourceRouteParam">The name of the route value whose UUID identifies
    /// the target resource. Defaults to <see cref="AxiamAccessAttribute.DefaultResourceRouteParam"/> (<c>"id"</c>).</param>
    public AxiamRequirement(string? resource, string action, string? scope = null, string resourceRouteParam = AxiamAccessAttribute.DefaultResourceRouteParam)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        if (resource is not null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(resource);
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(resourceRouteParam);
        Resource = resource;
        Action = action;
        Scope = scope;
        ResourceRouteParam = resourceRouteParam;
    }

    /// <summary>
    /// The full <c>"resource:action"</c> (or bare <c>action</c>, when <see cref="Resource"/>
    /// is <c>null</c>) string this requirement was built from — sent verbatim as the wire
    /// <c>action</c> field to <c>POST /api/v1/authz/check</c>, which documents its own
    /// <c>action</c> field with exactly this "resource:verb" shape (e.g. the real server's
    /// own doc example is <c>"users:get"</c>).
    /// </summary>
    public string PolicyName => Resource is null ? Action : $"{Resource}:{Action}";
}
