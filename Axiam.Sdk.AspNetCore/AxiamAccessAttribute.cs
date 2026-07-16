using Microsoft.AspNetCore.Authorization;

namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// Declarative, per-endpoint AXIAM authorization attribute (CONTRACT.md &#167;11
/// <c>require_access(action, resource[, scope])</c> — C# maps this to
/// <c>[AxiamAccess(...)]</c>). Sugar over the existing <c>"resource:action"</c> policy
/// string mechanism (<see cref="AxiamPolicyProvider"/>/<see cref="AxiamPolicyHandler"/>):
/// this attribute serializes its <see cref="Action"/>/<see cref="Resource"/>/
/// <see cref="Scope"/>/<see cref="ResourceRouteParam"/> into a structured policy name
/// (<c>"axiam::&lt;action&gt;::&lt;resource&gt;::&lt;scope&gt;::&lt;param&gt;"</c>) that
/// <see cref="AxiamPolicyProvider"/> recognizes and parses ALONGSIDE the legacy
/// single-colon <c>"resource:action"</c> form (which remains fully supported — see its
/// own remarks). Because this type derives from <see cref="AuthorizeAttribute"/>, it can
/// be placed directly on a controller/action (<c>[AxiamAccess("read", "documents")]</c>)
/// or passed to <c>RequireAuthorization(IAuthorizeData)</c> for minimal APIs — ASP.NET
/// Core's own authorization pipeline combines it into a policy via
/// <see cref="Policy"/> exactly like any other <see cref="AuthorizeAttribute"/>.
/// </summary>
/// <remarks>
/// This attribute never calls the AXIAM server itself — it only computes a policy name.
/// The actual check happens in <see cref="AxiamPolicyHandler"/>, strictly AFTER the
/// &#167;10 authentication middleware (<see cref="AxiamAuthMiddleware"/>) has already
/// verified the caller and populated <see cref="Microsoft.AspNetCore.Http.HttpContext.User"/>;
/// this attribute never performs its own token extraction or verification (CONTRACT.md
/// &#167;11.2.1).
/// </remarks>
public sealed class AxiamAccessAttribute : AuthorizeAttribute
{
    /// <summary>Prefix identifying a structured (attribute-generated) policy name, as
    /// opposed to the legacy single-colon <c>"resource:action"</c> form.</summary>
    internal const string PolicyPrefix = "axiam";

    /// <summary>Segment separator used when serializing this attribute's fields into a
    /// policy name. Deliberately a two-character sequence so it can never collide with
    /// the single <c>':'</c> used by the legacy policy-string form.</summary>
    internal const string SegmentSeparator = "::";

    /// <summary>The default route value name used to resolve the target resource's UUID
    /// when <see cref="ResourceRouteParam"/> is not explicitly set (CONTRACT.md
    /// &#167;11.2.3b).</summary>
    public const string DefaultResourceRouteParam = "id";

    private string? _scope;
    private string _resourceRouteParam = DefaultResourceRouteParam;

    /// <summary>The action half of the check (e.g. <c>"read"</c>) — sent as part of the
    /// wire <c>action</c> field to <c>POST /api/v1/authz/check</c>.</summary>
    public string Action { get; }

    /// <summary>
    /// The resource-type half of the check (e.g. <c>"documents"</c>), combined with
    /// <see cref="Action"/> into the wire <c>action</c> field as <c>"documents:read"</c>
    /// (mirrors the real AXIAM server's own <c>"resource:verb"</c> action-naming
    /// convention, e.g. <c>"users:get"</c>). <c>null</c> sends <see cref="Action"/> alone.
    /// </summary>
    public string? Resource { get; }

    /// <summary>
    /// Optional scope for sub-resource granularity (CONTRACT.md &#167;11.2.4), passed
    /// through to <c>CheckAccessAsync</c> verbatim. Setting this property recomputes
    /// <see cref="AuthorizeAttribute.Policy"/>.
    /// </summary>
    public string? Scope
    {
        get => _scope;
        set
        {
            _scope = value;
            RebuildPolicy();
        }
    }

    /// <summary>
    /// The name of the route/path value whose UUID value identifies the target resource
    /// (CONTRACT.md &#167;11.2.3b). Defaults to <see cref="DefaultResourceRouteParam"/>
    /// (<c>"id"</c>). A missing or non-UUID route value at request time is a 400
    /// <c>invalid_request</c> outcome (&#167;11.2.3) — never a silent allow, never a
    /// nil/empty-UUID fallback. Setting this property recomputes
    /// <see cref="AuthorizeAttribute.Policy"/>.
    /// </summary>
    public string ResourceRouteParam
    {
        get => _resourceRouteParam;
        set
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value);
            _resourceRouteParam = value;
            RebuildPolicy();
        }
    }

    /// <summary>
    /// Constructs the attribute from the mandatory <paramref name="action"/> and the
    /// optional <paramref name="resource"/> half (CONTRACT.md &#167;11.1: argument order
    /// is always action before resource). <see cref="Scope"/> and
    /// <see cref="ResourceRouteParam"/> may be set afterwards via object-initializer
    /// syntax (e.g. <c>[AxiamAccess("read", "documents")]</c> or
    /// <c>new AxiamAccessAttribute("read", "documents") { Scope = "team-a" }</c>); every
    /// such assignment recomputes the underlying policy name.
    /// </summary>
    /// <param name="action">The action to check (e.g. <c>"read"</c>). Required, non-blank.</param>
    /// <param name="resource">The resource-type half of the check (e.g. <c>"documents"</c>).
    /// Optional; when omitted, <paramref name="action"/> alone is sent as the wire action.</param>
    public AxiamAccessAttribute(string action, string? resource = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        if (resource is not null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(resource);
        }

        Action = action;
        Resource = resource;
        RebuildPolicy();
    }

    private void RebuildPolicy()
    {
        // "axiam::<action>::<resource>::<scope>::<param>" — a missing Resource/Scope is
        // encoded as an empty segment (never omitted, so the segment count is always 5
        // and TryParse below never has to guess which optional field was dropped).
        Policy = string.Join(
            SegmentSeparator,
            PolicyPrefix,
            Action,
            Resource ?? string.Empty,
            Scope ?? string.Empty,
            ResourceRouteParam);
    }

    /// <summary>
    /// Attempts to parse a policy name produced by <see cref="RebuildPolicy"/> back into
    /// its constituent fields. Used by <see cref="AxiamPolicyProvider"/> to recognize an
    /// attribute-generated policy name ahead of the legacy single-colon
    /// <c>"resource:action"</c> form. Returns <c>false</c> for any string that is not a
    /// well-formed 5-segment <c>"axiam::..."</c> policy name (including the legacy form,
    /// which never starts with the <see cref="PolicyPrefix"/> segment).
    /// </summary>
    /// <param name="policyName">The policy name to parse.</param>
    /// <param name="action">The parsed action, or empty when parsing fails.</param>
    /// <param name="resource">The parsed resource, or <c>null</c> when absent/parsing fails.</param>
    /// <param name="scope">The parsed scope, or <c>null</c> when absent/parsing fails.</param>
    /// <param name="resourceRouteParam">The parsed route parameter name, or
    /// <see cref="DefaultResourceRouteParam"/> when parsing fails.</param>
    /// <returns><c>true</c> when <paramref name="policyName"/> was a well-formed structured policy name.</returns>
    internal static bool TryParse(
        string policyName,
        out string action,
        out string? resource,
        out string? scope,
        out string resourceRouteParam)
    {
        action = string.Empty;
        resource = null;
        scope = null;
        resourceRouteParam = DefaultResourceRouteParam;

        string[] parts = policyName.Split(SegmentSeparator, StringSplitOptions.None);
        if (parts.Length != 5 || parts[0] != PolicyPrefix || parts[1].Length == 0 || parts[4].Length == 0)
        {
            return false;
        }

        action = parts[1];
        resource = parts[2].Length == 0 ? null : parts[2];
        scope = parts[3].Length == 0 ? null : parts[3];
        resourceRouteParam = parts[4];
        return true;
    }
}
