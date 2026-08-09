using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;

namespace Axiam.Sdk.Rest;

/// <summary>
/// REST authorization client (CONTRACT.md &#167;1, FND-04): <c>CheckAccessAsync</c>/
/// <c>CanAsync</c>/<c>BatchCheckAsync</c> over <c>POST /api/v1/authz/check</c> and
/// <c>POST /api/v1/authz/check/batch</c> (mirrors the gRPC
/// <c>CheckAccess</c>/<c>BatchCheckAccess</c> semantics a later plan wires up over the
/// same shared session). Exposed as <c>AxiamClient.Authz</c>.
/// </summary>
/// <remarks>
/// This class holds NO local cache of any authorization decision — every call hits the
/// server fresh. AXIAM's RBAC engine is additive-only (allow-wins, default-deny,
/// SEC-040; project constraint per CLAUDE.md); a client-side cache or short-circuit
/// could silently diverge from the server's live decision, which this SDK must never
/// risk.
/// </remarks>
public sealed class AuthzRestClient
{
    private const string CheckPath = "/api/v1/authz/check";
    private const string BatchCheckPath = "/api/v1/authz/check/batch";

    private readonly HttpClient _http;

    private readonly AxiamClientOptions _options;
    private readonly TelemetryDispatcher _telemetry;
    private readonly DecisionMemo _memo;
    private readonly Func<double> _jitter;

    /// <summary>
    /// Builds an authz client.
    /// </summary>
    /// <remarks>
    /// The §16/§17/§19 collaborators are optional so the existing test seams that
    /// construct this with only an <see cref="HttpClient"/> keep working. Their
    /// fallbacks are the contract defaults: the §16 policy at its normative values,
    /// telemetry inert, and the memo disabled — which is exactly what a caller who
    /// passed nothing should get.
    /// </remarks>
    internal AuthzRestClient(
        HttpClient httpClient,
        AxiamClientOptions? options = null,
        TelemetryDispatcher? telemetry = null,
        DecisionMemo? memo = null,
        Func<double>? jitter = null)
    {
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options ?? new AxiamClientOptions
        {
            BaseUrl = httpClient.BaseAddress ?? new Uri("https://localhost"),
            TenantId = string.Empty,
        };
        _telemetry = telemetry ?? new TelemetryDispatcher(null);
        _memo = memo ?? new DecisionMemo(TimeSpan.Zero);
        _jitter = jitter ?? Random.Shared.NextDouble;
    }

    /// <summary>A single authorization check request item for <see cref="BatchCheckAsync"/>.</summary>
    /// <param name="Action">The action to check (e.g. <c>"users:get"</c>).</param>
    /// <param name="ResourceId">The resource UUID the action targets.</param>
    /// <param name="Scope">Optional scope for sub-resource granularity.</param>
    /// <param name="SubjectId">
    /// Optional "check-as" subject override. Requires the caller to hold
    /// <c>authz:check_as</c> server-side; omit to check on behalf of the authenticated
    /// caller.
    /// </param>
    public sealed record AccessCheck(string Action, Guid ResourceId, string? Scope = null, Guid? SubjectId = null);

    private sealed record CheckAccessWireRequest(
        [property: JsonPropertyName("action")] string Action,
        [property: JsonPropertyName("resource_id")] Guid ResourceId,
        [property: JsonPropertyName("scope")] string? Scope,
        [property: JsonPropertyName("subject_id")] Guid? SubjectId);

    private sealed record CheckAccessWireResponse(
        [property: JsonPropertyName("allowed")] bool Allowed,
        [property: JsonPropertyName("reason")] string? Reason,
        [property: JsonPropertyName("reason_code")] string? ReasonCode = null);


    private sealed record BatchCheckWireRequest(
        [property: JsonPropertyName("checks")] IReadOnlyList<CheckAccessWireRequest> Checks);

    private sealed record BatchCheckWireResponse(
        [property: JsonPropertyName("results")] IReadOnlyList<CheckAccessWireResponse> Results);

    /// <summary>
    /// <c>POST /api/v1/authz/check</c> (FND-04). Evaluates fresh every time — no
    /// client-side authz caching/short-circuiting. Returns the response's
    /// <c>allowed</c> field.
    /// </summary>
    public async Task<bool> CheckAccessAsync(
        string action, Guid resourceId, string? scope = null, Guid? subjectId = null, CancellationToken cancellationToken = default)
    {
        var wireRequest = new CheckAccessWireRequest(action, resourceId, scope, subjectId);
        HttpResponseMessage response;
        try
        {
            response = await _http.PostAsJsonAsync(CheckPath, wireRequest, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            // Transport-level failure (connection refused, DNS, TLS) — map to the
            // documented NetworkError taxonomy (CONTRACT.md §2), matching
            // AxiamClient.PostJsonAsync rather than leaking a raw HttpRequestException.
            throw NetworkError.FromException(ex, "checkAccess failed");
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw ErrorMapper.FromHttpResponse(response, "checkAccess failed");
            }

            CheckAccessWireResponse? wire = await response.Content
                .ReadFromJsonAsync<CheckAccessWireResponse>(cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return wire?.Allowed ?? false;
        }
    }

    /// <summary>
    /// <c>POST /api/v1/authz/check</c> returning the <b>full</b> decision, including the
    /// CONTRACT.md &#167;11 rule 9 <c>reason_code</c>.
    /// </summary>
    /// <remarks>
    /// Exists because <see cref="CheckAccessAsync"/> returns a bare <see cref="bool"/> that predates
    /// that field and cannot carry it without a breaking signature change. The distinction it
    /// surfaces is not cosmetic: <c>no_grant</c> means "ask an admin for access",
    /// <c>denied_by_rule</c> means "an admin has already decided", and an application that cannot
    /// tell them apart sends users to raise tickets that will be refused.
    /// </remarks>
    /// <param name="action">The action to check.</param>
    /// <param name="resourceId">The resource to check it against.</param>
    /// <param name="scope">Optional sub-resource scope.</param>
    /// <param name="subjectId">Optional "check-as" subject override.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The full decision.</returns>
    public async Task<AccessDecision> CheckAccessDecisionAsync(
        string action, Guid resourceId, string? scope = null, Guid? subjectId = null, CancellationToken cancellationToken = default)
    {
        // §17: consult the memo first. Disabled by default, in which case this is
        // one dictionary lookup that always misses.
        string key = DecisionMemo.Key(subjectId, resourceId, action, scope);
        if (_memo.Get(key) is { } memoized)
        {
            return memoized;
        }

        // §16: a POST, but side-effect-free, so it is retry-eligible. Eligibility is
        // "changes no server state", NOT "is a GET" — gating on the verb would
        // exclude the single most important operation this policy covers.
        AccessDecision decision = await RetryPolicy.ExecuteAsync(
            "CheckAccess",
            _options,
            _telemetry,
            _jitter,
            attempt => SendCheckAsync(action, resourceId, scope, subjectId, attempt, cancellationToken),
            cancellationToken).ConfigureAwait(false);

        // Only a decision the server actually returned is memoized: reaching here
        // means success, so §17.1 rule 7's ban on caching a failure is structural
        // rather than a check that could be forgotten.
        _memo.Put(key, decision);
        return decision;
    }

    /// <summary>One §16 attempt at the single-check call, with its §19 request pair.</summary>
    private async Task<AccessDecision> SendCheckAsync(
        string action, Guid resourceId, string? scope, Guid? subjectId, int attempt, CancellationToken cancellationToken)
    {
        var wireRequest = new CheckAccessWireRequest(action, resourceId, scope, subjectId);
        TelemetryDispatcher.Span span = _telemetry.StartRequest("CheckAccess", "POST", CheckPath, attempt);
        HttpResponseMessage response;
        try
        {
            response = await _http.PostAsJsonAsync(CheckPath, wireRequest, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            span.End(null, TelemetryOutcome.Failure);
            throw NetworkError.FromException(ex, "checkAccess failed");
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                span.End((int)response.StatusCode, TelemetryOutcome.Failure);
                throw ErrorMapper.FromHttpResponse(response, "checkAccess failed");
            }

            span.End((int)response.StatusCode, TelemetryOutcome.Success);
            CheckAccessWireResponse? wire = await response.Content
                .ReadFromJsonAsync<CheckAccessWireResponse>(cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            // §11 rule 9: the reason code is surfaced verbatim, including a value this SDK has
            // never heard of — the outcome is carried by `allowed` alone, so an unknown code can
            // never change it.
            return new AccessDecision(wire?.Allowed ?? false, wire?.Reason, wire?.ReasonCode);
        }
    }

    /// <summary>
    /// Browser/UI-scenario ergonomic alias for <see cref="CheckAccessAsync"/>
    /// (CONTRACT.md &#167;1 "can" alias note) — the exact same fresh server call and
    /// no-cache guarantee; async-only per D-10 (no bare synchronous <c>Can</c> method).
    /// </summary>
    public Task<bool> CanAsync(string action, Guid resourceId, string? scope = null, CancellationToken cancellationToken = default) =>
        CheckAccessAsync(action, resourceId, scope, subjectId: null, cancellationToken);

    /// <summary>
    /// <c>POST /api/v1/authz/check/batch</c> (FND-04). Returns results in the same
    /// order as <paramref name="checks"/>. Fresh, uncached, per &#167;1/FND-04.
    /// </summary>
    public async Task<IReadOnlyList<bool>> BatchCheckAsync(IEnumerable<AccessCheck> checks, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checks);
        List<CheckAccessWireRequest> wireChecks = checks
            .Select(c => new CheckAccessWireRequest(c.Action, c.ResourceId, c.Scope, c.SubjectId))
            .ToList();
        var wireRequest = new BatchCheckWireRequest(wireChecks);

        HttpResponseMessage response;
        try
        {
            response = await _http.PostAsJsonAsync(BatchCheckPath, wireRequest, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            // Transport-level failure — map to NetworkError (CONTRACT.md §2), matching
            // AxiamClient.PostJsonAsync rather than leaking a raw HttpRequestException.
            throw NetworkError.FromException(ex, "batchCheck failed");
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw ErrorMapper.FromHttpResponse(response, "batchCheck failed");
            }

            BatchCheckWireResponse? wire = await response.Content
                .ReadFromJsonAsync<BatchCheckWireResponse>(cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return wire?.Results.Select(r => r.Allowed).ToList() ?? new List<bool>();
        }
    }

    /// <summary>
    /// <c>POST /api/v1/authz/check/batch</c> returning the <b>full</b> decisions, including each
    /// <c>reason_code</c> (CONTRACT.md &#167;11 rule 9). Results preserve input order.
    /// </summary>
    /// <param name="checks">The checks to evaluate.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>One decision per input check, in order.</returns>
    public async Task<IReadOnlyList<AccessDecision>> BatchCheckDecisionsAsync(
        IEnumerable<AccessCheck> checks, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checks);
        List<CheckAccessWireRequest> wireChecks = checks
            .Select(c => new CheckAccessWireRequest(c.Action, c.ResourceId, c.Scope, c.SubjectId))
            .ToList();
        var wireRequest = new BatchCheckWireRequest(wireChecks);

        HttpResponseMessage response;
        try
        {
            response = await _http.PostAsJsonAsync(BatchCheckPath, wireRequest, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw NetworkError.FromException(ex, "batchCheck failed");
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw ErrorMapper.FromHttpResponse(response, "batchCheck failed");
            }

            BatchCheckWireResponse? wire = await response.Content
                .ReadFromJsonAsync<BatchCheckWireResponse>(cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return wire?.Results
                .Select(r => new AccessDecision(r.Allowed, r.Reason, r.ReasonCode))
                .ToList() ?? new List<AccessDecision>();
        }
    }
}
