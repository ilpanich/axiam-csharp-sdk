using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;

namespace Axiam.Sdk.Management;

/// <summary>
/// The one request path every CONTRACT.md &#167;27 management operation goes through.
/// </summary>
/// <remarks>
/// &#167;27.8 is explicit that the generated layer MUST sit on the SDK's existing
/// request path and MUST NOT build its own. That is what this class is: 147 generated
/// operations all funnel into <see cref="SendAsync"/>, so they inherit &#167;3 (CSRF),
/// &#167;4 (the cookie jar), &#167;5 (the tenant header), &#167;6 (TLS), &#167;16 (retry)
/// and &#167;19 (telemetry) by construction rather than by 147 opportunities to forget
/// one — the first four because every request goes through the same decorated
/// <see cref="HttpClient"/> the rest of the SDK uses.
/// </remarks>
internal sealed class ManagementTransport
{
    private const int MaxErrorPeekChars = 8192;
    private const int MaxErrorTextChars = 200;

    private readonly HttpClient _http;
    private readonly AxiamClientOptions _options;
    private readonly TelemetryDispatcher _telemetry;
    private readonly Func<string?> _accessToken;
    private readonly Func<Guid?> _resolvedOrgId;
    private readonly Func<Guid?> _resolvedTenantId;
    private readonly Action _throwIfDisposed;
    private readonly Func<double> _jitter;

    internal ManagementTransport(
        HttpClient http,
        AxiamClientOptions options,
        TelemetryDispatcher telemetry,
        Func<string?> accessToken,
        Func<Guid?> resolvedOrgId,
        Func<Guid?> resolvedTenantId,
        Action throwIfDisposed,
        Func<double> jitter)
    {
        _http = http;
        _options = options;
        _telemetry = telemetry;
        _accessToken = accessToken;
        _resolvedOrgId = resolvedOrgId;
        _resolvedTenantId = resolvedTenantId;
        _throwIfDisposed = throwIfDisposed;
        _jitter = jitter;
    }

    /// <summary>The organization UUID §27.4 rule 3 interpolates, or <c>null</c>.</summary>
    internal Guid? ResolvedOrgId => _resolvedOrgId();

    /// <summary>The tenant UUID §27.4 rule 3 interpolates, or <c>null</c>.</summary>
    internal Guid? ResolvedTenantId => _resolvedTenantId();

    /// <summary>
    /// Issues one management request and returns its parsed body.
    /// </summary>
    /// <param name="operation">The canonical <c>namespace.operation</c> name.</param>
    /// <param name="method">The HTTP method the registry declares.</param>
    /// <param name="pathTemplate">The UNSUBSTITUTED path, used as the §19.1 label.</param>
    /// <param name="path">The substituted path actually requested.</param>
    /// <param name="query">Query parameters; a <c>null</c> value is omitted.</param>
    /// <param name="body">The already-encoded JSON request body, or <c>null</c>.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The parsed response body, or <c>null</c> for a 204 or empty body.</returns>
    internal async Task<JsonElement?> SendAsync(
        string operation,
        HttpMethod method,
        string pathTemplate,
        string path,
        IReadOnlyDictionary<string, string?>? query,
        string? body,
        CancellationToken cancellationToken)
    {
        _throwIfDisposed();
        RequireSession(operation);

        // §27.4 rule 8: every GET here is read-only and therefore retry-eligible under
        // §16.2; every POST, PUT and DELETE is not — including the ones that look
        // idempotent. certificates.generate twice mints two certificates.
        if (method != HttpMethod.Get)
        {
            return await AttemptAsync(operation, method, pathTemplate, path, query, body, 1, cancellationToken)
                .ConfigureAwait(false);
        }

        return await RetryPolicy.ExecuteAsync(
            operation,
            _options,
            _telemetry,
            _jitter,
            attempt => AttemptAsync(operation, method, pathTemplate, path, query, body, attempt, cancellationToken),
            cancellationToken,
            // A rejected body is not a transient fault: the same bytes earn the same
            // refusal, three times as slowly.
            retryable: e => e is not ValidationError).ConfigureAwait(false);
    }

    /// <summary>
    /// §27.4 rule 1: no session means no wire call.
    /// </summary>
    /// <remarks>
    /// Refused here, once, rather than in 147 generated operations — and refused BEFORE
    /// the socket, so an unauthenticated caller gets a message naming the missing
    /// session instead of a 401 they have to interpret.
    /// </remarks>
    private void RequireSession(string operation)
    {
        if (_accessToken() is null)
        {
            throw new AuthError(
                $"{operation}: no active session. The management API acts as the logged-in " +
                "administrator, so call LoginAsync() (or complete an OAuth2 flow) first — " +
                "this call was refused locally and never reached the network.");
        }
    }

    private async Task<JsonElement?> AttemptAsync(
        string operation,
        HttpMethod method,
        string pathTemplate,
        string path,
        IReadOnlyDictionary<string, string?>? query,
        string? body,
        int attempt,
        CancellationToken cancellationToken)
    {
        var url = new StringBuilder(path);
        if (query is not null)
        {
            // Sorted so a request is reproducible from its telemetry, and so two
            // otherwise-identical requests cannot differ by dictionary ordering.
            var pairs = query
                .Where(kv => kv.Value is not null)
                .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value!)}")
                .ToList();
            if (pairs.Count > 0)
            {
                url.Append('?').Append(string.Join("&", pairs));
            }
        }

        using var request = new HttpRequestMessage(method, url.ToString());
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        // §19.1: the label is the TEMPLATE, never the substituted path — a label
        // carrying a tenant's user identifiers is a cardinality explosion and a
        // disclosure at once.
        TelemetryDispatcher.Span span = _telemetry.StartRequest(operation, method.Method, pathTemplate, attempt);

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            span.End(null, TelemetryOutcome.Failure);
            throw NetworkError.FromException(ex, $"{operation}: request failed");
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                span.End((int)response.StatusCode, TelemetryOutcome.Failure);
                throw await ClassifyAsync(operation, response, cancellationToken).ConfigureAwait(false);
            }

            span.End((int)response.StatusCode, TelemetryOutcome.Success);
            return await ReadBodyAsync(operation, response, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<JsonElement?> ReadBodyAsync(
        string operation, HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.StatusCode == HttpStatusCode.NoContent)
        {
            return null;
        }

        string text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(text);
            return document.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            throw NetworkError.FromMessage(
                $"{operation}: could not parse the server's response: {ex.Message}");
        }
    }

    /// <summary>
    /// Maps a failed management response onto the &#167;2 taxonomy.
    /// </summary>
    /// <remarks>
    /// &#167;27.4 rule 7 adds three classifications and widens the taxonomy no further:
    /// everything the table does not name falls through to <see cref="ErrorMapper"/>,
    /// which is &#167;2's own mapping and stays the single source of truth for it.
    /// </remarks>
    private static async Task<Exception> ClassifyAsync(
        string operation, HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string peeked = await PeekAsync(response, cancellationToken).ConfigureAwait(false);
        string detail = Describe(peeked);
        return (int)response.StatusCode switch
        {
            404 => new NotFoundError($"{operation}: not found{detail}"),
            409 => new ConflictError($"{operation}: conflict{detail}"),
            400 or 422 => new ValidationError($"{operation}: rejected{detail}", ParseFieldErrors(peeked)),
            _ => ErrorMapper.FromHttpResponse(response, $"{operation} failed"),
        };
    }

    /// <summary>At most a few KB of an error body is needed to explain the refusal.</summary>
    private static async Task<string> PeekAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            string text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return text.Length > MaxErrorPeekChars ? text[..MaxErrorPeekChars] : text;
        }
        catch (HttpRequestException)
        {
            return string.Empty;
        }
    }

    private static string Describe(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return string.Empty;
        }

        try
        {
            using var document = JsonDocument.Parse(body);
            JsonElement root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Object)
            {
                if (root.TryGetProperty("message", out JsonElement m) && m.ValueKind == JsonValueKind.String)
                {
                    return ": " + m.GetString();
                }

                if (root.TryGetProperty("error", out JsonElement e) && e.ValueKind == JsonValueKind.String)
                {
                    return ": " + e.GetString();
                }
            }

            return string.Empty;
        }
        catch (JsonException)
        {
            return ": " + (body.Length > MaxErrorTextChars ? body[..MaxErrorTextChars] : body);
        }
    }

    /// <summary>
    /// Pulls field-level detail out of an error body, on a best-effort basis.
    /// </summary>
    /// <remarks>
    /// Two shapes are recognised — an array of <c>{field, message}</c> and an object
    /// keyed by field name. A body in neither shape yields no fields rather than an
    /// error: failing to parse an error body would replace a useful message with a
    /// useless one.
    /// </remarks>
    private static IReadOnlyList<FieldError> ParseFieldErrors(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return Array.Empty<FieldError>();
        }

        try
        {
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("errors", out JsonElement errors))
            {
                return Array.Empty<FieldError>();
            }

            var found = new List<FieldError>();
            if (errors.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in errors.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.Object ||
                        !item.TryGetProperty("field", out JsonElement field) ||
                        field.ValueKind != JsonValueKind.String)
                    {
                        continue;
                    }

                    string message = item.TryGetProperty("message", out JsonElement msg) &&
                                     msg.ValueKind == JsonValueKind.String
                        ? msg.GetString()!
                        : "is invalid";
                    found.Add(new FieldError(field.GetString()!, message));
                }
            }
            else if (errors.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty property in errors.EnumerateObject())
                {
                    found.Add(new FieldError(property.Name, FieldMessage(property.Value)));
                }
            }

            return found;
        }
        catch (JsonException)
        {
            return Array.Empty<FieldError>();
        }
    }

    private static string FieldMessage(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString()!,
        JsonValueKind.Array => string.Join("; ", value.EnumerateArray()
            .Where(e => e.ValueKind == JsonValueKind.String)
            .Select(e => e.GetString())),
        _ => value.ToString(),
    };
}
