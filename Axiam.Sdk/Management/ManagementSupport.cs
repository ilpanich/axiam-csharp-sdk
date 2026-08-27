using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Management;

/// <summary>
/// The pieces every generated namespace handle leans on.
/// </summary>
/// <remarks>
/// <c>internal</c> on purpose: the generated handles live in this assembly, so nothing
/// here needs to be public, and none of it is API a caller should reach for.
/// </remarks>
internal static class ManagementSupport
{
    /// <summary>
    /// Resolves <c>{org_id}</c>: the handle's override, else the client's.
    /// </summary>
    /// <remarks>
    /// A client built with an organization <em>slug</em> that has not logged in fails
    /// HERE, with no wire call. &#167;27.4 rule 3 forbids resolving the slug behind the
    /// caller's back: a silent extra round-trip on an admin path is what &#167;12.1
    /// rule 2 refuses for the OAuth2 endpoints, and for the same reason — the caller
    /// cannot see it, cannot cache it, and pays for it on every call.
    /// </remarks>
    internal static Guid ResolveOrg(ManagementTransport transport, NamespaceScope scope, string operation)
        => scope.OrgId
           ?? transport.ResolvedOrgId
           ?? throw NetworkError.FromMessage(
               $"{operation}: this route needs an organization UUID and the client has none. " +
               "Construct the client with AxiamClientOptions.OrgId, log in so the access " +
               "token's org_id claim resolves one, or name one on the handle with InOrg(...).");

    /// <summary>
    /// Resolves <c>{tenant_id}</c> where it names the <em>context</em>, not the object.
    /// </summary>
    /// <remarks>
    /// Namespaces where <c>{tenant_id}</c> names the thing being acted on —
    /// <c>tenants</c>, and the signing CAs under <c>ca_certificates</c> — take it as an
    /// ordinary argument instead and never reach this.
    /// </remarks>
    internal static Guid ResolveTenant(ManagementTransport transport, NamespaceScope scope, string operation)
        => scope.TenantId
           ?? transport.ResolvedTenantId
           ?? throw NetworkError.FromMessage(
               $"{operation}: this route needs a tenant UUID, but none has been resolved yet. " +
               "Call LoginAsync() so the access token's tenant_id claim resolves one, or name " +
               "one on the handle with ForTenant(...).");

    /// <summary>
    /// The query contribution of a <see cref="PageRequest"/>.
    /// </summary>
    /// <remarks>
    /// <c>limit</c> is omitted entirely when unset rather than sent as <c>0</c> — the
    /// server reads <c>limit=0</c> as "none", which would return an empty page.
    /// </remarks>
    internal static Dictionary<string, string?> PageQuery(
        Dictionary<string, string?>? query, PageRequest? page)
    {
        PageRequest request = page ?? PageRequest.First();
        var merged = query is null
            ? new Dictionary<string, string?>(StringComparer.Ordinal)
            : new Dictionary<string, string?>(query, StringComparer.Ordinal);
        merged["offset"] = request.Offset.ToString(System.Globalization.CultureInfo.InvariantCulture);
        merged["limit"] = request.Limit?.ToString(System.Globalization.CultureInfo.InvariantCulture);
        merged["search"] = NormalizeSearch(request.Search);
        return merged;
    }

    /// <summary>
    /// The trimmed term, or <c>null</c> when there is nothing to filter on.
    /// </summary>
    /// <remarks>
    /// Mirrors the server's own normalisation minus the length cap, which is the server's
    /// to apply. A <c>null</c> value here is dropped before the request is built, so an
    /// unfiltered read and a read whose search box was cleared are the same request on the
    /// wire (&#167;27.4 rule 4).
    /// </remarks>
    internal static string? NormalizeSearch(string? term)
    {
        if (term is null)
        {
            return null;
        }

        string trimmed = term.Trim();
        return trimmed.Length == 0 ? null : trimmed;
    }

    /// <summary>
    /// Encodes a request body exactly as it goes on the socket.
    /// </summary>
    /// <remarks>
    /// Routed through <see cref="ManagementJson.Wire"/> — the single writer that
    /// serializes a <see cref="Sensitive{T}"/> in the clear (&#167;27.5) and omits unset
    /// properties (&#167;27.4 rule 5).
    /// </remarks>
    internal static string EncodeBody<T>(string operation, T body)
    {
        try
        {
            return JsonSerializer.Serialize(body, ManagementJson.Wire);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            throw NetworkError.FromMessage(
                $"{operation}: could not encode the request body: {ex.Message}");
        }
    }

    /// <summary>Converts a response node into a model, or throws a <see cref="NetworkError"/>.</summary>
    internal static T Decode<T>(string operation, JsonElement? node)
    {
        if (node is not { } element)
        {
            throw NetworkError.FromMessage(
                $"{operation}: the server returned no body where one was expected");
        }

        try
        {
            return element.Deserialize<T>(ManagementJson.Reader)
                   ?? throw NetworkError.FromMessage(
                       $"{operation}: the server's response deserialized to null");
        }
        catch (JsonException ex)
        {
            throw NetworkError.FromMessage(
                $"{operation}: the server's response did not match {typeof(T).Name}: {ex.Message}");
        }
    }

    /// <summary>Converts a bare-array response into a list of models (&#167;27.4 rule 4).</summary>
    internal static IReadOnlyList<T> DecodeList<T>(string operation, JsonElement? node)
    {
        if (node is not { } element || element.ValueKind != JsonValueKind.Array)
        {
            // An empty list is the honest answer to "what scopes are there" when the
            // server sent something that is not a list of them, and it keeps a malformed
            // read from taking down a plan that was only surveying.
            return Array.Empty<T>();
        }

        var items = new List<T>();
        foreach (JsonElement item in element.EnumerateArray())
        {
            items.Add(Decode<T>(operation, item));
        }

        return items;
    }

    /// <summary>
    /// Converts an <c>{items, total, offset, limit}</c> envelope into a
    /// <see cref="Page{T}"/>.
    /// </summary>
    /// <remarks>
    /// <c>total</c> is read from the envelope and never inferred from the item count:
    /// the whole point of the type is that the two differ (&#167;27.4 rule 4).
    /// </remarks>
    internal static Page<T> DecodePage<T>(string operation, JsonElement? node)
    {
        if (node is not { } element || element.ValueKind != JsonValueKind.Object)
        {
            return Page<T>.Empty();
        }

        IReadOnlyList<T> items = element.TryGetProperty("items", out JsonElement itemsEl)
            ? DecodeList<T>(operation, itemsEl)
            : Array.Empty<T>();
        return new Page<T>(items, IntOr(element, "total"), IntOr(element, "offset"), IntOr(element, "limit"));
    }

    private static int IntOr(JsonElement element, string name)
        => element.TryGetProperty(name, out JsonElement value) &&
           value.ValueKind == JsonValueKind.Number &&
           value.TryGetInt32(out int parsed)
            ? parsed
            : 0;

    /// <summary>
    /// Walks a paginated read to exhaustion, concatenating every page.
    /// </summary>
    /// <remarks>
    /// The <c>ListAllAsync</c> shape &#167;27.4 rule 4 requires. The walk stops on an
    /// empty page even when <c>total</c> disagrees, so a misreporting server costs one
    /// wasted request rather than an unbounded loop.
    /// </remarks>
    internal static async Task<IReadOnlyList<T>> CollectPagesAsync<T>(
        PageRequest? start, Func<PageRequest, Task<Page<T>>> fetch)
    {
        PageRequest request = start ?? PageRequest.First();
        var all = new List<T>();
        while (true)
        {
            Page<T> page = await fetch(request).ConfigureAwait(false);
            all.AddRange(page.Items);
            // The term is carried, not dropped (§27.4 rule 4): a walk that
            // filtered only its first request would concatenate the matches
            // with the unfiltered remainder.
            PageRequest? next = page.NextPage(request.Search);
            if (next is null)
            {
                return all;
            }

            request = next;
        }
    }
}
