using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.Management;
using Axiam.Sdk.Options;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// Shared scaffolding for the CONTRACT.md &#167;27 management tests.
/// </summary>
/// <remarks>
/// <para>
/// The generated conformance suite and the hand-written semantics suites both build a
/// client the same way: a fake transport plus a seeded session cookie, so the org and
/// tenant UUIDs the management routes interpolate come from the access token's claims
/// exactly as they would in production, rather than being poked into private fields.
/// </para>
/// <para>
/// A queue of responses is the wrong shape here — a management test mounts a route and
/// asserts the SDK reached <em>that</em> path, which a queue cannot express. So this
/// routes on method and path and fails loudly on anything unmounted.
/// </para>
/// </remarks>
public abstract class ManagementTestBase : IDisposable
{
    /// <summary>The organization UUID the test client's access token carries.</summary>
    protected static readonly Guid OrgId = Guid.Parse("22222222-2222-4222-8222-222222222222");

    /// <summary>The tenant UUID the test client's access token carries.</summary>
    protected static readonly Guid TenantId = Guid.Parse("33333333-3333-4333-8333-333333333333");

    /// <summary>The identifier the generated cases pass for every <c>{..._id}</c> parameter.</summary>
    protected static readonly Guid ExampleId = Guid.Parse("11111111-1111-4111-8111-111111111111");

    /// <summary>The slug the client is built with, and sends as its tenant header.</summary>
    protected const string TenantSlug = "acme";

    private static readonly Uri Base = new("https://axiam.test");

    private readonly MountingHandler _handler;

    /// <summary>Builds a logged-in client over a mounting fake transport.</summary>
    protected ManagementTestBase()
    {
        _handler = new MountingHandler();
        Client = AxiamClient.CreateForTesting(
            Base,
            TenantSlug,
            new AxiamClientOptions { BaseUrl = Base, TenantId = TenantSlug },
            _handler);
        SeedSession(OrgId.ToString(), TenantId.ToString());
    }

    /// <summary>A client with a live session, pointed at the mounting transport.</summary>
    protected AxiamClient Client { get; private set; }

    /// <summary>Disposes the client and transport.</summary>
    public void Dispose()
    {
        Client.Dispose();
        _handler.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>What one mounted route answered, and what actually reached it.</summary>
    public sealed class Route
    {
        private readonly int _status;
        private readonly string _body;
        private readonly Func<Recorded, string>? _responder;

        internal Route(int status, string body)
        {
            _status = status;
            _body = body;
        }

        /// <summary>
        /// A route whose body depends on the request that reached it.
        /// </summary>
        /// <remarks>
        /// Needed by the §27.4 rule 4 walk assertions: a queue of fixed responses passes
        /// even when the walk asks for offset 0 three times, so the fixture has to answer
        /// <em>from</em> the offset it was asked for.
        /// </remarks>
        internal Route(int status, Func<Recorded, string> responder)
        {
            _status = status;
            _body = string.Empty;
            _responder = responder;
        }

        /// <summary>Every request that reached this route, in order.</summary>
        public List<Recorded> Requests { get; } = new();

        /// <summary>How many requests reached this route.</summary>
        public int Calls => Requests.Count;

        /// <summary>The most recent request this route saw.</summary>
        public Recorded Last => Requests.Count > 0
            ? Requests[^1]
            : throw new InvalidOperationException("route was never called");

        internal HttpResponseMessage Respond()
        {
            var response = new HttpResponseMessage((HttpStatusCode)_status);
            string body = _responder is null ? _body : _responder(Last);
            if (body.Length > 0)
            {
                response.Content = new StringContent(body, Encoding.UTF8, "application/json");
            }

            return response;
        }
    }

    /// <summary>What a mounted route saw.</summary>
    /// <param name="Method">The HTTP method.</param>
    /// <param name="Path">The path, without the query string.</param>
    /// <param name="Query">The decoded query parameters.</param>
    /// <param name="Body">The raw request body.</param>
    /// <param name="ContentType">The request's declared content type, or <c>null</c>.</param>
    public sealed record Recorded(
        string Method,
        string Path,
        IReadOnlyDictionary<string, string> Query,
        string Body,
        string? ContentType)
    {
        /// <summary>The request body's key set, sorted.</summary>
        public IReadOnlyList<string> Keys() =>
            JsonDocument.Parse(Body).RootElement.EnumerateObject()
                .Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToList();

        /// <summary>The request body as a JSON element.</summary>
        public JsonElement Json() => JsonDocument.Parse(Body).RootElement.Clone();
    }

    /// <summary>
    /// Mounts one route, answering <paramref name="body"/> at <paramref name="status"/>.
    /// </summary>
    /// <remarks>
    /// The match is exact on method and path, so an operation that sends its request
    /// somewhere other than the registry's path fails here rather than falling through
    /// to another mock.
    /// </remarks>
    /// <param name="method">The HTTP method to match.</param>
    /// <param name="path">The exact path to match.</param>
    /// <param name="status">The status to answer with.</param>
    /// <param name="body">The body to answer with, or empty for none.</param>
    /// <returns>The mounted route, for assertions.</returns>
    protected Route Mount(string method, string path, int status, string body)
        => _handler.Mount(method, path, status, body);

    /// <summary>
    /// Mounts one route whose body is computed from the request that reached it.
    /// </summary>
    /// <param name="method">The HTTP method to match.</param>
    /// <param name="path">The path to match, without a query string.</param>
    /// <param name="status">The status to answer with.</param>
    /// <param name="responder">Produces the body from the recorded request.</param>
    /// <returns>The mounted route, for asserting on what it saw.</returns>
    protected Route MountDynamic(
        string method, string path, int status, Func<Recorded, string> responder)
        => _handler.MountDynamic(method, path, status, responder);

    /// <summary>The route mounted at <c>method path</c>, for assertions.</summary>
    /// <param name="method">The mounted method.</param>
    /// <param name="path">The mounted path.</param>
    /// <returns>The route.</returns>
    protected Route RouteAt(string method, string path) => _handler.RouteAt(method, path);

    /// <summary>Requests that reached no mounted route.</summary>
    /// <returns>The unmatched requests, as <c>METHOD /path</c>.</returns>
    protected IReadOnlyList<string> Unmatched() => _handler.Unmatched;

    /// <summary>How many requests reached any mounted route, plus any that missed.</summary>
    /// <returns>The total request count.</returns>
    protected int TotalCalls() => _handler.TotalCalls;

    /// <summary>
    /// Replaces the client's session with one whose claims are as given.
    /// </summary>
    /// <param name="orgId">The raw <c>org_id</c> claim, valid UUID or not.</param>
    /// <param name="tenantId">The raw <c>tenant_id</c> claim, valid UUID or not.</param>
    protected void SeedSession(string? orgId, string? tenantId)
    {
        var payload = new Dictionary<string, object>
        {
            ["sub"] = ExampleId.ToString(),
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
        };
        if (orgId is not null)
        {
            payload["org_id"] = orgId;
        }

        if (tenantId is not null)
        {
            payload["tenant_id"] = tenantId;
        }

        SeedCookie(Client, "axiam_access", Jwt(payload));
    }

    /// <summary>Builds a second client over the same transport, with no session.</summary>
    /// <param name="options">Optional client options.</param>
    /// <returns>An anonymous client sharing this suite's mounted routes.</returns>
    protected AxiamClient AnonymousClient(AxiamClientOptions? options = null)
        => AxiamClient.CreateForTesting(
            Base,
            TenantSlug,
            options ?? new AxiamClientOptions { BaseUrl = Base, TenantId = TenantSlug },
            _handler);

    /// <summary>Gives <paramref name="client"/> a session with this suite's claims.</summary>
    /// <param name="client">The client to log in.</param>
    protected static void LogIn(AxiamClient client)
    {
        var payload = new Dictionary<string, object>
        {
            ["sub"] = ExampleId.ToString(),
            ["org_id"] = OrgId.ToString(),
            ["tenant_id"] = TenantId.ToString(),
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
        };
        SeedCookie(client, "axiam_access", Jwt(payload));
    }

    /// <summary>A single-item page envelope around <paramref name="item"/>.</summary>
    /// <param name="item">The item, or <c>null</c> for an empty page.</param>
    /// <returns>The envelope as JSON text.</returns>
    protected static string PageOf(string? item) => item is null
        ? """{"items":[],"total":0,"offset":0,"limit":200}"""
        : $$"""{"items":[{{item}}],"total":1,"offset":0,"limit":200}""";

    /// <summary>A minimal role response body.</summary>
    /// <param name="id">The role's id.</param>
    /// <param name="name">The role's name.</param>
    /// <param name="description">The role's description.</param>
    /// <returns>The body as JSON text.</returns>
    protected static string RoleBody(Guid id, string name, string description) =>
        $$"""
          {"id":"{{id}}","name":"{{name}}","description":"{{description}}","is_global":false,
           "tenant_id":"{{TenantId}}","created_at":"2026-08-26T00:00:00Z",
           "updated_at":"2026-08-26T00:00:00Z"}
          """.Replace("\n", string.Empty, StringComparison.Ordinal);

    /// <summary>
    /// Asserts every field the server sent survived the decode onto
    /// <paramref name="value"/>.
    /// </summary>
    /// <remarks>
    /// Re-encodes the decoded model and compares its key set against the body the route
    /// answered with. The mounted bodies carry exactly the fields <c>openapi.json</c>
    /// marks required, so anything missing here is a field the generated model dropped —
    /// which is not a hypothetical: the Go port of this surface silently lost
    /// <c>provisioning_token</c>, a ONE-TIME secret, to a generator that mishandled an
    /// inline <c>allOf</c>. Nothing in a surface test that only checks the method and
    /// path would have noticed.
    /// </remarks>
    /// <param name="value">The decoded model.</param>
    /// <param name="sent">The raw body the route answered with.</param>
    /// <typeparam name="T">The model type.</typeparam>
    protected static void AssertDecodedEveryField<T>(T value, string sent)
    {
        var expected = JsonDocument.Parse(sent).RootElement.EnumerateObject()
            .Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        string reEncoded = JsonSerializer.Serialize(
            value, ManagementJsonForTests());
        var actual = JsonDocument.Parse(reEncoded).RootElement.EnumerateObject()
            .Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        expected.ExceptWith(actual);
        Assert.True(
            expected.Count == 0,
            $"{typeof(T).Name} dropped [{string.Join(", ", expected.OrderBy(n => n, StringComparer.Ordinal))}]: " +
            "a field the generator did not emit is one no caller can ever read.");
    }

    /// <summary>
    /// The SDK's own §27 response reader, reached reflectively.
    /// </summary>
    /// <remarks>
    /// Re-encoding through the reader rather than a fresh <c>JsonSerializerOptions</c> is
    /// the point: a rule proved on a lookalike serializer is not proved. The reader is
    /// <c>internal</c> and this assembly has InternalsVisibleTo, but the options object
    /// itself is a private static field, so reflection is the only way in.
    /// </remarks>
    private static JsonSerializerOptions ManagementJsonForTests()
    {
        Type type = typeof(ManagementApi).Assembly
            .GetType("Axiam.Sdk.Management.ManagementJson", throwOnError: true)!;
        FieldInfo field = type.GetField("Reader", BindingFlags.NonPublic | BindingFlags.Static)!;
        return (JsonSerializerOptions)field.GetValue(null)!;
    }

    /// <summary>The §27.9 expected surface: every operation the vendored registry declares.</summary>
    /// <returns>The canonical operation names, sorted.</returns>
    protected static IReadOnlyList<string> ExpectedSurface()
    {
        string path = FindRegistry();
        using JsonDocument registry = JsonDocument.Parse(File.ReadAllText(path));
        var names = new List<string>();
        foreach (JsonProperty ns in registry.RootElement.GetProperty("namespaces").EnumerateObject())
        {
            foreach (JsonProperty op in ns.Value.GetProperty("operations").EnumerateObject())
            {
                names.Add($"{ns.Name}.{op.Name}");
            }
        }

        names.Sort(StringComparer.Ordinal);
        return names;
    }

    private static string FindRegistry()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, "management-registry.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException(
            "management-registry.json was not found above the test output directory; the " +
            "§27.9 surface assertion has nothing to compare against.");
    }

    private static string B64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Jwt(object payload)
    {
        string header = B64Url(Encoding.UTF8.GetBytes("""{"alg":"none"}"""));
        string body = B64Url(JsonSerializer.SerializeToUtf8Bytes(payload));
        return $"{header}.{body}.unsigned";
    }

    private static void SeedCookie(AxiamClient client, string name, string value)
    {
        FieldInfo field = typeof(AxiamClient)
            .GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var container = (CookieContainer)field.GetValue(client)!;
        container.Add(Base, new Cookie(name, value));
    }

    private sealed class MountingHandler : HttpMessageHandler
    {
        private readonly ConcurrentDictionary<string, Route> _routes = new(StringComparer.Ordinal);
        private readonly List<string> _unmatched = new();

        internal IReadOnlyList<string> Unmatched => _unmatched;

        internal int TotalCalls => _routes.Values.Sum(r => r.Calls) + _unmatched.Count;

        internal Route Mount(string method, string path, int status, string body)
        {
            var route = new Route(status, body);
            _routes[$"{method} {path}"] = route;
            return route;
        }

        internal Route MountDynamic(
            string method, string path, int status, Func<Recorded, string> responder)
        {
            var route = new Route(status, responder);
            _routes[$"{method} {path}"] = route;
            return route;
        }

        internal Route RouteAt(string method, string path) =>
            _routes.TryGetValue($"{method} {path}", out Route? route)
                ? route
                : throw new InvalidOperationException($"no route mounted at {method} {path}");

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = request.RequestUri!.AbsolutePath;
            string key = $"{request.Method.Method} {path}";
            if (!_routes.TryGetValue(key, out Route? route))
            {
                _unmatched.Add(key);
                return new HttpResponseMessage(HttpStatusCode.NotImplemented)
                {
                    Content = new StringContent($"no route mounted for {key}"),
                };
            }

            var query = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string pair in request.RequestUri.Query.TrimStart('?')
                         .Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = pair.IndexOf('=', StringComparison.Ordinal);
                if (eq > 0)
                {
                    query[Uri.UnescapeDataString(pair[..eq])] =
                        Uri.UnescapeDataString(pair[(eq + 1)..]);
                }
            }

            string body = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            route.Requests.Add(new Recorded(
                request.Method.Method, path, query, body,
                request.Content?.Headers.ContentType?.MediaType));
            return route.Respond();
        }
    }
}
