using System.Text.RegularExpressions;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;

namespace Axiam.Sdk.Mcp;

/// <summary>
/// MCP resource-server helpers (CONTRACT.md &#167;28, RFC 9728 + RFC 6750) &#8212; the
/// resource-server half of the Model Context Protocol authorization handshake:
/// publishing the RFC 9728 protected-resource metadata document that tells a client
/// which authorization server guards this resource, and building the
/// <c>WWW-Authenticate</c> challenge that starts the client's discovery.
/// </summary>
/// <remarks>
/// <para>
/// &#167;28.0: this SDK implements the RESOURCE SERVER's half and nothing else. AXIAM is
/// the authorization server and implements none of &#167;28; the MCP client's half
/// (parsing a challenge, fetching a document, deciding whether to trust the
/// authorization server it names) is deliberately not in this contract version, for the
/// same reason &#167;20.3 stops at parsing a UMA challenge.
/// </para>
/// <para>
/// <b>Neither operation performs network I/O</b>, so &#167;16 (retry) and &#167;9
/// (single-flight refresh) do not apply, and neither method takes nor touches an
/// <c>AxiamClient</c>. Both are pure local computation, like <c>OidcBegin</c> and
/// <c>UmaChallenge.Parse</c> &#8212; and, per &#167;28.7's "no <c>Async</c> suffix
/// anywhere" rule, neither is awaitable.
/// </para>
/// <para>
/// <b>Nothing here is a source of truth about a token.</b> The document is a claim a
/// resource server publishes about itself; the challenge is a hint it gives a caller
/// that already failed. Whether a request is authorized stays &#167;10.1's and &#167;11's
/// decision, unchanged and unreachable from here.
/// </para>
/// </remarks>
public static class AxiamMcp
{
    /// <summary>
    /// RFC 9728 &#167;3.1's well-known prefix &#8212; the segment inserted between a
    /// resource's authority and its path to reach the document that describes it.
    /// </summary>
    public const string ProtectedResourceMetadataPrefix = "/.well-known/oauth-protected-resource";

    /// <summary>The only accepted value of <c>bearer_methods_supported</c> in this
    /// contract version (CONTRACT.md &#167;28.2 rule 6).</summary>
    public static readonly IReadOnlyList<string> DefaultBearerMethodsSupported = new[] { "header" };

    /// <summary>
    /// The three hosts &#167;28.2 rule 2 lets an <c>http</c> URL use, and the only ones.
    /// </summary>
    /// <remarks>
    /// AXIAM's RFC 8252 &#167;7.3 loopback hosts, reused verbatim. There is deliberately
    /// no flag, environment variable or debug build that widens this: a resource server
    /// reachable over plaintext on a routable host publishes an identifier an attacker
    /// can impersonate.
    /// </remarks>
    private static readonly HashSet<string> LoopbackHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "127.0.0.1",
        "[::1]",
        "localhost",
    };

    /// <summary>
    /// <c>scheme://authority[path][?query][#fragment]</c>, matched against the caller's
    /// string exactly as given.
    /// </summary>
    /// <remarks>
    /// Deliberately not <see cref="Uri"/>: that parser <b>normalises</b> &#8212; it
    /// lowercases the host, resolves <c>..</c> segments, appends a path to an
    /// authority-only URL and re-encodes. &#167;28.2 forbids adjusting a value to make it
    /// pass, and &#167;28.3 derives the document's own path from this string, so what is
    /// validated must be what was written.
    /// </remarks>
    private static readonly Regex AbsoluteUriRegex = new(
        @"^([A-Za-z][A-Za-z0-9+.\-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(#[\s\S]*)?$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>The pieces of an absolute URI, sliced out of the caller's string without
    /// normalisation.</summary>
    private readonly record struct ParsedUri(string Scheme, string Authority, string Path, bool HasQuery, bool HasFragment);

    /// <summary>How much of &#167;28.2 rule 1 a particular member is held to &#8212; rule
    /// 7 and &#167;28.4's <c>resource_metadata</c> relax two parts of it.</summary>
    private readonly record struct UriPolicy(bool AllowQuery, bool AllowFragment)
    {
        /// <summary><c>resource</c> and each <c>authorization_servers</c> entry: no
        /// query, no fragment.</summary>
        public static readonly UriPolicy Identifier = new(AllowQuery: false, AllowFragment: false);

        /// <summary><c>resource_documentation</c> (&#167;28.2 rule 7) and
        /// <c>resource_metadata</c> (&#167;28.4): a page for a human may be
        /// parameterised.</summary>
        public static readonly UriPolicy Locator = new(AllowQuery: true, AllowFragment: true);
    }

    /// <summary>
    /// <c>ProtectedResourceMetadata(options)</c> (CONTRACT.md &#167;28.1) &#8212; build
    /// and validate the RFC 9728 protected-resource metadata document this server
    /// publishes about itself, and derive the path and URL it is served at.
    /// </summary>
    /// <remarks>
    /// <b>Validation happens here and it refuses; it never repairs.</b> Every &#167;28.2
    /// rule is checked before any route exists and before any request is served, and a
    /// violation throws <see cref="ValidationError"/>. Nothing is normalised, trimmed,
    /// lowercased or re-encoded to make it pass: a value that needs adjusting is a
    /// configuration mistake an operator fixes in one line, and a helper that quietly
    /// fixed it would publish a document describing a resource server that does not
    /// exist.
    /// <para>
    /// <b>Nothing in the document may come from a request</b> (&#167;28.2 rule 8). Both
    /// <see cref="ProtectedResourceMetadataOptions.Resource"/> and
    /// <see cref="ProtectedResourceMetadataOptions.AuthorizationServers"/> are
    /// configuration; this SDK offers no option to build either from the <c>Host</c>
    /// header, the <c>Forwarded</c>/<c>X-Forwarded-*</c> family or the request URL,
    /// because a document assembled from the request is a document an attacker can point
    /// at an authorization server of their choosing &#8212; the whole handshake
    /// redirected with one header.
    /// </para>
    /// </remarks>
    /// <param name="options">The document's contents, per &#167;28.2.</param>
    /// <returns>The validated document, its metadata path and its metadata URL.</returns>
    /// <exception cref="ValidationError">Any &#167;28.2 rule is violated.</exception>
    public static ProtectedResourceMetadata ProtectedResourceMetadata(ProtectedResourceMetadataOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        const string op = "ProtectedResourceMetadata";

        // Rule 1 + rule 2.
        ParsedUri resource = RequireAbsoluteUri(op, "Resource", options.Resource, UriPolicy.Identifier);

        // Rule 3 + rule 4: at least one entry, each an issuer verbatim, no duplicates.
        IReadOnlyList<string>? serversInput = options.AuthorizationServers;
        if (serversInput is null)
        {
            throw Refuse(op, "AuthorizationServers", "must be a list");
        }
        if (serversInput.Count == 0)
        {
            throw Refuse(
                op,
                "AuthorizationServers",
                "must name at least one authorization server — a document that names none answers none of the question the client asked");
        }
        var seenServers = new HashSet<string>(StringComparer.Ordinal);
        var authorizationServers = new List<string>(serversInput.Count);
        foreach (string entry in serversInput)
        {
            RequireAbsoluteUri(op, "AuthorizationServers", entry, UriPolicy.Identifier);
            if (!seenServers.Add(entry))
            {
                throw Refuse(op, "AuthorizationServers", $"duplicate entry \"{entry}\"");
            }
            authorizationServers.Add(entry);
        }

        // Rule 5: NQCHAR tokens, order preserved, duplicates refused, empty omits.
        IReadOnlyList<string>? scopesInput = options.ScopesSupported;
        if (scopesInput is null)
        {
            throw Refuse(op, "ScopesSupported", "must be a list");
        }
        var seenScopes = new HashSet<string>(StringComparer.Ordinal);
        var scopesSupported = new List<string>();
        foreach (string scope in scopesInput)
        {
            if (string.IsNullOrEmpty(scope) || !IsAll(scope, IsNqchar))
            {
                throw Refuse(
                    op,
                    "ScopesSupported",
                    $"\"{scope}\" is not a scope token — one or more NQCHAR (no space, no '\"', no '\\', no control character, no non-ASCII)");
            }
            if (!seenScopes.Add(scope))
            {
                throw Refuse(op, "ScopesSupported", $"duplicate scope \"{scope}\"");
            }
            scopesSupported.Add(scope);
        }

        // Rule 6: exactly ["header"].
        IReadOnlyList<string> methods = options.BearerMethodsSupported;
        if (methods.Count != 1 || methods[0] != "header")
        {
            throw Refuse(
                op,
                "BearerMethodsSupported",
                "must be exactly [\"header\"] in this contract version — §10's guard reads a bearer credential from the Authorization header alone");
        }

        // Rule 7: absolute URL, query and fragment permitted, omitted when absent.
        string? documentation = options.ResourceDocumentation;
        if (documentation is not null)
        {
            RequireAbsoluteUri(op, "ResourceDocumentation", documentation, UriPolicy.Locator);
        }

        var document = new ProtectedResourceMetadataDocument
        {
            Resource = options.Resource,
            AuthorizationServers = authorizationServers,
            ScopesSupported = scopesSupported.Count > 0 ? scopesSupported : null,
            BearerMethodsSupported = DefaultBearerMethodsSupported,
            ResourceDocumentation = documentation,
        };

        string metadataPath = DeriveMetadataPath(resource.Path);
        return new ProtectedResourceMetadata
        {
            Document = document,
            MetadataPath = metadataPath,
            MetadataUrl = $"{resource.Scheme}://{resource.Authority}{metadataPath}",
        };
    }

    /// <summary>
    /// &#167;28.3's derivation: RFC 9728 &#167;3.1 inserts the well-known segment between
    /// the authority and the path. An empty path and a bare <c>/</c> both reach the root
    /// form; anything else is appended, <b>trailing slash included</b> &#8212; it is part
    /// of the identifier a client compares, and two resources that differ only by it are
    /// two resources.
    /// </summary>
    private static string DeriveMetadataPath(string resourcePath) =>
        resourcePath is "" or "/" ? ProtectedResourceMetadataPrefix : ProtectedResourceMetadataPrefix + resourcePath;

    /// <summary>
    /// <c>BearerChallenge(options)</c> (CONTRACT.md &#167;28.4) &#8212; build the
    /// <b>value</b> of a <c>WWW-Authenticate</c> header, never the whole header line and
    /// never a map. The caller sets the header.
    /// </summary>
    /// <remarks>
    /// Parameters appear in a fixed order &#8212; <c>error</c>, <c>error_description</c>,
    /// <c>scope</c>, <c>resource_metadata</c> &#8212; separated by exactly <c>", "</c>.
    /// <c>resource_metadata</c> is always present; the other three are omitted when not
    /// given.
    /// <para>
    /// <b>Every value is quoted and no value is ever escaped.</b> RFC 6750 &#167;3
    /// restricts each parameter to a character set that cannot contain <c>"</c> or
    /// <c>\</c>, so a value needing an escape is a value that does not belong in a
    /// challenge: this method refuses it rather than escaping, truncating or stripping
    /// it. A challenge is built from the code's own constants and a route's own
    /// configuration, so an invalid one is a programming error, not a runtime condition
    /// to degrade around.
    /// </para>
    /// </remarks>
    /// <param name="options">The challenge's parameters, per &#167;28.4.</param>
    /// <returns>The <c>WWW-Authenticate</c> header value, including the <c>Bearer</c> scheme.</returns>
    /// <exception cref="ValidationError">Any parameter is outside RFC 6750's syntax.</exception>
    public static string BearerChallenge(BearerChallengeOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        const string op = "BearerChallenge";
        var parts = new List<string>();

        if (options.Error is not null)
        {
            if (options.Error != AxiamBearerChallengeError.InvalidRequest &&
                options.Error != AxiamBearerChallengeError.InvalidToken &&
                options.Error != AxiamBearerChallengeError.InsufficientScope)
            {
                throw Refuse(
                    op,
                    "Error",
                    $"must be one of invalid_request, invalid_token, insufficient_scope — RFC 6750 §3.1 defines no others, and \"{options.Error}\" is not among them");
            }
            parts.Add($"error=\"{options.Error}\"");
        }

        if (options.ErrorDescription is not null)
        {
            string description = options.ErrorDescription;
            if (description.Length == 0 || !IsAll(description, IsNqschar))
            {
                throw Refuse(
                    op,
                    "ErrorDescription",
                    "must be one or more NQSCHAR (no '\"', no '\\', no control character, no non-ASCII) — a value needing an escape does not belong in a challenge");
            }
            parts.Add($"error_description=\"{description}\"");
        }

        if (options.Scope is not null)
        {
            string scope = options.Scope;
            if (scope.Length == 0)
            {
                throw Refuse(op, "Scope", "must be one or more scope tokens joined by a single space");
            }
            foreach (string token in scope.Split(' '))
            {
                if (token.Length == 0 || !IsAll(token, IsNqchar))
                {
                    throw Refuse(
                        op,
                        "Scope",
                        $"\"{scope}\" is not a space-joined list of scope tokens — no leading, trailing or doubled space, and no empty token");
                }
            }
            parts.Add($"scope=\"{scope}\"");
        }

        string url = options.ResourceMetadataUrl;
        RequireAbsoluteUri(op, "ResourceMetadataUrl", url, UriPolicy.Locator);
        if (!IsAll(url, IsNqchar))
        {
            throw Refuse(
                op,
                "ResourceMetadataUrl",
                "must carry no '\"', no '\\', no space and no control character — a correctly encoded URL cannot, so one that does has not been encoded");
        }
        parts.Add($"resource_metadata=\"{url}\"");

        return $"Bearer {string.Join(", ", parts)}";
    }

    /// <summary>&#167;28.2 rules 1 and 2, applied to one member. Returns the parse so a
    /// caller that needs the path (&#167;28.3) does not parse twice.</summary>
    private static ParsedUri RequireAbsoluteUri(string operation, string field, string? raw, UriPolicy policy)
    {
        if (string.IsNullOrEmpty(raw))
        {
            throw Refuse(operation, field, "must be a non-empty absolute URI");
        }

        ParsedUri? parsed = ParseAbsoluteUri(raw);
        if (parsed is null)
        {
            throw Refuse(operation, field, $"must be an absolute URI with a scheme and an authority, not \"{raw}\"");
        }
        ParsedUri value = parsed.Value;

        if (value.HasQuery && !policy.AllowQuery)
        {
            throw Refuse(operation, field, "must carry no query — §28.3 derives the metadata path from it");
        }
        if (value.HasFragment && !policy.AllowFragment)
        {
            throw Refuse(operation, field, "must carry no fragment");
        }

        string scheme = value.Scheme.ToLowerInvariant();
        if (scheme == "https")
        {
            return value;
        }
        if (scheme == "http" && LoopbackHosts.Contains(HostOf(value.Authority)))
        {
            return value;
        }
        throw Refuse(
            operation,
            field,
            $"must use https — http is accepted only on 127.0.0.1, [::1] or localhost, and \"{raw}\" is neither");
    }

    private static ParsedUri? ParseAbsoluteUri(string raw)
    {
        Match match = AbsoluteUriRegex.Match(raw);
        if (!match.Success)
        {
            return null;
        }
        string authority = match.Groups[2].Value;
        if (authority.Length == 0)
        {
            return null;
        }
        return new ParsedUri(
            match.Groups[1].Value,
            authority,
            match.Groups[3].Value,
            match.Groups[4].Success,
            match.Groups[5].Success);
    }

    /// <summary>
    /// The host inside an authority: <c>userinfo@</c> stripped, port stripped, an IPv6
    /// literal's brackets kept (so <c>[::1]</c> compares as &#167;28.2 rule 2 spells it).
    /// </summary>
    /// <remarks>
    /// Stripping <c>userinfo</c> is what makes <c>http://localhost@evil.example.com/</c>
    /// a refusal rather than a loopback pass &#8212; the host there is
    /// <c>evil.example.com</c>.
    /// </remarks>
    private static string HostOf(string authority)
    {
        int at = authority.LastIndexOf('@');
        string hostport = at >= 0 ? authority[(at + 1)..] : authority;
        if (hostport.StartsWith('['))
        {
            int close = hostport.IndexOf(']');
            return close < 0 ? hostport : hostport[..(close + 1)];
        }
        int colon = hostport.IndexOf(':');
        return colon < 0 ? hostport : hostport[..colon];
    }

    /// <summary><c>NQCHAR</c>: <c>%x21</c> / <c>%x23</c>&#8211;<c>%x5B</c> /
    /// <c>%x5D</c>&#8211;<c>%x7E</c>. No space, no <c>"</c>, no <c>\</c>, no control, no
    /// non-ASCII.</summary>
    private static bool IsNqchar(char c) => c == '\x21' || (c is >= '\x23' and <= '\x5B') || (c is >= '\x5D' and <= '\x7E');

    /// <summary><c>NQSCHAR</c>: <c>NQCHAR</c> plus the space (<c>%x20</c>).</summary>
    private static bool IsNqschar(char c) => c == '\x20' || IsNqchar(c);

    private static bool IsAll(string value, Func<char, bool> predicate)
    {
        foreach (char c in value)
        {
            if (!predicate(c))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Raise &#167;28's refusal.
    /// </summary>
    /// <remarks>
    /// &#167;28.6 pins the error taxonomy: "&#167;28's refusals are <c>ValidationError</c>;
    /// no new type". This SDK's <see cref="ValidationError"/> is &#167;27.4 rule 7's
    /// sub-type of <see cref="NetworkError"/>, reused here even though no server was
    /// asked and no request was made &#8212; the message names the operation and field so
    /// a caller can tell a &#167;28 refusal from a &#167;27 one at a glance.
    /// </remarks>
    private static ValidationError Refuse(string operation, string field, string message) =>
        new($"{operation}: {field}: {message} (CONTRACT.md §28)", new[] { new FieldError(field, message) });
}
