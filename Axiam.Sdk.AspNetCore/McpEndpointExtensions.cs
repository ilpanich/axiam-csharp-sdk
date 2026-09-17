using System.Text.Json;
using Axiam.Sdk.Management;
using Axiam.Sdk.Mcp;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// <c>ServeProtectedResourceMetadata</c> (CONTRACT.md &#167;28.1/&#167;28.3, &#167;28.7's
/// C# row) &#8212; the ASP.NET Core minimal-API endpoint that publishes an
/// <see cref="AxiamMcp.ProtectedResourceMetadata"/> document.
/// </summary>
public static class McpEndpointExtensions
{
    /// <summary>
    /// Registers the one <c>GET</c> route that serves <paramref name="metadata"/>'s
    /// document, at the path <see cref="ProtectedResourceMetadata.MetadataPath"/> names,
    /// and returns <paramref name="metadata"/> unchanged so it can be chained.
    /// </summary>
    /// <remarks>
    /// <b>The path is derived, not chosen, and exactly one route is registered</b>
    /// (CONTRACT.md &#167;28.3): a deployment fronting several resources calls this once
    /// per resource, and the derived paths cannot collide because each comes from its
    /// own resource.
    /// <para>
    /// The response is <c>200</c> with <c>Content-Type: application/json</c>, the
    /// document as its body, <c>Cache-Control: public, max-age=3600</c> and
    /// <c>Access-Control-Allow-Origin: *</c> (never
    /// <c>Access-Control-Allow-Credentials</c>, which would ask a browser to attach a
    /// user's cookies to a request that has no use for them) &#8212; the CORS header is
    /// safe precisely because the response is identical for every caller. Nothing is
    /// read from the request, so there is no per-caller content and no
    /// <c>Set-Cookie</c>.
    /// </para>
    /// <para>
    /// <c>.AllowAnonymous()</c> is applied explicitly so the document still answers
    /// unauthenticated even in an application that has configured a global
    /// authorization fallback policy (&#167;28.3 rule 2). Where the &#167;10 guard is
    /// applied globally via <c>AxiamAuthMiddleware</c>, that middleware separately
    /// exempts this exact path from its own credential handling, derived from the same
    /// <see cref="AxiamOptions.ResourceMetadataUrl"/> &#8212; so the route works whichever
    /// order the middleware and this call are registered in.
    /// </para>
    /// </remarks>
    /// <param name="endpoints">The application's root endpoint route builder. Register on
    /// the root, not a router mounted under a prefix: a prefixed router would serve the
    /// document at a path the derived URL does not name.</param>
    /// <param name="metadata">The value <see cref="AxiamMcp.ProtectedResourceMetadata"/> returned.</param>
    /// <param name="guard">
    /// Optionally, the options the &#167;10 guard was built from. Passing it applies
    /// &#167;28.5 rule 3's cross-check: the guard's <see cref="AxiamOptions.ResourceMetadataUrl"/>
    /// must equal <paramref name="metadata"/>'s <see cref="ProtectedResourceMetadata.MetadataUrl"/>
    /// and its <see cref="AxiamOptions.ExpectedAudience"/> must equal
    /// <paramref name="metadata"/>'s <c>Document.Resource</c> &#8212; both plain string
    /// equality (RFC 3986 &#167;6.2.1), no normalisation. Omit it where the guard is
    /// configured in a different process; nothing can be checked from here then, and the
    /// operator configures both from the one <see cref="ProtectedResourceMetadata.MetadataUrl"/>
    /// constant instead.
    /// </param>
    /// <returns><paramref name="endpoints"/>, for chaining.</returns>
    /// <exception cref="ValidationError">
    /// <paramref name="guard"/> is given and its <see cref="AxiamOptions.ResourceMetadataUrl"/>
    /// is not exactly <paramref name="metadata"/>'s <see cref="ProtectedResourceMetadata.MetadataUrl"/>,
    /// or its <see cref="AxiamOptions.ExpectedAudience"/> is not exactly
    /// <paramref name="metadata"/>'s <c>Document.Resource</c>.
    /// </exception>
    public static IEndpointRouteBuilder ServeProtectedResourceMetadata(
        this IEndpointRouteBuilder endpoints,
        ProtectedResourceMetadata metadata,
        AxiamOptions? guard = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(metadata);

        if (guard is not null)
        {
            // §28.5 rule 3: two DIFFERENT strings, each compared against its own
            // counterpart — the resource is e.g. "https://mcp.example.com/mcp" and the
            // metadata URL is ".../.well-known/oauth-protected-resource/mcp". Plain
            // string equality: no normalisation, no case folding, no trailing-slash
            // tolerance — a difference here is a real misconfiguration and startup is a
            // better place to hear about it than a support ticket.
            if (guard.ResourceMetadataUrl != metadata.MetadataUrl)
            {
                throw new ValidationError(
                    $"ServeProtectedResourceMetadata: ResourceMetadataUrl is \"{guard.ResourceMetadataUrl}\" but this document is published at \"{metadata.MetadataUrl}\" — the challenge would point at a document that is not this resource server's (CONTRACT.md §28.5 rule 3)",
                    new[] { new FieldError("ResourceMetadataUrl", "must equal this document's MetadataUrl") });
            }
            if (guard.ExpectedAudience != metadata.Document.Resource)
            {
                throw new ValidationError(
                    $"ServeProtectedResourceMetadata: ExpectedAudience is \"{guard.ExpectedAudience}\" but this document announces \"{metadata.Document.Resource}\" — the document would announce one identifier while the guard checked `aud` against another, so every token the flow produced would be refused (CONTRACT.md §28.5 rule 3)",
                    new[] { new FieldError("ExpectedAudience", "must equal this document's Document.Resource") });
            }
        }

        // Serialized once: the response is identical for every caller (§28.3 rule 4), so
        // there is nothing per-request to build.
        string body = JsonSerializer.Serialize(metadata.Document);

        endpoints.MapGet(metadata.MetadataPath, async (HttpContext context) =>
        {
            context.Response.StatusCode = StatusCodes.Status200OK;
            // Set directly rather than via a Results.* helper: several of them append
            // "; charset=utf-8" to an explicit content type, and §28.3 rule 1 pins the
            // header to exactly "application/json".
            context.Response.ContentType = "application/json";
            context.Response.Headers.CacheControl = "public, max-age=3600";
            context.Response.Headers["Access-Control-Allow-Origin"] = "*";
            await context.Response.WriteAsync(body).ConfigureAwait(false);
        }).AllowAnonymous();

        return endpoints;
    }
}
