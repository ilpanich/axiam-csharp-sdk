using Axiam.Sdk.Management;
using Axiam.Sdk.Mcp;
using Microsoft.AspNetCore.Http;

namespace Axiam.Sdk.AspNetCore.Mcp;

/// <summary>
/// The &#167;28 challenge values one AXIAM ASP.NET Core guard singleton emits, built once
/// from <see cref="AxiamOptions"/> so that an invalid configuration is a construction-time
/// failure rather than a surprise on the 401 path.
/// </summary>
/// <remarks>
/// <c>null</c> — via <see cref="Build"/> returning <c>null</c> — is how "&#167;28 is off"
/// stays byte-for-byte indistinguishable from "&#167;28 is absent" (CONTRACT.md &#167;28.5
/// rule 1): every AXIAM guard in this package treats an absent <see cref="AxiamGuardChallenges"/>
/// exactly like a build of this SDK that predates &#167;28.
/// </remarks>
internal sealed class AxiamGuardChallenges
{
    /// <summary>The configured <see cref="AxiamOptions.ResourceMetadataUrl"/>, already
    /// validated as an absolute, correctly-encoded URL.</summary>
    public required string ResourceMetadataUrl { get; init; }

    /// <summary>The request path the metadata document is served at, exempted from
    /// authentication by every guard in this package (&#167;28.3 rule 2).</summary>
    public required string MetadataPath { get; init; }

    /// <summary>&#167;28.4 vector 1 &#8212; the request carried <b>no</b> authentication
    /// information, so RFC 6750 &#167;3 says not to name an error.</summary>
    public required string NoCredential { get; init; }

    /// <summary>&#167;28.4 vector 2 &#8212; a credential was presented and rejected. The
    /// only thing a 401 from this package ever says about why.</summary>
    public required string InvalidToken { get; init; }

    /// <summary>
    /// Validates a guard's &#167;28 configuration and precomputes the two challenges every
    /// 401 needs. Called once by every AXIAM guard singleton's constructor &#8212; never
    /// per-request.
    /// </summary>
    /// <remarks>
    /// Returns <c>null</c> when <see cref="AxiamOptions.ResourceMetadataUrl"/> is unset:
    /// &#167;28 is opt-in, and with the option absent the guard must behave exactly as it
    /// did before &#167;28 existed.
    /// <para>
    /// <b><see cref="AxiamOptions.ExpectedAudience"/> is mandatory once
    /// <see cref="AxiamOptions.ResourceMetadataUrl"/> is set</b>, and the refusal names
    /// both options. A resource server that publishes "tokens for me carry this
    /// <c>aud</c>" and then does not check <c>aud</c> has published a claim it does not
    /// honour, and a token minted for a <i>different</i> resource server opens it —
    /// that is the confusion RFC 8707 exists to prevent, so this is a refusal rather than
    /// a warning (&#167;28.5 rule 2).
    /// </para>
    /// </remarks>
    /// <param name="options">The AXIAM options the guard singleton was built from.</param>
    /// <param name="operation">The guard type's name, so the refusal says which guard refused.</param>
    /// <returns>The precomputed challenges, or <c>null</c> when &#167;28 is off.</returns>
    /// <exception cref="ValidationError">
    /// <see cref="AxiamOptions.ResourceMetadataUrl"/> is set without
    /// <see cref="AxiamOptions.ExpectedAudience"/>, or either is outside &#167;28's
    /// syntax.
    /// </exception>
    public static AxiamGuardChallenges? Build(AxiamOptions options, string operation)
    {
        ArgumentNullException.ThrowIfNull(options);
        string? resourceMetadataUrl = options.ResourceMetadataUrl;
        if (string.IsNullOrEmpty(resourceMetadataUrl))
        {
            return null;
        }

        if (string.IsNullOrEmpty(options.ExpectedAudience))
        {
            throw new ValidationError(
                $"{operation}: ResourceMetadataUrl requires ExpectedAudience to be set on the same AxiamOptions (CONTRACT.md §28.5 rule 2) — announcing a resource identifier obliges this server to check that an inbound token's `aud` is that identifier, and a resource server that announces itself without checking is opened by a token minted for somebody else",
                new[]
                {
                    new FieldError("ResourceMetadataUrl", "requires ExpectedAudience to also be set"),
                    new FieldError("ExpectedAudience", "required when ResourceMetadataUrl is set"),
                });
        }

        // Validates ResourceMetadataUrl as an absolute, §28.4-clean URL (raises
        // ValidationError itself when it is not) and builds the two request-independent
        // vectors. The metadata path is read back off the same string via System.Uri —
        // safe here specifically because BearerChallenge has already refused anything
        // System.Uri would parse differently than AxiamMcp's own non-normalising parser
        // (a "?", a "#", a bad scheme, a non-loopback http host, …).
        string noCredential = AxiamMcp.BearerChallenge(new BearerChallengeOptions { ResourceMetadataUrl = resourceMetadataUrl });
        string invalidToken = AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = resourceMetadataUrl,
            Error = AxiamBearerChallengeError.InvalidToken,
        });

        var uri = new Uri(resourceMetadataUrl, UriKind.Absolute);
        string metadataPath = uri.AbsolutePath.Length == 0 ? "/" : uri.AbsolutePath;

        return new AxiamGuardChallenges
        {
            ResourceMetadataUrl = resourceMetadataUrl,
            MetadataPath = metadataPath,
            NoCredential = noCredential,
            InvalidToken = invalidToken,
        };
    }

    /// <summary>
    /// Is <paramref name="method"/>/<paramref name="path"/> the unauthenticated
    /// <c>GET</c>/<c>HEAD</c> of the metadata document?
    /// </summary>
    /// <remarks>
    /// &#167;28.3 rule 2 requires the document to be reachable with no credential of any
    /// kind, and requires the SDK to exempt the path explicitly where the guard is
    /// applied globally — which <see cref="AxiamAuthMiddleware"/> is. A document that
    /// 401s cannot start the handshake it exists to start: the client would be holding a
    /// 401 and being told to go read a page that answers 401.
    /// </remarks>
    public bool IsMetadataDocumentRequest(string method, PathString path) =>
        (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase) ||
         string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase)) &&
        path.Equals(MetadataPath, StringComparison.Ordinal);
}
