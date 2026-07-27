using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Auth.Oidc;

/// <summary>
/// The seven CONTRACT.md &#167;12.3 rule 3 / &#167;12.4 stable, machine-readable ID-token
/// validation failure reason codes, carried on the resulting <see cref="AuthError.Reason"/>.
/// Exact wire spelling — used verbatim, never translated or localized.
/// </summary>
public static class IdTokenFailureReasons
{
    /// <summary>The JOSE header <c>alg</c> was not exactly <c>EdDSA</c> (&#167;12.4 rule 1).</summary>
    public const string InvalidAlg = "invalid_alg";

    /// <summary>The <c>kid</c> was absent, or still unknown after one JWKS re-fetch (&#167;12.4 rule 2).</summary>
    public const string UnknownKid = "unknown_kid";

    /// <summary>The Ed25519 signature did not verify against the resolved key (&#167;12.4 rule 2).</summary>
    public const string InvalidSignature = "invalid_signature";

    /// <summary>The <c>iss</c> claim did not exactly equal the discovery document's <c>issuer</c> (&#167;12.4 rule 3).</summary>
    public const string InvalidIssuer = "invalid_issuer";

    /// <summary>The <c>aud</c>/<c>azp</c> claims did not satisfy &#167;12.4 rule 4.</summary>
    public const string InvalidAudience = "invalid_audience";

    /// <summary>The <c>exp</c>/<c>iat</c>/<c>nbf</c> claims did not satisfy &#167;12.4 rule 5
    /// (including a missing <c>exp</c> or <c>iat</c> — &#167;12 port addendum item 11).</summary>
    public const string TokenExpired = "token_expired";

    /// <summary>The <c>nonce</c> claim was absent or did not match (&#167;12.4 rule 6).</summary>
    public const string NonceMismatch = "nonce_mismatch";
}

/// <summary>
/// The decoded, ALREADY-VALIDATED ID-token claim set carried by
/// <see cref="OidcTokenSet.IdClaims"/> (CONTRACT.md &#167;12.1).
/// </summary>
/// <remarks>
/// Claim names are kept verbatim in their JWT/OIDC spelling (<see cref="Iss"/>,
/// <see cref="Sub"/>, <see cref="Aud"/>, &#8230;) rather than C#'s usual naming
/// conventions — they are protocol identifiers a caller cross-references against OIDC Core.
/// <see cref="Extra"/> preserves any further claim the server sends (e.g. <c>email</c>,
/// <c>preferred_username</c>) — the ID token's full claim set is not enumerated by
/// <c>openapi.json</c> (the field is typed as an opaque string there), so SDKs MUST NOT
/// reject unknown claims.
/// </remarks>
public sealed class IdTokenClaims
{
    /// <summary>The issuer — matched for exact string equality against the discovery
    /// document's issuer (rule 3).</summary>
    public required string Iss { get; init; }

    /// <summary>The authenticated end user's stable identifier at AXIAM.</summary>
    public required string Sub { get; init; }

    /// <summary>The audience — contains the relying party's <c>client_id</c> (rule 4). May
    /// hold one or more values on the wire; always normalized to a list here.</summary>
    public required IReadOnlyList<string> Aud { get; init; }

    /// <summary>The expiry time (epoch seconds).</summary>
    public required long Exp { get; init; }

    /// <summary>The issued-at time (epoch seconds).</summary>
    public required long Iat { get; init; }

    /// <summary>The not-before time (epoch seconds), when the server sends one.</summary>
    public long? Nbf { get; init; }

    /// <summary>The nonce echoed back from the authorization request (rule 6). <c>null</c>
    /// when the grant did not require one (<c>oidc_refresh</c>/<c>login_client_credentials</c>).</summary>
    public string? Nonce { get; init; }

    /// <summary>The authorized party — required to equal <c>client_id</c> when
    /// <see cref="Aud"/> holds multiple audiences (rule 4).</summary>
    public string? Azp { get; init; }

    /// <summary>Preserves any claim not already modeled above (<c>null</c> when none).</summary>
    public IReadOnlyDictionary<string, JsonElement>? Extra { get; init; }
}

/// <summary>
/// Mirrors the TypeScript reference's <c>IdTokenExpectations</c> (&#167;12.4 rules 3-6):
/// what an already-signature-verified ID token is checked against.
/// </summary>
internal readonly record struct IdTokenExpectations(
    string Issuer,
    string ClientId,
    bool HasNonce,
    string? Nonce,
    int ClockSkewSeconds);

/// <summary>
/// ID-token claim validation — CONTRACT.md &#167;12.4, OIDC Core &#167;3.1.3.7.
/// </summary>
/// <remarks>
/// The signature half of &#167;12.4 (rules 1-2: alg allowlist, kid lookup, Ed25519
/// verification, single JWKS re-fetch) lives in
/// <see cref="JwksVerifier.VerifyOidcIdTokenSignatureAsync"/> — the SAME verifier the
/// &#167;10 middleware uses, extended (never forked) with a raw-payload entry point. This
/// class holds rules 3-6 (issuer, audience, time, nonce) plus the reason-code vocabulary
/// mapping, so both halves are independently testable — ported as one pair from the
/// TypeScript reference.
/// <para>
/// Every failure raises <see cref="AuthError"/> carrying one of the seven stable
/// <see cref="IdTokenFailureReasons"/> codes (&#167;12.3 rule 3). Rule 7 (all-or-nothing
/// discard) is enforced by the caller (<c>AxiamClient</c>'s <c>ToTokenSetAsync</c>): it
/// never returns an <see cref="OidcTokenSet"/> whose ID token failed here, so
/// <c>access_token</c>/<c>refresh_token</c> from the same response are dropped with it.
/// </para>
/// </remarks>
internal static class IdTokenValidator
{
    private static readonly string[] KnownClaimKeys = { "iss", "sub", "aud", "exp", "iat", "nbf", "nonce", "azp" };

    /// <summary>Maps a <see cref="JwksVerifier"/> signature-verification failure onto the
    /// matching &#167;12.4 rule-1/rule-2 reason code. Never embeds the token.</summary>
    internal static AuthError SignatureFailureToAuthError(OidcSignatureFailure failure) => failure switch
    {
        OidcSignatureFailure.InvalidAlg =>
            BuildError(IdTokenFailureReasons.InvalidAlg, "id_token alg header is not exactly EdDSA"),
        OidcSignatureFailure.UnknownKid =>
            BuildError(IdTokenFailureReasons.UnknownKid, "id_token kid is missing or unknown after one JWKS refetch"),
        _ =>
            BuildError(IdTokenFailureReasons.InvalidSignature, "id_token Ed25519 signature verification failed"),
    };

    /// <summary>
    /// Performs CONTRACT.md &#167;12.4 rules 3-6 (issuer, audience, time, nonce) over an
    /// already-signature-verified JWS payload, returning the decoded
    /// <see cref="IdTokenClaims"/> on success or throwing the matching reason-coded
    /// <see cref="AuthError"/> on the FIRST failure (rule 7's all-or-nothing discard is the
    /// caller's responsibility: it must never construct an <see cref="OidcTokenSet"/> from a
    /// partial result here).
    /// </summary>
    internal static IdTokenClaims Validate(JsonElement payload, IdTokenExpectations expectations, DateTimeOffset now)
    {
        string? iss = GetString(payload, "iss");

        // Rule 3 — exact string comparison. No normalization, no trailing-slash tolerance,
        // no prefix matching.
        if (iss is null || iss != expectations.Issuer)
        {
            throw BuildError(IdTokenFailureReasons.InvalidIssuer, "iss does not equal the discovery document issuer");
        }

        List<string> aud = ExtractAudience(payload);
        string? azp = GetString(payload, "azp");

        // Rule 4 — aud must contain our client_id; with multiple audiences an azp claim
        // must be present and equal to it.
        if (!aud.Contains(expectations.ClientId, StringComparer.Ordinal))
        {
            throw BuildError(IdTokenFailureReasons.InvalidAudience, "aud does not contain this client_id");
        }
        if (aud.Count > 1 && azp != expectations.ClientId)
        {
            throw BuildError(IdTokenFailureReasons.InvalidAudience, "aud holds multiple audiences and azp is absent or does not equal this client_id");
        }

        long skew = ResolveClockSkewSeconds(expectations.ClockSkewSeconds);
        long nowSec = now.ToUnixTimeSeconds();

        // Rule 5 — exp must be in the future, iat must not be in the future, nbf is
        // honored when present; all within skew seconds. exp/iat are treated as REQUIRED:
        // a token with no expiry could never satisfy "exp must be in the future", so
        // absence is an expiry failure, not a free pass (§12 port addendum item 11).
        if (!TryGetInt64(payload, "exp", out long exp))
        {
            throw BuildError(IdTokenFailureReasons.TokenExpired, "exp claim is missing");
        }
        if (exp + skew <= nowSec)
        {
            throw BuildError(IdTokenFailureReasons.TokenExpired, "exp is in the past");
        }

        if (!TryGetInt64(payload, "iat", out long iat))
        {
            throw BuildError(IdTokenFailureReasons.TokenExpired, "iat claim is missing");
        }
        if (iat - skew > nowSec)
        {
            throw BuildError(IdTokenFailureReasons.TokenExpired, "iat is in the future");
        }

        long? nbf = null;
        if (TryGetInt64(payload, "nbf", out long nbfValue))
        {
            nbf = nbfValue;
            if (nbfValue - skew > nowSec)
            {
                throw BuildError(IdTokenFailureReasons.TokenExpired, "nbf is in the future");
            }
        }

        // Rule 6 — mandatory for oidc_exchange (HasNonce=true), skipped for
        // oidc_refresh/login_client_credentials.
        string? nonce = GetString(payload, "nonce");
        if (expectations.HasNonce)
        {
            if (nonce is null || !ConstantTimeEquals(nonce, expectations.Nonce ?? string.Empty))
            {
                throw BuildError(IdTokenFailureReasons.NonceMismatch, "nonce claim is absent or does not match the request nonce");
            }
        }

        return new IdTokenClaims
        {
            Iss = iss,
            Sub = GetString(payload, "sub") ?? string.Empty,
            Aud = aud,
            Exp = exp,
            Iat = iat,
            Nbf = nbf,
            Nonce = nonce,
            Azp = azp,
            Extra = ExtractExtraClaims(payload),
        };
    }

    /// <summary>Clamps <paramref name="seconds"/> into [1, 60] — CONTRACT.md &#167;12.4
    /// rule 5 forbids configuring the skew ABOVE 60s, so a larger (or non-positive,
    /// unconfigured) value is silently reduced/defaulted rather than honored verbatim.</summary>
    private static long ResolveClockSkewSeconds(int seconds) => seconds is <= 0 or > 60 ? 60 : seconds;

    /// <summary>Constant-time string comparison, used for the nonce check &#167;12.4 rule 6
    /// requires. A length mismatch short-circuits to false via
    /// <see cref="CryptographicOperations.FixedTimeEquals"/>'s equal-length requirement.</summary>
    private static bool ConstantTimeEquals(string a, string b)
    {
        byte[] left = Encoding.UTF8.GetBytes(a);
        byte[] right = Encoding.UTF8.GetBytes(b);
        return left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    }

    private static AuthError BuildError(string reason, string detail) =>
        new($"id_token validation failed ({reason}): {detail}", reason);

    private static string? GetString(JsonElement payload, string property) =>
        payload.ValueKind == JsonValueKind.Object &&
        payload.TryGetProperty(property, out JsonElement element) &&
        element.ValueKind == JsonValueKind.String
            ? element.GetString()
            : null;

    private static bool TryGetInt64(JsonElement payload, string property, out long value)
    {
        value = 0;
        return payload.ValueKind == JsonValueKind.Object &&
               payload.TryGetProperty(property, out JsonElement element) &&
               element.ValueKind == JsonValueKind.Number &&
               element.TryGetInt64(out value);
    }

    /// <summary>Decodes the wire <c>aud</c> claim (a bare string OR a JSON array, per OIDC
    /// Core) into a list, always.</summary>
    private static List<string> ExtractAudience(JsonElement payload)
    {
        var result = new List<string>();
        if (payload.ValueKind != JsonValueKind.Object || !payload.TryGetProperty("aud", out JsonElement aud))
        {
            return result;
        }

        switch (aud.ValueKind)
        {
            case JsonValueKind.String:
                string? single = aud.GetString();
                if (single is not null)
                {
                    result.Add(single);
                }
                break;
            case JsonValueKind.Array:
                foreach (JsonElement item in aud.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String && item.GetString() is { } s)
                    {
                        result.Add(s);
                    }
                }
                break;
        }
        return result;
    }

    /// <summary>Decodes payload into an open map and strips every modeled claim, returning
    /// <c>null</c> rather than an empty map when nothing is left (&#167;12.1 open-map
    /// preservation requirement).</summary>
    private static IReadOnlyDictionary<string, JsonElement>? ExtractExtraClaims(JsonElement payload)
    {
        if (payload.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        Dictionary<string, JsonElement>? extra = null;
        foreach (JsonProperty property in payload.EnumerateObject())
        {
            if (Array.IndexOf(KnownClaimKeys, property.Name) >= 0)
            {
                continue;
            }
            extra ??= new Dictionary<string, JsonElement>();
            extra[property.Name] = property.Value;
        }
        return extra;
    }
}
