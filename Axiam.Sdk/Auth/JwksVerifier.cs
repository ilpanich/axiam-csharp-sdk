using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Axiam.Sdk.Auth;

/// <summary>
/// Local EdDSA (Ed25519) JWKS verification (D-02, CONTRACT.md &#167;10 local-verification
/// fast path). .NET has no native Ed25519/EdDSA support anywhere in
/// <c>System.Security.Cryptography</c> (confirmed research finding — <c>dotnet/runtime</c>
/// #14741/#63174 remain unimplemented through .NET 10 GA), so this class uses
/// <c>BouncyCastle.Cryptography</c>'s <see cref="Ed25519Signer"/> /
/// <see cref="Ed25519PublicKeyParameters"/> directly — the single, well-vetted,
/// verify-only crypto dependency D-02 permits.
/// </summary>
/// <remarks>
/// Security-critical invariants (T-21-06, T-21-07):
/// <list type="bullet">
/// <item>
/// <description>
/// <c>alg</c> is pinned to <c>"EdDSA"</c> and checked BEFORE any key (<c>kid</c>) lookup —
/// the token's own header is never trusted to select its verifier (alg-confusion
/// defense).
/// </description>
/// </item>
/// <item>
/// <description>
/// AFTER signature verification succeeds, the <c>tenant_id</c> claim is checked against
/// the caller-supplied expected tenant. The JWKS document is organization-wide, not
/// tenant-scoped, so a valid signature alone never implies tenant authorization
/// (Pitfall 3 — independently confirmed by every sibling SDK).
/// </description>
/// </item>
/// <item>
/// <description>
/// <see cref="VerifyAsync"/> NEVER throws for attacker-controlled input — every failure
/// mode (bad alg, unknown kid, tampered/invalid signature, wrong tenant, expired token,
/// malformed/non-base64/truncated token) returns <c>null</c>. This matches the AMQP
/// HMAC verifier's fail-closed convention (<c>Amqp/Hmac.cs</c>).
/// </description>
/// </item>
/// </list>
/// </remarks>
public sealed class JwksVerifier
{
    private readonly HttpClient _http;
    private readonly Uri _jwksUri;
    private readonly TimeSpan _cacheTtl;

    private Dictionary<string, byte[]> _keysByKid = new();
    private DateTimeOffset _fetchedAt = DateTimeOffset.MinValue;

    /// <summary>
    /// Serializes the actual JWKS fetch/cache-mutation path so a concurrent burst of
    /// unknown-<c>kid</c> verifications collapses to exactly one HTTP fetch (D-08/D-09).
    /// Reuses the same <see cref="SemaphoreSlim"/>(1, 1) primitive already used by the
    /// SDK's token-refresh single-flight guard (CS-01), for in-codebase consistency. This
    /// also fixes the pre-existing data race on <see cref="_keysByKid"/>/<see cref="_fetchedAt"/>,
    /// which previously had ZERO synchronization despite being mutated from concurrent
    /// <see cref="VerifyAsync"/> callers.
    /// </summary>
    private readonly SemaphoreSlim _fetchLock = new(1, 1);

    /// <param name="httpClient">Used only to fetch the JWKS document; ownership stays with the caller.</param>
    /// <param name="baseUrl">The AXIAM server base URL; the JWKS path is resolved relative to it.</param>
    /// <param name="cacheTtl">How long a fetched JWKS document is trusted before a refetch is forced.</param>
    public JwksVerifier(HttpClient httpClient, Uri baseUrl, TimeSpan cacheTtl)
        : this(httpClient, ResolveDefaultJwksUri(baseUrl), cacheTtl, exact: true)
    {
    }

    /// <summary>
    /// Constructs a <see cref="JwksVerifier"/> bound to the EXACT <paramref name="jwksUri"/>
    /// given — no path is appended. Used for the CONTRACT.md &#167;12.3 rule 6 OIDC
    /// relying-party path, which MUST read <c>jwks_uri</c> from the discovery document
    /// rather than assume the fixed AXIAM resource-server path this class's other
    /// constructor hardcodes. Sharing this one class (rather than a second
    /// implementation) is the "extend it, never fork it" CONTRACT.md &#167;12 requirement —
    /// <see cref="VerifyOidcIdTokenSignatureAsync"/> reuses the exact same fetch/cache
    /// fields and logic as <see cref="VerifyAsync"/>.
    /// </summary>
    internal static JwksVerifier ForJwksUri(HttpClient httpClient, Uri jwksUri, TimeSpan cacheTtl) =>
        new(httpClient, jwksUri, cacheTtl, exact: true);

    private JwksVerifier(HttpClient httpClient, Uri jwksUri, TimeSpan cacheTtl, bool exact)
    {
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _jwksUri = jwksUri ?? throw new ArgumentNullException(nameof(jwksUri));
        _cacheTtl = cacheTtl;
    }

    // NOT /.well-known/jwks.json — AXIAM does not serve that path
    // (crates/axiam-api-rest/src/handlers/oauth2.rs: GET /oauth2/jwks, org-wide).
    private static Uri ResolveDefaultJwksUri(Uri baseUrl)
    {
        ArgumentNullException.ThrowIfNull(baseUrl);
        return new Uri(baseUrl, "/oauth2/jwks");
    }

    /// <summary>
    /// Verifies <paramref name="jwt"/>'s EdDSA signature against the cached (or freshly
    /// fetched) org-wide JWKS AND checks the mandatory <c>tenant_id</c> claim against
    /// <paramref name="expectedTenantId"/>. Returns the decoded claims payload on success;
    /// returns <c>null</c> for ANY failure. Never throws on malformed or attacker-controlled
    /// input — see the type-level remarks for the fail-closed contract.
    /// </summary>
    public async Task<JsonElement?> VerifyAsync(string jwt, string expectedTenantId, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrEmpty(jwt) || string.IsNullOrEmpty(expectedTenantId))
                return null;

            string[] parts = jwt.Split('.');
            if (parts.Length != 3 || Array.Exists(parts, string.IsNullOrEmpty))
                return null;

            byte[] headerJson = Base64UrlDecode(parts[0]);
            using JsonDocument header = JsonDocument.Parse(headerJson);

            // alg-pin BEFORE any key lookup — never let the token select its own verifier
            // (alg-confusion defense, T-21-06).
            if (!header.RootElement.TryGetProperty("alg", out JsonElement algEl) ||
                algEl.ValueKind != JsonValueKind.String ||
                algEl.GetString() != "EdDSA")
            {
                return null;
            }

            if (!header.RootElement.TryGetProperty("kid", out JsonElement kidEl) ||
                kidEl.ValueKind != JsonValueKind.String)
            {
                return null;
            }
            string? kid = kidEl.GetString();
            if (string.IsNullOrEmpty(kid))
                return null;

            await EnsureFreshAsync(kid, cancellationToken).ConfigureAwait(false);
            if (!_keysByKid.TryGetValue(kid, out byte[]? rawPublicKey))
                return null; // unknown kid even after the one refetch attempt above

            byte[] signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
            byte[] signature = Base64UrlDecode(parts[2]);

            var verifier = new Ed25519Signer();
            verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(rawPublicKey));
            verifier.BlockUpdate(signingInput, 0, signingInput.Length);
            if (!verifier.VerifySignature(signature))
                return null;

            byte[] payloadJson = Base64UrlDecode(parts[1]);
            using JsonDocument payload = JsonDocument.Parse(payloadJson);
            JsonElement claims = payload.RootElement.Clone();

            // Mandatory cross-tenant check, performed AFTER signature verification
            // succeeds — a valid org-wide JWKS signature alone never authorizes a
            // specific tenant (T-21-07, Pitfall 3).
            if (!claims.TryGetProperty("tenant_id", out JsonElement tenantEl) ||
                tenantEl.ValueKind != JsonValueKind.String ||
                tenantEl.GetString() != expectedTenantId)
            {
                return null;
            }

            if (claims.TryGetProperty("exp", out JsonElement expEl) &&
                expEl.TryGetInt64(out long expSeconds) &&
                DateTimeOffset.FromUnixTimeSeconds(expSeconds) < DateTimeOffset.UtcNow)
            {
                return null; // expired — caller falls back to the reactive refresh path
            }

            return claims;
        }
        catch
        {
            // Fail closed on ANY malformed/attacker-controlled input (bad base64,
            // truncated/invalid JSON, wrong-length key, etc.) — never let a
            // parsing/crypto exception escape to the caller.
            return null;
        }
    }

    /// <summary>
    /// Performs the SAME alg-allowlist + kid-lookup + one-shot unknown-kid-refetch Ed25519
    /// signature verification as <see cref="VerifyAsync"/> — sharing this instance's
    /// <c>_keysByKid</c>/<c>_fetchedAt</c>/<c>_fetchLock</c> fields and
    /// <see cref="EnsureFreshAsync"/>, never a forked copy — but returns the raw,
    /// UNINTERPRETED claims payload plus a discriminated <see cref="OidcSignatureFailure"/>
    /// instead of a single collapsed <c>null</c>, and performs NEITHER the mandatory
    /// cross-tenant check NOR the <c>exp</c> check <see cref="VerifyAsync"/> does.
    /// </summary>
    /// <remarks>
    /// Exists for the CONTRACT.md &#167;12.4 ID-token validator
    /// (<see cref="Oidc.IdTokenValidator"/>), which needs an ID token's
    /// <c>iss</c>/<c>aud</c>/<c>nonce</c>/&#8230; claims — a shape this class does not model —
    /// while still sharing all of this class's signature-verification machinery, and which
    /// needs to distinguish &#167;12.4 rule 1 (bad <c>alg</c>) from rule 2 (unknown <c>kid</c>
    /// vs. an invalid signature under a KNOWN <c>kid</c>) to raise the matching stable reason
    /// code (&#167;12.3 rule 3) — a distinction <see cref="VerifyAsync"/>'s single-<c>null</c>
    /// return never needed for its AXIAM-resource-server callers. An ID token's own
    /// <c>exp</c>/<c>iat</c>/<c>nbf</c>/clock-skew handling is §12.4 rule 5, which the ID-token
    /// validator performs itself (its skew rules differ from this class's simple
    /// resource-token <c>exp</c> check), so this method deliberately does not duplicate it.
    /// </remarks>
    internal async Task<(JsonElement? Payload, OidcSignatureFailure? Failure)> VerifyOidcIdTokenSignatureAsync(
        string jwt, CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrEmpty(jwt))
            {
                return (null, OidcSignatureFailure.InvalidSignature);
            }

            string[] parts = jwt.Split('.');
            if (parts.Length != 3 || Array.Exists(parts, string.IsNullOrEmpty))
            {
                return (null, OidcSignatureFailure.InvalidSignature);
            }

            byte[] headerJson = Base64UrlDecode(parts[0]);
            using JsonDocument header = JsonDocument.Parse(headerJson);

            // alg-pin BEFORE any key lookup — never let the token select its own verifier
            // (alg-confusion defense, §12.4 rule 1, mirrors VerifyAsync above).
            if (!header.RootElement.TryGetProperty("alg", out JsonElement algEl) ||
                algEl.ValueKind != JsonValueKind.String ||
                algEl.GetString() != "EdDSA")
            {
                return (null, OidcSignatureFailure.InvalidAlg);
            }

            // §12.4 rule 2 / §12 port addendum item 12: a missing `kid` header is an
            // unknown-kid failure too, not a separate case.
            if (!header.RootElement.TryGetProperty("kid", out JsonElement kidEl) ||
                kidEl.ValueKind != JsonValueKind.String ||
                string.IsNullOrEmpty(kidEl.GetString()))
            {
                return (null, OidcSignatureFailure.UnknownKid);
            }
            string kid = kidEl.GetString()!;

            await EnsureFreshAsync(kid, cancellationToken).ConfigureAwait(false);
            if (!_keysByKid.TryGetValue(kid, out byte[]? rawPublicKey))
            {
                return (null, OidcSignatureFailure.UnknownKid); // still unknown after the one refetch
            }

            byte[] signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
            byte[] signature = Base64UrlDecode(parts[2]);

            var verifier = new Ed25519Signer();
            verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(rawPublicKey));
            verifier.BlockUpdate(signingInput, 0, signingInput.Length);
            if (!verifier.VerifySignature(signature))
            {
                return (null, OidcSignatureFailure.InvalidSignature);
            }

            byte[] payloadJson = Base64UrlDecode(parts[1]);
            using JsonDocument payload = JsonDocument.Parse(payloadJson);
            return (payload.RootElement.Clone(), null);
        }
        catch
        {
            // Fail closed on ANY malformed/attacker-controlled input, mirroring
            // VerifyAsync's fail-closed contract — classified as an invalid signature
            // (the CONTRACT.md §12.4 reason-code vocabulary has no separate "malformed"
            // code, and a token this class cannot even parse was never validly signed).
            return (null, OidcSignatureFailure.InvalidSignature);
        }
    }

    /// <summary>
    /// Refetches the JWKS document when the cache is stale OR <paramref name="unknownKid"/>
    /// is not already known — at most once per <see cref="VerifyAsync"/> call (no retry
    /// loop). Leaves the existing cache untouched if the fetch itself fails; the caller
    /// fails closed on the still-unknown <c>kid</c>.
    /// </summary>
    /// <remarks>
    /// D-08/D-09: the fast path below (outside the lock) skips the fetch entirely when
    /// the cache is already fresh — the common case. On a miss, <see cref="_fetchLock"/>
    /// is acquired and freshness is re-checked ONE more time under the lock, since
    /// another concurrent caller may have just performed the refetch while this one was
    /// waiting; only if still stale/unknown does the actual HTTP fetch + cache mutation
    /// happen. This collapses a concurrent invalid-<c>kid</c> burst to exactly one fetch.
    /// </remarks>
    private async Task EnsureFreshAsync(string unknownKid, CancellationToken cancellationToken)
    {
        if (IsFresh(unknownKid))
            return;

        await _fetchLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (IsFresh(unknownKid))
                return; // another caller already refreshed while we waited for the lock

            JwksDocument? document = await _http.GetFromJsonAsync<JwksDocument>(_jwksUri, cancellationToken).ConfigureAwait(false);
            if (document is null)
                return;

            var map = new Dictionary<string, byte[]>();
            foreach (Jwk jwk in document.Keys)
            {
                if (jwk.Kty != "OKP" || jwk.Crv != "Ed25519")
                    continue; // ignore non-EdDSA entries defensively — alg is pinned by the caller too
                map[jwk.Kid] = Base64UrlDecode(jwk.X); // raw 32-byte Ed25519 public key
            }

            _keysByKid = map;
            _fetchedAt = DateTimeOffset.UtcNow;
        }
        finally
        {
            _fetchLock.Release();
        }
    }

    private bool IsFresh(string kid)
    {
        bool expired = DateTimeOffset.UtcNow - _fetchedAt > _cacheTtl;
        bool unknown = !_keysByKid.ContainsKey(kid);
        return !expired && !unknown;
    }

    private static byte[] Base64UrlDecode(string s)
    {
        string padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}

/// <summary>
/// Discriminates a <see cref="JwksVerifier.VerifyOidcIdTokenSignatureAsync"/> failure onto
/// the matching CONTRACT.md &#167;12.4 rule-1/rule-2 reason-code family (&#167;12.3 rule 3):
/// <see cref="InvalidAlg"/> for rule 1, <see cref="UnknownKid"/>/<see cref="InvalidSignature"/>
/// for the two rule-2 outcomes.
/// </summary>
internal enum OidcSignatureFailure
{
    /// <summary>The JOSE header <c>alg</c> was not exactly <c>EdDSA</c> (&#167;12.4 rule 1).</summary>
    InvalidAlg,

    /// <summary>The <c>kid</c> header was absent, or still unknown after one JWKS
    /// re-fetch (&#167;12.4 rule 2, &#167;12 port addendum item 12).</summary>
    UnknownKid,

    /// <summary>The <c>kid</c> WAS found in the key set, but the Ed25519 signature did not
    /// verify against that key — or the token could not even be parsed (&#167;12.4 rule 2).</summary>
    InvalidSignature,
}
