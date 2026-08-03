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
/// <para>
/// <see cref="VerifyAsync"/> applies the COMPLETE CONTRACT.md &#167;10.1 "minimum
/// local-verification set", every rule of which fails closed. This SDK uses NO JWT
/// library: there is no <c>System.IdentityModel.Tokens.Jwt</c>,
/// <c>JwtSecurityTokenHandler</c> or <c>TokenValidationParameters</c> anywhere in the
/// dependency graph (.NET ships no Ed25519 primitive, so the JOSE processing is
/// hand-rolled over BouncyCastle). Every rule below is therefore enforced explicitly
/// here rather than delegated to a library whose defaults would need auditing.
/// </para>
/// <list type="number">
/// <item><description>
/// <b>signature</b> — <c>alg</c> is pinned to <c>"EdDSA"</c> and checked BEFORE any key
/// (<c>kid</c>) lookup, so <c>alg: none</c> and HS-family confusion are rejected without
/// ever consulting a key. The token's own header never selects its verifier.
/// </description></item>
/// <item><description>
/// <b><c>exp</c> — REQUIRED.</b> A token carrying no <c>exp</c>, or an <c>exp</c> that is
/// not a JSON number, is rejected. An absent <c>exp</c> is a *permanent credential*, never
/// "no expiry constraint" — treating it as the latter is the <c>SEC-080</c> defect.
/// </description></item>
/// <item><description>
/// <b><c>nbf</c></b> — honoured when present; an <c>nbf</c> in the future is rejected. An
/// absent <c>nbf</c> is valid.
/// </description></item>
/// <item><description>
/// <b><c>tenant_id</c> — REQUIRED and asserted</b> against the caller-supplied expected
/// tenant, AFTER signature verification succeeds. An absent claim, or an empty expected
/// tenant, fails closed. The JWKS document is organization-wide, not tenant-scoped, so a
/// valid signature alone never implies tenant authorization (Pitfall 3 — independently
/// confirmed by every sibling SDK).
/// </description></item>
/// <item><description>
/// <b><c>iss</c></b> — checked only when this verifier was constructed with an expected
/// issuer (see <see cref="Options.AxiamClientOptions.ExpectedIssuer"/>). Unset by default.
/// </description></item>
/// <item><description>
/// <b><c>aud</c></b> — checked only when this verifier was constructed with an expected
/// audience (see <see cref="Options.AxiamClientOptions.ExpectedAudience"/>). Unset by
/// default. Accepts the single-string and array forms RFC 7519 permits.
/// </description></item>
/// <item><description>
/// <b>clock skew</b> — <see cref="ClockSkewLeeway"/>, a named 60-second constant applied
/// to rules 2 and 3. It is deliberately NOT operator-configurable.
/// </description></item>
/// </list>
/// <para>
/// <see cref="VerifyAsync"/> NEVER throws for attacker-controlled input — every failure
/// mode (bad alg, unknown kid, tampered/invalid signature, wrong tenant, missing/expired/
/// non-numeric <c>exp</c>, future <c>nbf</c>, issuer/audience mismatch, malformed/
/// non-base64/truncated token) returns <c>null</c>. This matches the AMQP HMAC verifier's
/// fail-closed convention (<c>Amqp/Hmac.cs</c>).
/// </para>
/// </remarks>
public sealed class JwksVerifier
{
    /// <summary>
    /// The single, named, bounded clock-skew allowance applied to the <c>exp</c> and
    /// <c>nbf</c> checks (CONTRACT.md &#167;10.1 rule 7 — RECOMMENDED 60 s).
    /// </summary>
    /// <remarks>
    /// Deliberately a <c>const</c> and not an option: &#167;10.1 requires the leeway be
    /// "a named constant, not an inline literal" and forbids it being
    /// "operator-configurable to an unbounded value". Exposing it as a knob is the exact
    /// failure mode the rule exists to prevent.
    /// </remarks>
    public static readonly TimeSpan ClockSkewLeeway = TimeSpan.FromSeconds(60);

    private readonly HttpClient _http;
    private readonly Uri _jwksUri;
    private readonly TimeSpan _cacheTtl;
    private readonly string? _expectedIssuer;
    private readonly string? _expectedAudience;

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
    /// <param name="expectedIssuer">
    /// The <c>iss</c> claim value this verifier requires (CONTRACT.md &#167;10.1 rule 5).
    /// CONDITIONAL: <c>null</c>/empty (the default) means no issuer check is performed at
    /// all; once supplied, a token whose <c>iss</c> differs — or which carries no
    /// <c>iss</c> — is rejected. There is no default value and no hardcoded AXIAM issuer.
    /// </param>
    /// <param name="expectedAudience">
    /// The <c>aud</c> value this verifier requires (CONTRACT.md &#167;10.1 rule 6).
    /// CONDITIONAL: <c>null</c>/empty (the default) means no audience check is performed at
    /// all; once supplied, a token whose <c>aud</c> does not contain it — including a token
    /// with no <c>aud</c> at all — is rejected. A verifier fronting a user-facing resource
    /// server should generally expect <c>axiam:user</c>.
    /// </param>
    public JwksVerifier(
        HttpClient httpClient,
        Uri baseUrl,
        TimeSpan cacheTtl,
        string? expectedIssuer = null,
        string? expectedAudience = null)
        : this(httpClient, ResolveDefaultJwksUri(baseUrl), cacheTtl, exact: true, expectedIssuer, expectedAudience)
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

    private JwksVerifier(
        HttpClient httpClient,
        Uri jwksUri,
        TimeSpan cacheTtl,
        bool exact,
        string? expectedIssuer = null,
        string? expectedAudience = null)
    {
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _jwksUri = jwksUri ?? throw new ArgumentNullException(nameof(jwksUri));
        _cacheTtl = cacheTtl;
        // Normalize "" to null so an empty configuration value can never be mistaken for
        // "expect the empty string" — it means "not configured, so not checked".
        _expectedIssuer = string.IsNullOrWhiteSpace(expectedIssuer) ? null : expectedIssuer;
        _expectedAudience = string.IsNullOrWhiteSpace(expectedAudience) ? null : expectedAudience;
    }

    // NOT /.well-known/jwks.json — AXIAM does not serve that path
    // (crates/axiam-api-rest/src/handlers/oauth2.rs: GET /oauth2/jwks, org-wide).
    private static Uri ResolveDefaultJwksUri(Uri baseUrl)
    {
        ArgumentNullException.ThrowIfNull(baseUrl);
        return new Uri(baseUrl, "/oauth2/jwks");
    }

    /// <summary>
    /// Verifies <paramref name="jwt"/> against the COMPLETE CONTRACT.md &#167;10.1 minimum
    /// local-verification set: EdDSA-pinned signature against the cached (or freshly
    /// fetched) org-wide JWKS, a REQUIRED <c>exp</c>, an <c>nbf</c> honoured when present,
    /// a mandatory <c>tenant_id</c> asserted against <paramref name="expectedTenantId"/>,
    /// and the conditional <c>iss</c>/<c>aud</c> checks when this verifier was configured
    /// with an expectation — all under <see cref="ClockSkewLeeway"/>.
    /// Returns the decoded claims payload on success; returns <c>null</c> for ANY failure.
    /// Never throws on malformed or attacker-controlled input — see the type-level remarks
    /// for the fail-closed contract.
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

            return ApplyClaimPolicy(claims, expectedTenantId) ? claims : null;
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
    /// Applies CONTRACT.md &#167;10.1 rules 2&#8211;7 to already signature-verified claims
    /// (rule 1 is the alg pin, enforced before any key lookup). Returns <c>false</c> —
    /// meaning REJECT — for every failure.
    /// </summary>
    /// <remarks>
    /// Every rule fails closed. A required claim that is absent, unparseable, or of the
    /// wrong JSON type is a rejection; "the claim was missing so there was nothing to
    /// check" is never treated as success. That conflation is precisely the
    /// <c>SEC-080</c> defect this method exists to prevent.
    /// </remarks>
    private bool ApplyClaimPolicy(JsonElement claims, string expectedTenantId)
    {
        // Rule 4 — tenant_id: REQUIRED and asserted, AFTER signature verification
        // succeeds. A valid org-wide JWKS signature alone never authorizes a specific
        // tenant (T-21-07, Pitfall 3). An empty expected tenant is already rejected by
        // VerifyAsync's guard clause, so there is never "nothing to compare against".
        if (!claims.TryGetProperty("tenant_id", out JsonElement tenantEl) ||
            tenantEl.ValueKind != JsonValueKind.String ||
            tenantEl.GetString() != expectedTenantId)
        {
            return false;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;

        // Rule 2 — exp: REQUIRED. Absent, or present but not a JSON number, is a
        // rejection. An absent exp is a permanent credential, not an absent constraint.
        if (!TryReadNumericDate(claims, "exp", out DateTimeOffset expiresAt))
        {
            return false;
        }
        if (expiresAt <= now - ClockSkewLeeway)
        {
            return false; // expired — caller falls back to the reactive refresh path
        }

        // Rule 3 — nbf: honoured when present, absent is valid. Present-but-malformed is
        // still a rejection (wrong JSON type ⇒ reject), which is why the "absent" and
        // "unparseable" cases are distinguished here rather than collapsed.
        if (claims.TryGetProperty("nbf", out JsonElement nbfEl) && nbfEl.ValueKind != JsonValueKind.Null)
        {
            if (!TryReadNumericDate(claims, "nbf", out DateTimeOffset notBefore))
            {
                return false;
            }
            if (notBefore > now + ClockSkewLeeway)
            {
                return false; // not valid yet
            }
        }

        // Rule 5 — iss: checked ONLY when an expected issuer was configured.
        if (_expectedIssuer is not null)
        {
            if (!claims.TryGetProperty("iss", out JsonElement issEl) ||
                issEl.ValueKind != JsonValueKind.String ||
                issEl.GetString() != _expectedIssuer)
            {
                return false;
            }
        }

        // Rule 6 — aud: checked ONLY when an expected audience was configured. RFC 7519
        // §4.1.3 permits a single string or an array of strings; an absent aud can never
        // contain the expectation, so it fails closed without a special case.
        if (_expectedAudience is not null && !AudienceContains(claims, _expectedAudience))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Reads an RFC 7519 NumericDate claim ("A JSON numeric value"). Returns <c>false</c>
    /// when the claim is absent, JSON null, or of any JSON type other than a number — a
    /// quoted <c>"1700000000"</c> is a JSON string, not a NumericDate, and is rejected
    /// rather than coerced.
    /// </summary>
    private static bool TryReadNumericDate(JsonElement claims, string name, out DateTimeOffset value)
    {
        value = default;
        if (!claims.TryGetProperty(name, out JsonElement el) || el.ValueKind != JsonValueKind.Number)
        {
            return false;
        }

        // TryGetInt64 rejects a fractional NumericDate, which RFC 7519 permits; fall back
        // to the double form and truncate, the same rounding every sibling SDK applies.
        if (el.TryGetInt64(out long seconds))
        {
            value = DateTimeOffset.FromUnixTimeSeconds(seconds);
            return true;
        }
        if (el.TryGetDouble(out double fractional) &&
            !double.IsNaN(fractional) &&
            !double.IsInfinity(fractional) &&
            fractional >= -62135596800d &&
            fractional <= 253402300799d)
        {
            value = DateTimeOffset.FromUnixTimeSeconds((long)fractional);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Whether the token's <c>aud</c> claim contains <paramref name="expected"/>, honouring
    /// both RFC 7519 shapes (a single string, or an array of strings).
    /// </summary>
    private static bool AudienceContains(JsonElement claims, string expected)
    {
        if (!claims.TryGetProperty("aud", out JsonElement audEl))
        {
            return false;
        }

        if (audEl.ValueKind == JsonValueKind.String)
        {
            return audEl.GetString() == expected;
        }

        if (audEl.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement entry in audEl.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.String && entry.GetString() == expected)
                {
                    return true;
                }
            }
        }

        return false;
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
