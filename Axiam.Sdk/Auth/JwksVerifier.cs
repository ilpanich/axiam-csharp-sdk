using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
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
/// <item><description>
/// <b><c>typ</c></b> (contract 1.68, rule 10) — when the header carries <c>typ</c> it must be
/// <c>at+jwt</c>; a header with no <c>typ</c> is not refused by this rule.
/// </description></item>
/// <item><description>
/// <b><c>purpose</c></b> (rule 11) — a token whose claim set contains a <c>purpose</c> member
/// (an MFA-challenge or WebAuthn-state token) is refused, whatever its value.
/// </description></item>
/// <item><description>
/// <b><c>kid</c></b> (rule 12) — required; the key is selected by it and never by "the only key
/// in the set". An unknown <c>kid</c> causes at most one JWKS re-fetch per 60 s window.
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

    /// <summary>
    /// The cooldown window of CONTRACT.md &#167;12.4 rule 2: an unknown <c>kid</c> on an otherwise
    /// fresh cache causes at most ONE JWKS re-fetch per window; every further unknown
    /// <c>kid</c> inside it is rejected from the cached set with no network call. Without it an
    /// unauthenticated client could drive one outbound fetch per forged token (audit C5).
    /// </summary>
    internal static readonly TimeSpan UnknownKidRefetchCooldown = TimeSpan.FromSeconds(60);

    /// <summary>The longest a fetched JWKS document is trusted, whatever the configured
    /// <c>JwksCacheTtl</c> or the advertised <c>Cache-Control: max-age</c> (CONTRACT.md &#167;12.4 rule 2,
    /// contract 1.69: at most 300 s, which keeps the stale bound below inside the ten minutes &#167;32.7 allows
    /// the SSF key cache).</summary>
    internal static readonly TimeSpan MaxCacheTtl = TimeSpan.FromSeconds(300);

    /// <summary>What a zero or negative <c>JwksCacheTtl</c> becomes: the documented default,
    /// never "no caching" (which would refetch the JWKS for every token).</summary>
    internal static readonly TimeSpan DefaultCacheTtl = TimeSpan.FromSeconds(300);

    /// <summary>How long past the TTL the held keys keep verifying while every refresh fails
    /// (CONTRACT.md &#167;12.4 rule 2, "Stale-if-error, bounded", owner decision D-10). After
    /// TTL + this, measured from the last SUCCESSFUL fetch, every token is refused until a fetch succeeds.</summary>
    internal static readonly TimeSpan StaleBound = TimeSpan.FromSeconds(300);

    /// <summary>Clamps a configured cache TTL into (0, <see cref="MaxCacheTtl"/>].</summary>
    internal static TimeSpan ClampCacheTtl(TimeSpan configured) =>
        configured <= TimeSpan.Zero ? DefaultCacheTtl : configured > MaxCacheTtl ? MaxCacheTtl : configured;

    private readonly HttpClient _http;
    private readonly Uri _jwksUri;
    private readonly TimeSpan _configuredTtl;

    /// <summary><c>true</c> when the caller set a positive TTL: then it wins (clamped to 300 s) and an advertised
    /// <c>max-age</c> is ignored; otherwise the advertised one (clamped) is used when the response carries it.</summary>
    private readonly bool _ttlConfigured;

    /// <summary>The TTL in force: the configured one when set, else the advertised <c>max-age</c> (clamped to
    /// <see cref="MaxCacheTtl"/>), else the default. Written by the single in-flight refresh only.</summary>
    private TimeSpan _cacheTtl;

    /// <summary>The <c>ETag</c> of the held set, sent as <c>If-None-Match</c> on a refresh.</summary>
    private string? _etag;

    /// <summary>UTC ticks of the last FAILED refresh; -1 = none since the last success. A failed attempt counts
    /// toward the cooldown window, so a failing endpoint costs one fetch per window, not one per token.</summary>
    private long _lastFailedRefreshTicks = -1;

    /// <summary>UTC ticks of the start of the last refresh of any outcome; -1 = never.</summary>
    private long _lastRefreshStartTicks = -1;

    private readonly string? _expectedIssuer;
    private readonly string? _expectedAudience;

    /// <summary>
    /// The optional CONTRACT.md &#167;10.4 revocation feed. <c>null</c> — the default — is
    /// the feature off, which is what every integration built before contract 1.44 gets on
    /// upgrade.
    /// </summary>
    private readonly RevocationFeed? _revocationFeed;

    private Dictionary<string, byte[]> _keysByKid = new();
    private DateTimeOffset _fetchedAt = DateTimeOffset.MinValue;

    /// <summary>
    /// Test seam for the cache clock (the JWKS cache lifetime and the unknown-<c>kid</c>
    /// cooldown). <c>null</c> — the default and the only production value — is the wall
    /// clock. The claim checks (<c>exp</c>, <c>nbf</c>) always read the wall clock.
    /// </summary>
    internal Func<DateTimeOffset>? CacheClock { get; set; }

    /// <summary>UTC ticks of the last re-fetch caused by an unknown <c>kid</c>; -1 = never.
    /// A <c>long</c> so it can be read without tearing.</summary>
    private long _lastUnknownKidRefetchTicks = -1;

    private DateTimeOffset CacheNow() => CacheClock?.Invoke() ?? DateTimeOffset.UtcNow;

    /// <summary>
    /// Serializes the actual JWKS fetch/cache-mutation path so a concurrent burst of
    /// unknown-<c>kid</c> verifications collapses to exactly one HTTP fetch (D-08/D-09).
    /// Reuses the same <see cref="SemaphoreSlim"/>(1, 1) primitive already used by the
    /// SDK's token-refresh single-flight guard (CS-01), for in-codebase consistency. This
    /// also fixes the pre-existing data race on <see cref="_keysByKid"/>/<see cref="_fetchedAt"/>,
    /// which previously had ZERO synchronization despite being mutated from concurrent
    /// <see cref="VerifyAsync"/> callers.
    /// </summary>
    private readonly object _gate = new();

    /// <summary>The refresh under way, if any (single flight). Guarded by <see cref="_gate"/>; the lock is never held
    /// across network I/O.</summary>
    private Task? _inFlight;

    /// <summary>The SDK's own bound on one JWKS fetch, independent of any caller's cancellation.</summary>
    internal static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(30);

    /// <param name="httpClient">Used only to fetch the JWKS document; ownership stays with the caller.</param>
    /// <param name="baseUrl">The AXIAM server base URL; the JWKS path is resolved relative to it.</param>
    /// <param name="cacheTtl">How long a fetched JWKS document is trusted before a refetch is forced.
    /// Clamped: a value above 300 s becomes 300 s. A zero or negative one means "not set": the advertised
    /// <c>Cache-Control: max-age</c> (clamped to 300 s) is used when present, else the 300 s default.</param>
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
    /// <param name="revocationFeed">
    /// The CONTRACT.md &#167;10.4 session-revocation feed (contract 1.44). OPTIONAL, and
    /// <c>null</c> — the default — is the feature <strong>off</strong>: nothing is fetched,
    /// and this verifier behaves byte-for-byte as it did before contract 1.44. Supplying one
    /// lets a revoked session be rejected within one poll interval rather than one token
    /// lifetime; it can only ever turn an accept into a reject, and a feed that is
    /// unreachable or unusable behaves exactly as no feed at all.
    /// </param>
    public JwksVerifier(
        HttpClient httpClient,
        Uri baseUrl,
        TimeSpan cacheTtl,
        string? expectedIssuer = null,
        string? expectedAudience = null,
        RevocationFeed? revocationFeed = null)
        : this(httpClient, ResolveDefaultJwksUri(baseUrl), cacheTtl, exact: true, expectedIssuer, expectedAudience, revocationFeed)
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
        string? expectedAudience = null,
        RevocationFeed? revocationFeed = null)
    {
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _jwksUri = jwksUri ?? throw new ArgumentNullException(nameof(jwksUri));
        _ttlConfigured = cacheTtl > TimeSpan.Zero;
        _configuredTtl = ClampCacheTtl(cacheTtl);
        _cacheTtl = _configuredTtl;
        _revocationFeed = revocationFeed;
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
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Rule 9, and it is the documented guard entry point.</b> This method has NO
    /// transport evidence to check a sender constraint against, so — per CONTRACT.md
    /// &#167;10.1 rule 9's own table — it refuses ANY token carrying <c>cnf</c>, whatever
    /// method it names: "a different certificate, or none" is exactly this case. A
    /// resource server that needs to accept a bound token (the &#167;6.1 device login
    /// mints certificate-bound tokens by default) calls
    /// <see cref="VerifyWithProofsAsync"/> instead, supplying the evidence from ITS OWN
    /// connection. Until this method enforced rule 9, a token lifted off a device and
    /// replayed as a bearer credential was accepted here like any other — the defect
    /// CONTRACT.md &#167;10.1 rule 9's compatibility note calls out, closed in contract
    /// 1.51 (Breaking: a caller that previously accepted bound tokens through this method
    /// with no evidence now gets <c>null</c>/401 for them).
    /// </para>
    /// <para>
    /// Returns the decoded claims payload on success; returns <c>null</c> for ANY
    /// failure. Never throws on malformed or attacker-controlled input — see the
    /// type-level remarks for the fail-closed contract.
    /// </para>
    /// </remarks>
    public async Task<JsonElement?> VerifyAsync(string jwt, string expectedTenantId, CancellationToken cancellationToken = default)
    {
        JsonElement? claims = await VerifyCoreAsync(jwt, expectedTenantId, cancellationToken).ConfigureAwait(false);
        if (claims is not { } resolved)
        {
            return null;
        }

        // Rule 9, no-evidence case: ANY cnf at all is refused here — see the remarks
        // above. VerifyTokenBinding with PresentedProofs.None() is exactly this rule
        // (cnf absent -> accept; cnf present, no proofs -> refuse on every row), so the
        // no-evidence and full-evidence paths cannot silently drift apart.
        return VerifyTokenBinding(resolved, PresentedProofs.None()) ? resolved : null;
    }

    /// <summary>
    /// The FULL CONTRACT.md &#167;10.1 rule 9, with evidence (contract 1.51). Applies
    /// every rule <see cref="VerifyAsync"/> does, and additionally verifies a sender
    /// constraint against <paramref name="proofs"/> — the certificate and/or DPoP key the
    /// CALLER proved possession of on THIS connection and request — rather than refusing
    /// every bound token outright.
    /// </summary>
    /// <remarks>
    /// This is the entry point for a resource server that accepts &#167;6.1 device
    /// (certificate-bound) or &#167;21.7 DPoP-bound tokens. Under ASP.NET Core the
    /// certificate evidence comes from <c>HttpContext.Connection.ClientCertificate</c>
    /// (via <see cref="CertificateThumbprintS256"/>) — NEVER from a request header, which
    /// is exactly what <see cref="VerifyTokenBinding"/>'s own remarks already require of
    /// <paramref name="proofs"/>.
    /// </remarks>
    /// <param name="jwt">The token to verify.</param>
    /// <param name="expectedTenantId">The tenant this token must belong to.</param>
    /// <param name="proofs">What the caller proved on this connection and request.</param>
    /// <param name="cancellationToken">Cancels the JWKS fetch, if one is needed.</param>
    /// <returns>The decoded claims on success (including when the token is unbound, or
    /// bound and the matching proof(s) are present); <c>null</c> for ANY failure,
    /// including a bound token whose constraint <paramref name="proofs"/> does not
    /// satisfy.</returns>
    public async Task<JsonElement?> VerifyWithProofsAsync(
        string jwt, string expectedTenantId, PresentedProofs proofs, CancellationToken cancellationToken = default)
    {
        JsonElement? claims = await VerifyCoreAsync(jwt, expectedTenantId, cancellationToken).ConfigureAwait(false);
        if (claims is not { } resolved)
        {
            return null;
        }

        return VerifyTokenBinding(resolved, proofs) ? resolved : null;
    }

    /// <summary>
    /// Rules 1&#8211;8 and &#167;10.4 — everything <see cref="VerifyAsync"/> and
    /// <see cref="VerifyWithProofsAsync"/> share. Rule 9 is deliberately NOT applied
    /// here: it needs evidence (or the deliberate absence of any, for
    /// <see cref="VerifyAsync"/>'s case), which only the two public callers know how to
    /// supply.
    /// </summary>
    private async Task<JsonElement?> VerifyCoreAsync(string jwt, string expectedTenantId, CancellationToken cancellationToken)
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

            // Rule 10 (contract 1.68, audit N14): when the header carries `typ` it MUST be
            // at+jwt. Checked before any key lookup, so a purpose token (an MFA challenge,
            // a WebAuthn state token, a logout or SET token) causes no JWKS fetch either.
            if (header.RootElement.TryGetProperty("typ", out JsonElement typEl) && !IsAccessTokenType(typEl))
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
            if (!TryGetHeldKey(kid, out byte[]? rawPublicKey))
                return null; // unknown kid even after the one refetch attempt above, or the stale bound has passed

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

            // Rule 11 (contract 1.68, audit N14): a token whose claim set contains a `purpose`
            // member is not an access token, whatever its value (null included) and whatever
            // `typ` says. Read from the verified payload itself, not from a claims model.
            if (claims.ValueKind != JsonValueKind.Object || claims.TryGetProperty("purpose", out _))
                return null;

            if (!ApplyClaimPolicy(claims, expectedTenantId))
                return null;

            // CONTRACT.md §10.4 (contract 1.44) — LAST, and only after every §10.1 rule
            // has already decided to accept. The feed "only ever rejects" (rule 4), so
            // running it here rather than earlier is what makes that true: a token that
            // fails a §10.1 rule is rejected whatever the feed says, and the feed is not
            // consulted — nor fetched — for it at all.
            //
            // This sits in VerifyAsync and NOT in the shared signature-verification helper
            // below, so the §12.4 ID-token path cannot reach it: an ID token carries no
            // AXIAM session and has no `sid` to match.
            if (_revocationFeed is not null)
            {
                string? sid = claims.TryGetProperty("sid", out JsonElement sidEl) &&
                              sidEl.ValueKind == JsonValueKind.String
                    ? sidEl.GetString()
                    : null;

                // Rule 6: a token with no `sid` — client credentials, an RPT, a token
                // exchange — is never matched. Hashing `jti` instead would match nothing
                // while looking like it worked.
                if (await _revocationFeed.IsRevokedAsync(sid, cancellationToken).ConfigureAwait(false))
                    return null;
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
    /// <c>_keysByKid</c>/<c>_fetchedAt</c>/in-flight guard fields and
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
            if (!TryGetHeldKey(kid, out byte[]? rawPublicKey))
            {
                return (null, OidcSignatureFailure.UnknownKid); // still unknown after the one refetch, or past the stale bound
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
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // A caller's cancellation is not a verdict on the token: it must not be reported as a bad signature
            // (C164-40) - the JWKS fetch was abandoned, nothing was verified.
            throw;
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
    /// CONTRACT.md &#167;10.1 rule 10: <c>typ</c> is <c>at+jwt</c> (RFC 9068 &#167;2.1), compared
    /// ASCII case-insensitively, with or without the <c>application/</c> prefix (RFC 7515
    /// &#167;4.1.9). Anything that is not that string, a non-string and JSON <c>null</c> included,
    /// is not an access-token type.
    /// </summary>
    private static bool IsAccessTokenType(JsonElement typ)
    {
        if (typ.ValueKind != JsonValueKind.String || typ.GetString() is not { } value)
        {
            return false;
        }
        const string prefix = "application/";
        if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            value = value[prefix.Length..];
        }
        return string.Equals(value, "at+jwt", StringComparison.OrdinalIgnoreCase);
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
    /// CONTRACT.md §10.1 <b>rule 9</b> — enforce a token's sender constraint against the
    /// certificate the caller presented on <b>this</b> connection
    /// (RFC 8705 §3 / RFC 7800, contract 1.15).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A token carrying <c>cnf</c> is <b>not</b> a bearer token. Accepting one without
    /// proving the caller holds the named key converts it straight back into one,
    /// discarding the whole protection the operator turned on — which is why this is a
    /// rule and not a recommendation.
    /// </para>
    /// <para>The four cases:</para>
    /// <list type="table">
    ///   <item><term>cnf absent</term><description>anything → true (an ordinary bearer token)</description></item>
    ///   <item><term>x5t#S256 equal</term><description>→ true</description></item>
    ///   <item><term>x5t#S256 different, or no certificate</term><description>→ false</description></item>
    ///   <item><term>cnf present with no x5t#S256</term><description>anything → false</description></item>
    /// </list>
    /// <para>
    /// The first row is why adopting this rule breaks nothing: an <b>unbound</b> token is
    /// still accepted whether or not a certificate is present. Rule 9 constrains tokens
    /// that claim a constraint; it does not make certificates mandatory.
    /// </para>
    /// <para>
    /// The last row is the one that is easy to get wrong. A <c>cnf</c> naming a
    /// confirmation method this SDK cannot check — a DPoP <c>jkt</c>, say — is an
    /// <i>unverifiable constraint</i>, never <i>no constraint</i>. Read the other way, a
    /// sender-constrained token silently degrades to a bearer token the day a newer AXIAM
    /// issues a confirmation this SDK predates.
    /// </para>
    /// <para>
    /// <b>The thumbprint must come from the transport.</b> Under ASP.NET Core that is
    /// <c>HttpContext.Connection.ClientCertificate</c> passed through
    /// <see cref="CertificateThumbprintS256"/>, or a value a <i>trusted</i> terminating
    /// proxy forwarded over a channel your application controls. Never from a
    /// caller-settable request header: a forgeable input makes the whole mechanism
    /// decorative.
    /// </para>
    /// <para>
    /// <see cref="VerifyAsync"/> deliberately does <b>not</b> apply this rule — it has no
    /// transport to ask. A resource server accepting bound tokens must call both.
    /// </para>
    /// </remarks>
    /// <param name="claims">The verified claims returned by <see cref="VerifyAsync"/>.</param>
    /// <param name="presentedThumbprint">
    /// RFC 8705 §3.1 <c>x5t#S256</c> of the peer certificate on this connection, or
    /// <c>null</c> when the connection carries none.
    /// </param>
    /// <returns><c>true</c> when the constraint is satisfied or absent; otherwise <c>false</c>.</returns>
    public static bool VerifyCertificateBinding(JsonElement claims, string? presentedThumbprint)
    {
        if (!claims.TryGetProperty("cnf", out JsonElement cnf) || cnf.ValueKind == JsonValueKind.Null)
        {
            // An ordinary bearer token.
            return true;
        }

        if (cnf.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (!cnf.TryGetProperty("x5t#S256", out JsonElement x5tEl) ||
            x5tEl.ValueKind != JsonValueKind.String)
        {
            // A confirmation naming a method this entry point cannot check — including a
            // DPoP jkt. Fail closed; use VerifyTokenBinding for DPoP.
            return false;
        }

        // A cnf naming BOTH methods is a CONJUNCTION (contract 1.16): this method can
        // establish one half and must not answer for the whole. Refusing here is what
        // stops "check whichever we can".
        if (cnf.TryGetProperty("jkt", out JsonElement jktEl) &&
            jktEl.ValueKind == JsonValueKind.String &&
            !string.IsNullOrEmpty(jktEl.GetString()))
        {
            return false;
        }

        string? expected = x5tEl.GetString();
        if (string.IsNullOrEmpty(expected) || string.IsNullOrEmpty(presentedThumbprint))
        {
            return false;
        }

        // Constant-time. The thumbprint is usually public — it derives from a certificate
        // sent in the clear during the handshake — so this is defence in depth. It matters
        // most for a self-signed client, where the registered thumbprint is the whole
        // credential.
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected),
            Encoding.ASCII.GetBytes(presentedThumbprint));
    }

    /// <summary>
    /// CONTRACT.md &#167;10.1 <b>rule 9</b> in full — enforce a token's sender constraint
    /// against <b>every</b> proof the caller presented (contract 1.16).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the complete rule, and the one to use unless your transport genuinely cannot
    /// produce a DPoP thumbprint. The ten cases:
    /// </para>
    /// <code>
    /// token's cnf             certificate     DPoP        result
    /// absent                  anything        anything    true
    /// x5t#S256                equal           ignored     true
    /// x5t#S256                different       ignored     false
    /// x5t#S256                null            ignored     false
    /// jkt                     ignored         equal       true
    /// jkt                     ignored         different   false
    /// jkt                     ignored         null        false
    /// both                    equal           equal       true
    /// both                    wrong/missing   —           false
    /// present, names neither  anything        anything    false
    /// </code>
    /// <para>
    /// Two rows carry the weight. <b>Both named is a conjunction</b>: an operator who turned
    /// on two constraints asked for two, and satisfying the more convenient one is not
    /// compliance. <b>Names neither is a refusal</b>: a confirmation this SDK cannot
    /// interpret is an unverifiable constraint, and reading it as "unconstrained" is the
    /// exact downgrade rule 9 exists to prevent. That includes an <i>empty</i> <c>cnf</c>,
    /// which is also how proto3 delivers an empty <c>CnfClaim</c> over gRPC
    /// (&#167;10.3 rule 3).
    /// </para>
    /// </remarks>
    /// <param name="claims">The verified claims returned by <see cref="VerifyAsync"/>.</param>
    /// <param name="proofs">What the caller proved on this connection and request.</param>
    /// <returns><c>true</c> when the token may be accepted; otherwise <c>false</c>.</returns>
    public static bool VerifyTokenBinding(JsonElement claims, PresentedProofs proofs)
    {
        // The fast path, and the common one. First on purpose: an unbound token is accepted
        // with no proofs at all, which is what keeps existing deployments working when a
        // guard adopts this rule.
        if (!claims.TryGetProperty("cnf", out JsonElement cnf) || cnf.ValueKind == JsonValueKind.Null)
        {
            return SenderConstraintRule.Verify(cnfPresent: false, null, null, proofs);
        }

        if (cnf.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        string? x5tS256 = cnf.TryGetProperty("x5t#S256", out JsonElement certEl) &&
                          certEl.ValueKind == JsonValueKind.String
            ? certEl.GetString()
            : null;
        string? jkt = cnf.TryGetProperty("jkt", out JsonElement jktEl) &&
                     jktEl.ValueKind == JsonValueKind.String
            ? jktEl.GetString()
            : null;

        // §10.3 rule 1 / detail 4: the SAME rule-9 table CONTRACT.md §10.3 requires the
        // gRPC path (Grpc.TokenGrpcClient) to apply — shared here rather than
        // re-derived, so local verification and gRPC validation cannot disagree about
        // whether a token is a bearer token.
        return SenderConstraintRule.Verify(cnfPresent: true, x5tS256, jkt, proofs);
    }

    /// <summary>
    /// Compute the RFC 8705 §3.1 <c>x5t#S256</c> thumbprint of a DER client certificate:
    /// base64url-encoded SHA-256, <b>without</b> padding.
    /// </summary>
    /// <remarks>
    /// Unpadded is not a style choice — RFC 7515 §2 defines base64url in JOSE as omitting
    /// <c>=</c>, and a padded value will not compare equal to what AXIAM put in the token.
    /// A well-formed value is exactly 43 characters.
    /// </remarks>
    /// <param name="der">
    /// The DER encoding of the peer's leaf certificate — under ASP.NET Core,
    /// <c>HttpContext.Connection.ClientCertificate?.RawData</c>.
    /// </param>
    public static string CertificateThumbprintS256(byte[] der)
    {
        byte[] digest = SHA256.HashData(der);
        return Convert.ToBase64String(digest)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
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
    /// Refreshes the JWKS document when the cache is past its TTL OR <paramref name="unknownKid"/>
    /// is not already known — at most once per <see cref="VerifyAsync"/> call (no retry
    /// loop), and for an unknown <c>kid</c> on a fresh cache at most once per
    /// <see cref="UnknownKidRefetchCooldown"/> window. A FAILED refresh (CONTRACT.md &#167;12.4 rule 2,
    /// "Stale-if-error, bounded") leaves the held keys and the anchor untouched and counts toward that
    /// window; the caller then fails closed on a still-unknown <c>kid</c> and <see cref="TryGetHeldKey"/>
    /// stops serving held keys at TTL + <see cref="StaleBound"/>.
    /// </summary>
    /// <remarks>
    /// D-08/D-09, single flight: the fast path below skips everything when the cache is fresh — the common case.
    /// Otherwise, under a short lock that is never held across network I/O, the caller either joins the refresh
    /// already in flight or starts one on a scope detached from itself. A caller whose held key is usable returns at
    /// once; only a caller with no usable key waits (cancellably) for that one fetch. This collapses a concurrent
    /// invalid-<c>kid</c> burst to exactly one fetch.
    /// </remarks>
    private async Task EnsureFreshAsync(string unknownKid, CancellationToken cancellationToken)
    {
        if (IsFresh(unknownKid))
            return;

        // CONTRACT.md §12.4 rule 2 (audit C5): an unknown kid on an otherwise fresh cache is
        // rejected from the cached set, with no network call, while a re-fetch caused by an
        // earlier unknown kid is still inside its cooldown window. The same window bounds a
        // failing endpoint: one attempt per window, not one per token.
        if ((!CacheExpired() && UnknownKidCoolingDown()) || FailedRefreshCoolingDown() || (CacheExpired() && RecentRefresh() && !RefreshInFlight()))
            return; // (a caller with nothing usable still joins a fetch that is under way)

        // A usable held key answers at once and never waits for a fetch (§12.4 rule 2: a transient outage must not
        // stall verification either).
        bool usable = TryGetHeldKey(unknownKid, out _);

        Task refresh;
        lock (_gate)
        {
            if (_inFlight is { IsCompleted: false })
            {
                refresh = _inFlight; // single flight: join the fetch already under way
            }
            else
            {
                if (IsFresh(unknownKid) || FailedRefreshCoolingDown() || (CacheExpired() && RecentRefresh()))
                    return; // a fetch finished while we were deciding
                if (!CacheExpired())
                {
                    if (UnknownKidCoolingDown())
                        return;
                    // The cache is fresh, so this fetch is caused by the unknown kid alone. The window opens here,
                    // from the fetch that is really started: the fetch is detached from the caller, so a caller that
                    // goes away cannot be what opens it.
                    Interlocked.Exchange(ref _lastUnknownKidRefetchTicks, CacheNow().UtcTicks);
                }
                Interlocked.Exchange(ref _lastRefreshStartTicks, CacheNow().UtcTicks);
                refresh = _inFlight = Task.Run(RunRefreshAsync);
            }
        }

        if (usable)
            return;

        // Only a caller with no usable key waits, and it waits cancellably: its own cancellation abandons the wait,
        // never the fetch.
        await refresh.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The fetch, on a scope detached from any caller and bounded by the SDK's own timeout. Never throws.</summary>
    private async Task RunRefreshAsync()
    {
        bool succeeded;
        using var timeout = new CancellationTokenSource(FetchTimeout);
        try
        {
            succeeded = await TryRefreshAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            succeeded = false;
        }

        Interlocked.Exchange(ref _lastFailedRefreshTicks, succeeded ? -1 : CacheNow().UtcTicks);
    }

    private bool RefreshInFlight()
    {
        lock (_gate)
        {
            return _inFlight is { IsCompleted: false };
        }
    }

    /// <summary>Test seam: completes when no refresh is in flight.</summary>
    internal Task IdleAsync()
    {
        Task? t;
        lock (_gate)
        {
            t = _inFlight;
        }
        return t ?? Task.CompletedTask;
    }

    /// <summary>
    /// One refresh. <c>true</c> only for a successful fetch (CONTRACT.md &#167;12.4 rule 2): a <c>200</c> whose body is a
    /// JWKS document with at least one usable key, or a <c>304</c> answering a conditional request. Anything else —
    /// a transport error or timeout, another status, a body that is not a JWKS document, an empty key set — is
    /// <c>false</c> and changes nothing: the held keys and the anchor stay as they were. Runs detached from callers.
    /// </summary>
    private async Task<bool> TryRefreshAsync(CancellationToken cancellationToken)
    {
        try
        {
            bool conditional = _etag is not null && _keysByKid.Count > 0;
            using var request = new HttpRequestMessage(HttpMethod.Get, _jwksUri);
            if (conditional)
            {
                request.Headers.TryAddWithoutValidation("If-None-Match", _etag);
            }

            using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NotModified)
            {
                if (!conditional)
                    return false; // a 304 to a request that was not conditional confirms nothing

                _cacheTtl = EffectiveTtl(response);
                _fetchedAt = CacheNow(); // the 304 re-confirms the held set and moves the anchor
                return true;
            }

            if (response.StatusCode != HttpStatusCode.OK)
                return false;

            // Only a JWKS document is a success: a JSON object whose `keys` array holds at least one JWK object
            // (a JSON object with a string `kty`). `{"keys":[]}`, `{"keys":[{}]}`, `[0]`, `[null]` and a non-JWKS
            // body are failed refreshes. A set of valid JWKs none of which is of this SDK's algorithm is a success
            // per the contract: it is adopted, and verifies nothing.
            byte[] content = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            using JsonDocument parsed = JsonDocument.Parse(content);
            if (parsed.RootElement.ValueKind != JsonValueKind.Object ||
                !parsed.RootElement.TryGetProperty("keys", out JsonElement keysEl) ||
                keysEl.ValueKind != JsonValueKind.Array)
                return false;

            var map = new Dictionary<string, byte[]>();
            int validJwks = 0;
            foreach (JsonElement entry in keysEl.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.Object ||
                    !entry.TryGetProperty("kty", out JsonElement kty) || kty.ValueKind != JsonValueKind.String)
                    continue;
                validJwks++;
                if (kty.GetString() != "OKP" ||
                    !entry.TryGetProperty("crv", out JsonElement crv) || crv.ValueKind != JsonValueKind.String || crv.GetString() != "Ed25519" ||
                    !entry.TryGetProperty("kid", out JsonElement kid) || kid.ValueKind != JsonValueKind.String ||
                    !entry.TryGetProperty("x", out JsonElement x) || x.ValueKind != JsonValueKind.String)
                    continue; // not an EdDSA key (alg is pinned by the caller too) or unusable
                try
                {
                    map[kid.GetString()!] = Base64UrlDecode(x.GetString()!); // raw 32-byte Ed25519 public key
                }
                catch (FormatException)
                {
                    // an unusable key is skipped; it still counted as a JWK
                }
            }

            if (validJwks == 0)
                return false; // no JWK at all: not a JWKS document (the empty set is a failure, not a replacement)

            _keysByKid = map;
            _etag = SafeEtag(response.Headers.ETag?.ToString());
            _cacheTtl = EffectiveTtl(response);
            _fetchedAt = CacheNow();
            return true;
        }
        catch (Exception)
        {
            return false; // transport error, timeout, a body that is not a JWKS document, a bad key
        }
    }

    /// <summary>An ETag worth echoing as <c>If-None-Match</c>: at most 256 bytes, no control character. Anything else
    /// is not stored (the next refresh is unconditional).</summary>
    private static string? SafeEtag(string? etag)
    {
        if (string.IsNullOrEmpty(etag) || etag.Length > 256)
            return null;
        foreach (char c in etag)
        {
            if (c < 0x20 || c == 0x7f || c > 0x7e)
                return null;
        }
        return etag;
    }

    /// <summary>The TTL for a freshly fetched set: the configured one when set; otherwise the advertised
    /// <c>Cache-Control: max-age</c>, clamped to 300 s (&#167;12.4 rule 2), else the 300 s default.</summary>
    private TimeSpan EffectiveTtl(HttpResponseMessage response)
    {
        if (_ttlConfigured)
            return _configuredTtl;
        TimeSpan? advertised = response.Headers.CacheControl?.MaxAge;
        if (advertised is not { } maxAge || maxAge <= TimeSpan.Zero)
            return _configuredTtl;
        return maxAge > MaxCacheTtl ? MaxCacheTtl : maxAge;
    }

    /// <summary>
    /// The held key for <paramref name="kid"/>, or <c>false</c> when the set does not contain it OR the stale bound
    /// has passed: while no refresh has succeeded, held keys verify until exactly TTL + <see cref="StaleBound"/>
    /// after the last successful fetch and not after, whatever the cause and however many attempts failed.
    /// </summary>
    private bool TryGetHeldKey(string kid, out byte[]? rawPublicKey)
    {
        rawPublicKey = null;
        TimeSpan age = CacheNow() - _fetchedAt;
        if (age < TimeSpan.Zero || age > _cacheTtl + StaleBound)
            return false; // past the bound, or the clock stepped backwards: never extend a held key's life
        return _keysByKid.TryGetValue(kid, out rawPublicKey);
    }

    private bool CacheExpired()
    {
        TimeSpan age = CacheNow() - _fetchedAt;
        return age < TimeSpan.Zero || age > _cacheTtl; // a clock that moved backwards: refresh due, never fresh
    }

    /// <summary>Whether a window that began at <paramref name="lastTicks"/> (-1 = never) is still open. A start in the
    /// future (at all) means the wall clock stepped backwards: the window is over, never extended.</summary>
    private bool WithinWindow(long lastTicks)
    {
        if (lastTicks < 0)
            return false;
        long elapsed = CacheNow().UtcTicks - lastTicks;
        return elapsed >= 0 && elapsed < UnknownKidRefetchCooldown.Ticks; // a start in the future: the clock stepped back
    }

    private bool UnknownKidCoolingDown() => WithinWindow(Interlocked.Read(ref _lastUnknownKidRefetchTicks));

    private bool FailedRefreshCoolingDown() => WithinWindow(Interlocked.Read(ref _lastFailedRefreshTicks));

    /// <summary>Any refresh, successful or not, was started inside the window: a TTL-driven refresh waits it out, so an
    /// advertised tiny <c>max-age</c> can never mean one fetch per verification.</summary>
    private bool RecentRefresh() => WithinWindow(Interlocked.Read(ref _lastRefreshStartTicks));

    private bool IsFresh(string kid)
    {
        bool expired = CacheExpired();
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
