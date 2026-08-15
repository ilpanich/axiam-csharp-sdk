using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Core;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Axiam.Sdk.Auth;

/// <summary>
/// DPoP proof verification — CONTRACT.md &#167;21.7.2 (RFC 9449), contract 1.16.
/// </summary>
/// <remarks>
/// <para>
/// The resource-server half of DPoP: given the <c>DPoP</c> header a caller presented,
/// decide whether it proves possession for <b>this</b> request and <b>this</b> access
/// token, and return the key thumbprint that
/// <see cref="JwksVerifier.VerifyTokenBinding"/> then matches against the token's
/// <c>cnf.jkt</c>.
/// </para>
/// <para>
/// <b>Why this lives in the SDK.</b> &#167;21.7.2 is a ten-check list, and the contract is
/// blunt about partial implementations: <i>"Partial verification is worse than none,
/// because it produces a guard that reports success."</i> Nine of the ten look optional
/// until someone builds an attack out of the one that was skipped, so they belong in one
/// audited place rather than in every application guarding an endpoint.
/// </para>
/// <para>
/// The two most often missing: <c>typ</c> — without pinning it to <c>dpop+jwt</c>, any
/// <i>other</i> JWT signed by the same key (an access token, an ID token) is replayable as
/// a proof; and <c>ath</c> — without it, a proof captured on one request can be re-aimed at
/// a different token held by the same key.
/// </para>
/// <para>
/// <b>The algorithm comes from the key, never from the header.</b> <c>alg: none</c> and
/// RSA-public-key-as-HMAC-secret are the same bug wearing different clothes: <i>the token
/// told the verifier how to check the token</i>. This class dispatches on the embedded
/// key's own <c>kty</c>/<c>crv</c>, so an HMAC path is never reachable no matter what the
/// header says.
/// </para>
/// <para>
/// Ed25519 uses BouncyCastle for the same reason <see cref="JwksVerifier"/> does — .NET
/// still ships no EdDSA. <c>ES256</c> and <c>PS256</c> use the platform's own
/// <see cref="ECDsa"/> and <see cref="RSA"/>.
/// </para>
/// </remarks>
public static class DpopVerifier
{
    /// <summary>
    /// &#167;21.7.2 check 7 — the <c>iat</c> acceptance window, applied in <b>both</b>
    /// directions.
    /// </summary>
    /// <remarks>
    /// RFC 9449 recommends a small window without fixing a number; 60 seconds is the
    /// contract's RECOMMENDED value. A named constant, because a bare <c>60</c> three call
    /// frames deep is a number nobody ever revisits.
    /// </remarks>
    public static readonly TimeSpan IatLeeway = TimeSpan.FromSeconds(60);

    /// <summary>
    /// RFC 9449 &#167;4.3 private key material, which must never appear in a proof's
    /// embedded public <c>jwk</c>. <c>k</c> is the symmetric-key member: its presence means
    /// the "public key" is a shared secret.
    /// </summary>
    private static readonly string[] PrivateJwkMembers =
        ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

    /// <summary>
    /// &#167;21.7.2 check 8 — single-use <c>jti</c> tracking.
    /// </summary>
    /// <remarks>
    /// One method, and its contract is the point: <see cref="Claim"/> must be atomic. A
    /// contains-then-add pair read as two calls is a race that two concurrent replays of
    /// the same proof can both win.
    /// </remarks>
    public interface IJtiStore
    {
        /// <summary>Record <paramref name="jti"/> as used until <paramref name="expiresAt"/>.</summary>
        /// <param name="jti">The proof's <c>jti</c> claim.</param>
        /// <param name="expiresAt">When the entry may be forgotten.</param>
        /// <returns><c>true</c> if this is the first sighting, <c>false</c> if it is a replay.</returns>
        bool Claim(string jti, DateTimeOffset expiresAt);
    }

    /// <summary>
    /// An <see cref="IJtiStore"/> for a single process.
    /// </summary>
    /// <remarks>
    /// <b>Per-process, therefore per-instance.</b> Four replicas behind a load balancer give
    /// an attacker four chances to replay a proof inside its freshness window, and a restart
    /// clears the window entirely. Any deployment running more than one process needs a
    /// shared store (Redis, a database table) behind this same interface.
    /// </remarks>
    public sealed class InMemoryJtiStore : IJtiStore
    {
        private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new();

        /// <summary>Record <paramref name="jti"/> as used until <paramref name="expiresAt"/>.</summary>
        /// <param name="jti">The proof's <c>jti</c> claim.</param>
        /// <param name="expiresAt">When the entry may be forgotten.</param>
        /// <returns><c>true</c> if this is the first sighting, <c>false</c> if it is a replay.</returns>
        public bool Claim(string jti, DateTimeOffset expiresAt)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;

            // Prune inline. Entries only ever live for the freshness window, so this stays
            // small without a background timer.
            if (_seen.Count > 128)
            {
                foreach (KeyValuePair<string, DateTimeOffset> entry in _seen)
                {
                    if (entry.Value <= now)
                    {
                        _seen.TryRemove(entry.Key, out _);
                    }
                }
            }

            // TryAdd is the atomic half that matters: two concurrent replays cannot both
            // observe "absent" and both insert.
            if (_seen.TryAdd(jti, expiresAt))
            {
                return true;
            }

            if (_seen.TryGetValue(jti, out DateTimeOffset existing) && existing > now)
            {
                return false;
            }

            // The recorded entry has expired; take it over.
            return _seen.TryUpdate(jti, expiresAt, existing);
        }
    }

    /// <summary>What <see cref="VerifyProof"/> needs to know about the current request.</summary>
    /// <param name="HttpMethod">The request method, e.g. <c>POST</c>.</param>
    /// <param name="HttpUri">
    /// The full request URI. Query and fragment are stripped during comparison, so passing
    /// it with a query string is expected.
    /// </param>
    /// <param name="AccessToken">
    /// The token from the <c>Authorization</c> header, exactly as it arrived — this is
    /// hashed for the <c>ath</c> check.
    /// </param>
    /// <param name="ExpectedJkt">
    /// The token's <c>cnf.jkt</c>, when the caller has it. Supplying it performs check 10
    /// inside the call; leaving it <c>null</c> means the caller must do that comparison
    /// itself, which <see cref="JwksVerifier.VerifyTokenBinding"/> does.
    /// </param>
    /// <param name="Leeway">The <c>iat</c> window, applied in both directions.</param>
    /// <param name="Now">Override for the current time, for tests.</param>
    public readonly record struct DpopRequest(
        string HttpMethod,
        string HttpUri,
        string AccessToken,
        string? ExpectedJkt = null,
        TimeSpan? Leeway = null,
        DateTimeOffset? Now = null);

    /// <summary>
    /// Verify a DPoP proof against this request — all ten &#167;21.7.2 checks.
    /// </summary>
    /// <remarks>
    /// Returns the proof key's RFC 7638 thumbprint (<c>jkt</c>) on success. Feed it to
    /// <see cref="JwksVerifier.VerifyTokenBinding"/> as the DPoP half of
    /// <see cref="PresentedProofs"/>; returning it rather than <c>true</c> is deliberate, so
    /// the value a guard passes onward could only have come from a proof that actually
    /// verified. There is no "just check the signature" mode, because that is exactly the
    /// partial verification the contract calls worse than none.
    /// </remarks>
    /// <param name="proof">The raw <c>DPoP</c> header value.</param>
    /// <param name="request">The method, URI and access token this proof must match.</param>
    /// <param name="jtiStore">
    /// The replay guard. Required — there is no default, because every default here is
    /// either a silent skip of replay protection or a per-process store masquerading as a
    /// global one.
    /// </param>
    /// <returns>The proof key's <c>jkt</c>.</returns>
    /// <exception cref="AuthError">On any failing check.</exception>
    public static string VerifyProof(string proof, DpopRequest request, IJtiStore jtiStore)
    {
        ArgumentNullException.ThrowIfNull(jtiStore);

        if (string.IsNullOrEmpty(proof))
        {
            throw new AuthError("DPoP proof is missing or empty");
        }

        // RFC 9449 §4.2 makes exactly one proof the rule. Rejecting beats picking the
        // first, which is how a verifier and a downstream parser end up reading different
        // proofs.
        if (proof.Contains(',', StringComparison.Ordinal) ||
            ContainsWhitespace(proof.Trim()))
        {
            throw new AuthError("DPoP header must carry exactly one proof");
        }

        string[] segments = proof.Split('.');
        if (segments.Length != 3)
        {
            throw new AuthError("DPoP proof is not a compact JWS with three segments");
        }

        // The header as RAW JSON. §21.7.2 check 4 insists the private-material check run
        // against this rather than a parsed key type, because many JWK libraries quietly
        // drop d/p/q when parsing into a public key — the check would then pass by virtue
        // of the library having hidden the evidence.
        using JsonDocument headerDoc = ParseJsonSegment(segments[0], "header");
        JsonElement header = headerDoc.RootElement;
        if (header.ValueKind != JsonValueKind.Object)
        {
            throw new AuthError("DPoP proof header is not a JSON object");
        }

        // Check 1 — typ. First, because it is what stops any other JWT signed by the same
        // key from standing in as a proof.
        string typ = header.TryGetProperty("typ", out JsonElement typEl) &&
                     typEl.ValueKind == JsonValueKind.String
            ? typEl.GetString() ?? string.Empty
            : string.Empty;
        if (!string.Equals(typ, "dpop+jwt", StringComparison.OrdinalIgnoreCase))
        {
            throw new AuthError($"DPoP proof typ header must be 'dpop+jwt', got '{typ}'");
        }

        // Check 3 (first half) — the header carries a public jwk.
        if (!header.TryGetProperty("jwk", out JsonElement jwk) ||
            jwk.ValueKind != JsonValueKind.Object)
        {
            throw new AuthError("DPoP proof header must carry a public 'jwk'");
        }

        // Check 4 — no private material, against the raw header JSON.
        foreach (string member in PrivateJwkMembers)
        {
            if (jwk.TryGetProperty(member, out _))
            {
                throw new AuthError(
                    $"DPoP proof jwk carries private key material ({member}) — RFC 9449 §4.3");
            }
        }

        // Checks 2 and 3 (second half) — the algorithm is chosen by the KEY's own type,
        // and the signature must verify under it.
        string signingInput = segments[0] + "." + segments[1];
        byte[] signature = Base64UrlDecode(segments[2], "signature");
        if (!VerifySignature(jwk, Encoding.ASCII.GetBytes(signingInput), signature))
        {
            throw new AuthError("DPoP proof signature is invalid");
        }

        using JsonDocument payloadDoc = ParseJsonSegment(segments[1], "payload");
        JsonElement claims = payloadDoc.RootElement;
        if (claims.ValueKind != JsonValueKind.Object)
        {
            throw new AuthError("DPoP proof payload is not a JSON object");
        }

        // Check 5 — htm.
        string? htm = GetString(claims, "htm");
        if (!string.Equals(htm, request.HttpMethod, StringComparison.Ordinal))
        {
            throw new AuthError(
                $"DPoP proof htm '{htm}' does not match request method '{request.HttpMethod}'");
        }

        // Check 6 — htu, with query and fragment stripped from BOTH sides and nothing else
        // touched.
        string? htu = GetString(claims, "htu");
        string expectedHtu = CanonicalHtu(request.HttpUri);
        if (htu is null || !string.Equals(CanonicalHtu(htu), expectedHtu, StringComparison.Ordinal))
        {
            throw new AuthError(
                $"DPoP proof htu '{htu}' does not match request URI '{expectedHtu}'");
        }

        // Check 7 — iat freshness, in both directions. A proof from the future is as
        // suspect as a stale one: it is how a one-sided skew allowance becomes a long-lived
        // proof.
        if (!claims.TryGetProperty("iat", out JsonElement iatEl) ||
            iatEl.ValueKind != JsonValueKind.Number ||
            !iatEl.TryGetInt64(out long iatUnix))
        {
            throw new AuthError("DPoP proof iat must be a number");
        }

        DateTimeOffset iat = DateTimeOffset.FromUnixTimeSeconds(iatUnix);
        DateTimeOffset now = request.Now ?? DateTimeOffset.UtcNow;
        TimeSpan leeway = request.Leeway ?? IatLeeway;
        if ((now - iat).Duration() > leeway)
        {
            throw new AuthError(
                $"DPoP proof iat is outside the {leeway.TotalSeconds:F0}s freshness window");
        }

        // Check 9 — ath ties the proof to this specific access token.
        string? ath = GetString(claims, "ath");
        if (string.IsNullOrEmpty(ath))
        {
            throw new AuthError("DPoP proof is missing the ath claim");
        }

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(ath),
                Encoding.ASCII.GetBytes(AccessTokenHash(request.AccessToken))))
        {
            throw new AuthError("DPoP proof ath does not match the presented access token");
        }

        // Check 10 — the thumbprint that ties the proof to the token's cnf.
        string jkt = ThumbprintS256(jwk);
        if (request.ExpectedJkt is not null &&
            !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(jkt),
                Encoding.ASCII.GetBytes(request.ExpectedJkt)))
        {
            throw new AuthError("DPoP proof key does not match the token's cnf.jkt");
        }

        // Check 8 — jti single-use. LAST on purpose: claiming a jti is a mutation, and
        // doing it before the cheap checks would let an attacker burn arbitrary jti values
        // out of the store with proofs that were never going to verify.
        string? jti = GetString(claims, "jti");
        if (string.IsNullOrEmpty(jti))
        {
            throw new AuthError("DPoP proof is missing a non-empty jti");
        }

        if (!jtiStore.Claim(jti, iat + leeway))
        {
            throw new AuthError("DPoP proof jti has already been used (replay)");
        }

        return jkt;
    }

    /// <summary>
    /// &#167;21.7.2 check 2 and check 3 — dispatch on the key's own type, then verify.
    /// </summary>
    /// <remarks>
    /// This method is why the proof header's <c>alg</c> never selects anything: the key's
    /// own type determines how a signature over it can be checked, and that is not a matter
    /// the presenter gets an opinion on. There is no HMAC branch here at all, which is what
    /// defeats the public-key-as-shared-secret forgery.
    /// </remarks>
    /// <param name="jwk">The embedded public key.</param>
    /// <param name="signingInput">The ASCII bytes of <c>header.payload</c>.</param>
    /// <param name="signature">The decoded signature.</param>
    /// <returns><c>true</c> when the signature verifies.</returns>
    /// <exception cref="AuthError">When the key type is outside the three permitted algorithms.</exception>
    private static bool VerifySignature(JsonElement jwk, byte[] signingInput, byte[] signature)
    {
        string? kty = GetString(jwk, "kty");
        string? crv = GetString(jwk, "crv");

        try
        {
            if (kty == "OKP" && crv == "Ed25519")
            {
                byte[] x = Base64UrlDecode(RequireMember(jwk, "x"), "jwk.x");
                var verifier = new Ed25519Signer();
                verifier.Init(false, new Ed25519PublicKeyParameters(x, 0));
                verifier.BlockUpdate(signingInput, 0, signingInput.Length);
                return verifier.VerifySignature(signature);
            }

            if (kty == "EC" && crv == "P-256")
            {
                using var ecdsa = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint
                    {
                        X = Base64UrlDecode(RequireMember(jwk, "x"), "jwk.x"),
                        Y = Base64UrlDecode(RequireMember(jwk, "y"), "jwk.y"),
                    },
                });

                // JWS ES256 signatures are raw r||s, which is IEEE P1363 — NOT the DER
                // encoding VerifyData assumes by default.
                return ecdsa.VerifyData(
                    signingInput, signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }

            if (kty == "RSA")
            {
                using var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = Base64UrlDecode(RequireMember(jwk, "n"), "jwk.n"),
                    Exponent = Base64UrlDecode(RequireMember(jwk, "e"), "jwk.e"),
                });

                // PS256 is RSASSA-PSS, not PKCS#1 v1.5. Using Pkcs1 here would reject every
                // legitimate proof while accepting nothing extra — a silent interop break
                // rather than a security hole, but a break all the same.
                return rsa.VerifyData(
                    signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            }
        }
        catch (AuthError)
        {
            throw;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            throw new AuthError($"DPoP proof jwk is not a usable public key: {ex.Message}");
        }

        throw new AuthError(
            $"DPoP proof key type is not permitted by CONTRACT.md §21.7.2 " +
            $"(kty={kty ?? "<missing>"}, crv={crv ?? "<missing>"}; permitted: ES256, EdDSA, PS256)");
    }

    /// <summary>
    /// Compute the RFC 7638 SHA-256 thumbprint of a JWK — the <c>jkt</c>.
    /// </summary>
    /// <remarks>
    /// Only the members RFC 7638 names for the key type take part, serialised as compact
    /// JSON with lexicographically ordered keys. Members outside that set (<c>kid</c>,
    /// <c>use</c>, <c>alg</c>, <c>x5c</c>) are excluded by the spec, which is what makes the
    /// thumbprint stable across two encodings of the same key.
    /// </remarks>
    /// <param name="jwk">The public key to fingerprint.</param>
    /// <returns>The 43-character base64url thumbprint.</returns>
    /// <exception cref="AuthError">When the key type is unsupported or a member is missing.</exception>
    public static string ThumbprintS256(JsonElement jwk)
    {
        string? kty = GetString(jwk, "kty");

        // Built by hand rather than through a serialiser, so RFC 7638's member set and
        // their ordering are visible where they are required rather than depending on a
        // serialiser's ordering behaviour.
        string canonical = kty switch
        {
            "RSA" => $"{{\"e\":{JsonEncode(RequireMember(jwk, "e"))},\"kty\":\"RSA\"," +
                     $"\"n\":{JsonEncode(RequireMember(jwk, "n"))}}}",
            "EC" => $"{{\"crv\":{JsonEncode(RequireMember(jwk, "crv"))},\"kty\":\"EC\"," +
                    $"\"x\":{JsonEncode(RequireMember(jwk, "x"))}," +
                    $"\"y\":{JsonEncode(RequireMember(jwk, "y"))}}}",
            "OKP" => $"{{\"crv\":{JsonEncode(RequireMember(jwk, "crv"))},\"kty\":\"OKP\"," +
                     $"\"x\":{JsonEncode(RequireMember(jwk, "x"))}}}",
            _ => throw new AuthError($"DPoP proof jwk has an unsupported kty: {kty ?? "<missing>"}"),
        };

        return Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    /// <summary>
    /// Compute the <c>ath</c> claim value for an access token — RFC 9449 &#167;4.2.
    /// </summary>
    /// <remarks>
    /// base64url-unpadded SHA-256 over the token's ASCII bytes, i.e. over the compact JWT
    /// string exactly as it travelled in the <c>Authorization</c> header, not over anything
    /// decoded out of it.
    /// </remarks>
    /// <param name="accessToken">The token as it arrived.</param>
    /// <returns>The 43-character base64url hash.</returns>
    public static string AccessTokenHash(string accessToken)
    {
        ArgumentNullException.ThrowIfNull(accessToken);
        return Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
    }

    /// <summary>
    /// Reduce a URI to its <c>htu</c> comparison form — &#167;21.7.2 check 6.
    /// </summary>
    /// <remarks>
    /// Query and fragment removed, and <b>nothing else</b>. No case folding, no default-port
    /// elision, no percent-decoding, no trailing-slash fixing: a normalising comparison is
    /// precisely where two unequal URIs become equal, and an attacker who finds such a pair
    /// can aim a proof at an endpoint it was never minted for.
    /// </remarks>
    /// <param name="uri">The URI to reduce.</param>
    /// <returns>The same URI without its query string or fragment.</returns>
    public static string CanonicalHtu(string uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        int hash = uri.IndexOf('#', StringComparison.Ordinal);
        string withoutFragment = hash < 0 ? uri : uri[..hash];
        int query = withoutFragment.IndexOf('?', StringComparison.Ordinal);
        return query < 0 ? withoutFragment : withoutFragment[..query];
    }

    /// <summary>Read a required string member out of a JWK.</summary>
    /// <param name="jwk">The key object.</param>
    /// <param name="member">The member name.</param>
    /// <returns>The member's value.</returns>
    /// <exception cref="AuthError">When the member is absent or not a non-empty string.</exception>
    private static string RequireMember(JsonElement jwk, string member)
    {
        string? value = GetString(jwk, member);
        if (string.IsNullOrEmpty(value))
        {
            throw new AuthError($"DPoP proof jwk is missing the required member '{member}'");
        }

        return value;
    }

    /// <summary>Read an optional string property, or <c>null</c>.</summary>
    /// <param name="element">The JSON object.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The string value, or <c>null</c> when absent or of another type.</returns>
    private static string? GetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>Parse a base64url JWS segment as JSON.</summary>
    /// <param name="segment">The base64url segment.</param>
    /// <param name="what">Which segment, for the error message.</param>
    /// <returns>The parsed document.</returns>
    /// <exception cref="AuthError">When the segment is not base64url JSON.</exception>
    private static JsonDocument ParseJsonSegment(string segment, string what)
    {
        byte[] raw = Base64UrlDecode(segment, what);
        try
        {
            return JsonDocument.Parse(raw);
        }
        catch (JsonException)
        {
            throw new AuthError($"DPoP proof {what} is not valid JSON");
        }
    }

    /// <summary>Decode unpadded base64url text.</summary>
    /// <param name="text">The base64url text.</param>
    /// <param name="what">What is being decoded, for the error message.</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="AuthError">When the input is not valid base64url.</exception>
    private static byte[] Base64UrlDecode(string text, string what)
    {
        try
        {
            string padded = text.Replace('-', '+').Replace('_', '/');
            padded = (text.Length % 4) switch
            {
                2 => padded + "==",
                3 => padded + "=",
                0 => padded,
                _ => throw new FormatException("bad base64url length"),
            };
            return Convert.FromBase64String(padded);
        }
        catch (FormatException)
        {
            throw new AuthError($"DPoP proof {what} is not valid base64url");
        }
    }

    /// <summary>Encode bytes as unpadded base64url (RFC 7515 &#167;2).</summary>
    /// <param name="raw">The bytes to encode.</param>
    /// <returns>The unpadded base64url text.</returns>
    private static string Base64UrlEncode(byte[] raw) =>
        Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>JSON-encode a string, so a quote or backslash cannot break the canonical form.</summary>
    /// <param name="value">The string to encode.</param>
    /// <returns>The JSON string literal, quotes included.</returns>
    private static string JsonEncode(string value) => JsonSerializer.Serialize(value);

    /// <summary>Whether the text contains any whitespace character.</summary>
    /// <param name="text">The text to scan.</param>
    /// <returns><c>true</c> when a whitespace character is present.</returns>
    private static bool ContainsWhitespace(string text)
    {
        foreach (char c in text)
        {
            if (char.IsWhiteSpace(c))
            {
                return true;
            }
        }

        return false;
    }
}
