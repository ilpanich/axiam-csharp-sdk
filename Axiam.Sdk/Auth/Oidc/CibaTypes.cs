using System.Security.Cryptography;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Axiam.Sdk.Auth.Oidc;

// ---------------------------------------------------------------------------
// §33 CIBA — client-initiated backchannel authentication (contract 1.58)
// ---------------------------------------------------------------------------

/// <summary>
/// Whom to authenticate: <b>exactly one</b> hint (CONTRACT.md &#167;33.2). Built only through
/// <see cref="LoginHint"/> or <see cref="IdTokenHint"/>, so sending both, or neither, cannot be
/// written. <c>login_hint_token</c> is not offered (&#167;33.3 rule 3).
/// </summary>
public sealed record CibaUserHint
{
    private CibaUserHint(string member, string value)
    {
        Member = member;
        Value = value;
    }

    /// <summary>The form member this hint is sent as: <c>login_hint</c> or <c>id_token_hint</c>.</summary>
    public string Member { get; }

    /// <summary>The hint itself. Personal data: the SDK never logs it.</summary>
    public string Value { get; }

    /// <summary>A username, then an e-mail address, within the tenant (at most 256 bytes).</summary>
    /// <param name="username">The user's username or e-mail address.</param>
    /// <returns>The hint.</returns>
    public static CibaUserHint LoginHint(string username) =>
        new("login_hint", username ?? throw new ArgumentNullException(nameof(username)));

    /// <summary>An ID token this deployment issued to this client.</summary>
    /// <param name="idToken">The ID token.</param>
    /// <returns>The hint.</returns>
    public static CibaUserHint IdTokenHint(string idToken) =>
        new("id_token_hint", idToken ?? throw new ArgumentNullException(nameof(idToken)));
}

/// <summary>How the client receives the outcome, as it registered (&#167;33: poll or ping; no push).</summary>
public sealed record CibaDelivery
{
    private CibaDelivery(Sensitive<string>? token) => ClientNotificationToken = token;

    /// <summary>The client polls the token endpoint (<see cref="AxiamClient.CibaAwaitAsync"/>).</summary>
    public static CibaDelivery Poll { get; } = new((Sensitive<string>?)null);

    /// <summary>
    /// AXIAM pings the client's registered notification endpoint presenting
    /// <paramref name="clientNotificationToken"/> as a bearer; the client then polls once.
    /// Keep the token to check the ping with <see cref="AxiamClient.CibaHandlePing(IEnumerable{KeyValuePair{string, string}}, string, Sensitive{string})"/>.
    /// </summary>
    /// <param name="clientNotificationToken">1 – 1 024 visible ASCII characters (22 or more for a <c>fapi2</c> client).</param>
    /// <returns>Ping delivery.</returns>
    public static CibaDelivery Ping(Sensitive<string> clientNotificationToken) => new(clientNotificationToken);

    /// <summary>The ping bearer, or <c>null</c> in poll mode.</summary>
    public Sensitive<string>? ClientNotificationToken { get; }

    /// <summary>Whether this is ping mode.</summary>
    public bool IsPing => ClientNotificationToken is not null;
}

/// <summary>The algorithms a signed CIBA request may use (&#167;33.2).</summary>
public enum CibaSigningAlg
{
    /// <summary>RSASSA-PSS with SHA-256 (an RSA key of 2048 bits or more).</summary>
    PS256,

    /// <summary>ECDSA on P-256 with SHA-256.</summary>
    ES256,

    /// <summary>Ed25519.</summary>
    EdDSA,
}

/// <summary>
/// The key and algorithm for the signed request form (&#167;33.2, CIBA Core &#167;7.1.1). Both
/// are the caller's: there is no default for either, and the SDK signs under exactly the
/// algorithm given — the client's registered
/// <c>backchannel_authentication_request_signing_alg</c>.
/// </summary>
/// <remarks>
/// The key is key material (&#167;33.5): <see cref="ToString"/> names the algorithm and the
/// <c>kid</c>, never the key, and no accessor returns it. A key that cannot sign under the
/// algorithm is refused at construction by signing a probe.
/// </remarks>
public sealed class CibaRequestSigner
{
    private readonly RSA? _rsa;
    private readonly ECDsa? _ec;
    private readonly Ed25519PrivateKeyParameters? _ed;

    private CibaRequestSigner(CibaSigningAlg alg, string? kid, RSA? rsa, ECDsa? ec, Ed25519PrivateKeyParameters? ed)
    {
        Alg = alg;
        Kid = kid;
        _rsa = rsa;
        _ec = ec;
        _ed = ed;
    }

    /// <summary>The algorithm this signer uses — the JWS header <c>alg</c>.</summary>
    public CibaSigningAlg Alg { get; }

    /// <summary>The JWS header <c>kid</c>, or <c>null</c> to send none.</summary>
    public string? Kid { get; }

    /// <summary>
    /// A signer from a PEM private key — PKCS#8 for EdDSA, PKCS#8 or SEC 1 for ES256, PKCS#8 or
    /// PKCS#1 for PS256 — and the algorithm it signs under.
    /// </summary>
    /// <param name="alg">The registered algorithm.</param>
    /// <param name="privateKeyPem">The private key, PEM.</param>
    /// <param name="kid">The key id to put in the JWS header, if the client's JWKS names one.</param>
    /// <returns>The signer.</returns>
    /// <exception cref="ValidationError">
    /// The PEM is not a private key, or not one that signs under <paramref name="alg"/> —
    /// refused locally, before any request.
    /// </exception>
    public static CibaRequestSigner FromPem(CibaSigningAlg alg, Sensitive<string> privateKeyPem, string? kid = null)
    {
        string pem = privateKeyPem.Reveal() ?? string.Empty;
        CibaRequestSigner signer;
        try
        {
            switch (alg)
            {
                case CibaSigningAlg.PS256:
                    var rsa = RSA.Create();
                    rsa.ImportFromPem(pem);
                    if (rsa.KeySize < 2048)
                    {
                        throw Refuse();
                    }

                    signer = new CibaRequestSigner(alg, kid, rsa, null, null);
                    break;
                case CibaSigningAlg.ES256:
                    var ec = ECDsa.Create();
                    ec.ImportFromPem(pem);
                    if (ec.KeySize != 256)
                    {
                        throw Refuse();
                    }

                    signer = new CibaRequestSigner(alg, kid, null, ec, null);
                    break;
                case CibaSigningAlg.EdDSA:
                    AsymmetricKeyParameter key = PrivateKeyFactory.CreateKey(PemBody(pem));
                    signer = key is Ed25519PrivateKeyParameters ed
                        ? new CibaRequestSigner(alg, kid, null, null, ed)
                        : throw Refuse();
                    break;
                default:
                    throw Refuse();
            }

            // A key that parses is not yet a key for this algorithm: prove it signs.
            _ = signer.Sign("axiam-ciba-probe"u8.ToArray());
        }
        catch (Exception ex) when (ex is not ValidationError)
        {
            throw Refuse();
        }

        return signer;
    }

    private static ValidationError Refuse() => new(
        "CibaInitiateAsync: the signing key is not a private key that signs under the given algorithm (CONTRACT.md §33.2); no request was sent",
        new[] { new FieldError("signing_key", "not a private key for the algorithm") });

    private static byte[] PemBody(string pem)
    {
        const string begin = "-----BEGIN PRIVATE KEY-----";
        const string end = "-----END PRIVATE KEY-----";
        int start = pem.IndexOf(begin, StringComparison.Ordinal);
        int stop = pem.IndexOf(end, StringComparison.Ordinal);
        if (start < 0 || stop < start)
        {
            throw new FormatException("not a PKCS#8 PEM");
        }

        return Convert.FromBase64String(pem[(start + begin.Length)..stop].Replace("\r", string.Empty).Replace("\n", string.Empty).Trim());
    }

    /// <summary>The JWS header <c>alg</c> value.</summary>
    internal string JoseAlg => Alg switch
    {
        CibaSigningAlg.PS256 => "PS256",
        CibaSigningAlg.ES256 => "ES256",
        _ => "EdDSA",
    };

    /// <summary>The JWS signature over <paramref name="input"/>.</summary>
    internal byte[] Sign(byte[] input)
    {
        if (_rsa is not null)
        {
            return _rsa.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }

        if (_ec is not null)
        {
            // IEEE P1363 r||s, the JWS encoding (RFC 7518 §3.4).
            return _ec.SignData(input, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, _ed!);
        signer.BlockUpdate(input, 0, input.Length);
        return signer.GenerateSignature();
    }

    /// <summary>The algorithm and <c>kid</c> — never the key.</summary>
    /// <returns>A rendering safe to log.</returns>
    public override string ToString() => $"CibaRequestSigner {{ Alg = {Alg}, Kid = {Kid ?? "(none)"}, Key = [SENSITIVE] }}";
}

/// <summary>Arguments to <see cref="AxiamClient.CibaInitiateAsync"/> (&#167;33.2 <c>CibaInitiateRequest</c>).</summary>
/// <remarks>
/// Exactly the members set are sent. <c>BindingMessage</c> and the login hint can be personal
/// data: the SDK never logs them. <c>login_hint_token</c>, <c>user_code</c> and
/// <c>request_uri</c> have no member here — AXIAM refuses each (&#167;33.3 rule 3) — and there is
/// no way to add an arbitrary form parameter, so a signed request can carry nothing beside
/// <c>request</c> and the client's authentication.
/// </remarks>
public sealed class CibaInitiateParams
{
    /// <summary>Space-separated; must include <c>openid</c>.</summary>
    public required string Scope { get; init; }

    /// <summary>Whom to authenticate — exactly one hint.</summary>
    public required CibaUserHint Hint { get; init; }

    /// <summary>
    /// Shown to the user on the approval page: what lets them tell the request they started from
    /// one an attacker did. At most 64 printable characters; required for a <c>fapi2</c> client.
    /// </summary>
    public string? BindingMessage { get; init; }

    /// <summary>The requested lifetime, 30 – 600 s (absent: 300). A string on the form, a number in a signed request.</summary>
    public int? RequestedExpiry { get; init; }

    /// <summary>Space-separated authentication context classes the approval must reach.</summary>
    public string? AcrValues { get; init; }

    /// <summary>RFC 8707 resource indicator.</summary>
    public string? Resource { get; init; }

    /// <summary>Poll (the default) or ping, as the client registered.</summary>
    public CibaDelivery Delivery { get; init; } = CibaDelivery.Poll;

    /// <summary>
    /// Set to send the request as one signed JWT (<c>request</c>) — required of a client that
    /// registered a signing algorithm, refused by the server from one that did not.
    /// </summary>
    public CibaRequestSigner? Signer { get; init; }

    /// <summary>Tenant UUID for the <c>tenant_id</c> query parameter.</summary>
    public Guid? TenantId { get; init; }

    /// <summary>A pre-fetched discovery document, or <c>null</c> to fetch one.</summary>
    public OidcConfiguration? Configuration { get; init; }
}

/// <summary>The <c>CibaInitiateResponse</c> (&#167;33.2), plus when it was received.</summary>
/// <param name="AuthReqId">The request's id at the token endpoint — a bearer credential for the grant (&#167;33.5). Never parse or length-check it.</param>
/// <param name="ExpiresIn">The request's lifetime in seconds — authoritative (&#167;33.7 rule 4).</param>
/// <param name="Interval">The minimum seconds between token requests; the response's value, or 5 when it was absent or zero.</param>
/// <param name="ReceivedAt">When the response was received; <see cref="AxiamClient.CibaAwaitAsync"/>'s deadline is this plus <paramref name="ExpiresIn"/>.</param>
public sealed record CibaInitiateResponse(Sensitive<string> AuthReqId, long ExpiresIn, long Interval, DateTimeOffset ReceivedAt);

/// <summary>Arguments to <see cref="AxiamClient.CibaPollAsync"/>.</summary>
/// <param name="AuthReqId">The <c>auth_req_id</c> from <see cref="CibaInitiateResponse"/> or a ping.</param>
/// <param name="TenantId">Tenant UUID for the <c>tenant_id</c> query parameter.</param>
/// <param name="Configuration">A pre-fetched discovery document.</param>
public sealed record CibaPollParams(Sensitive<string> AuthReqId, Guid? TenantId = null, OidcConfiguration? Configuration = null);

/// <summary>
/// The clock <see cref="AxiamClient.CibaAwaitAsync"/> waits on — injectable so its schedule is
/// testable without sleeping (&#167;33.8 tests 6 and 7).
/// </summary>
public interface ICibaClock
{
    /// <summary>The current instant.</summary>
    DateTimeOffset UtcNow { get; }

    /// <summary>Waits <paramref name="duration"/>.</summary>
    /// <param name="duration">How long.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>A task completing when the time has passed.</returns>
    Task SleepAsync(TimeSpan duration, CancellationToken cancellationToken);
}

/// <summary>The real clock: <see cref="TimeProvider.System"/> and <see cref="Task.Delay(TimeSpan, CancellationToken)"/>.</summary>
public sealed class SystemCibaClock : ICibaClock
{
    /// <summary>The one instance.</summary>
    public static SystemCibaClock Instance { get; } = new();

    /// <inheritdoc />
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

    /// <inheritdoc />
    public Task SleepAsync(TimeSpan duration, CancellationToken cancellationToken) => Task.Delay(duration, cancellationToken);
}

/// <summary>Arguments to <see cref="AxiamClient.CibaAwaitAsync"/>.</summary>
/// <param name="TenantId">Tenant UUID for the <c>tenant_id</c> query parameter.</param>
/// <param name="Configuration">A pre-fetched discovery document.</param>
/// <param name="Clock">The clock to wait on; <c>null</c> is <see cref="SystemCibaClock"/>.</param>
public sealed record CibaAwaitParams(Guid? TenantId = null, OidcConfiguration? Configuration = null, ICibaClock? Clock = null);
