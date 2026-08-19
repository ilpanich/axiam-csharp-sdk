using System.Net;
using System.Numerics;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Srp;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// <c>LoginSrpAsync</c> end-to-end against a fake server that performs REAL SRP arithmetic
/// (CONTRACT.md &#167;23.7 rules 5, 7 and 8).
/// </summary>
/// <remarks>
/// A fake that echoed canned values would pass whatever the client computed. This one holds a
/// verifier, derives its own <c>S</c> from it and answers with the <c>M2</c> that follows — so
/// a client that gets <c>u</c>, <c>PAD()</c> or the identity wrong fails here rather than in
/// production.
/// </remarks>
[Trait("Category", "Fast")]
public class SrpLoginTests
{
    private static readonly Uri BaseUrl = new("https://axiam.test");
    private const string TenantGuid = "22222222-2222-2222-2222-222222222222";
    private const string Identity = "alice";
    private const string Password = "correct horse battery staple";

    private const string ChallengePath = "/api/v1/auth/srp/challenge";
    private const string VerifyPath = "/api/v1/auth/srp/verify";
    private const string LoginPath = "/api/v1/auth/login";

    private static AxiamClient Client(RoutingHandler handler) =>
        AxiamClient.CreateForTesting(
            BaseUrl,
            TenantGuid,
            new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantGuid },
            handler);

    private static CookieContainer CookiesOf(AxiamClient client)
    {
        FieldInfo field = typeof(AxiamClient)
            .GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        return (CookieContainer)field.GetValue(client)!;
    }

    /// <summary>The server half of one enrolled account, performing real SRP arithmetic.</summary>
    private sealed class FakeSrpServer
    {
        private readonly SrpGroup _group;
        // PBKDF2 at a low iteration count: the KDF's cost is not what these tests measure, and
        // Argon2id at production memory would dominate them.
        private readonly SrpKdfParams _kdf = new(SrpKdfParams.Pbkdf2Sha256, 1000);
        private readonly byte[] _salt = Enumerable.Repeat((byte)0xa3, 32).ToArray();
        private readonly BigInteger _verifier;
        private readonly BigInteger _bPriv = new(Enumerable.Repeat((byte)0x22, 32).ToArray(), isUnsigned: true, isBigEndian: true);

        private BigInteger _bPub;
        private BigInteger _aPub;

        public FakeSrpServer(string groupWireName)
        {
            _group = SrpGroup.FromWire(groupWireName);
            byte[] x = SrpMath.DeriveX(Identity, Password.ToCharArray(), _salt, _kdf);
            _verifier = BigInteger.ModPow(_group.Generator, SrpMath.ToPositive(x) % _group.Modulus, _group.Modulus);
        }

        public bool CorruptServerProof { get; set; }

        public bool MfaRequired { get; set; }

        /// <summary>When set, answered on the first challenge so the client must restart.</summary>
        public string? NamedGroup { get; set; }

        public List<string> Bodies { get; } = [];

        public byte[] Salt => _salt;

        public void Map(RoutingHandler handler)
        {
            handler.Map(ChallengePath, Challenge);
            handler.Map(VerifyPath, Verify);
        }

        private HttpResponseMessage Challenge(HttpRequestMessage request)
        {
            string body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            Bodies.Add(body);
            using JsonDocument doc = JsonDocument.Parse(body);
            Assert.False(doc.RootElement.TryGetProperty("password", out _),
                "the challenge request must not carry a password field");
            _aPub = SrpMath.ToPositive(
                Convert.FromHexString(doc.RootElement.GetProperty("client_public").GetString()!));

            if (NamedGroup is string named && named != _group.WireName)
            {
                // Name a different group and answer in it; the client is expected to restart
                // rather than continue with the A it already sent.
                NamedGroup = null;
                return ChallengeBody(SrpGroup.FromWire(named), BigInteger.One);
            }

            // B = (k*v + g^b) mod N
            _bPub = ((SrpMath.Multiplier(_group) * _verifier)
                + BigInteger.ModPow(_group.Generator, _bPriv, _group.Modulus)) % _group.Modulus;
            return ChallengeBody(_group, _bPub);
        }

        private HttpResponseMessage ChallengeBody(SrpGroup named, BigInteger publicValue)
        {
            var payload = new
            {
                srp_session = "opaque-session-token",
                identity = Identity,
                salt = SrpMath.ToHex(_salt),
                group = named.WireName,
                kdf = _kdf.Kdf,
                iterations = _kdf.Iterations,
                b_pub = SrpMath.ToHex(SrpMath.Pad(publicValue, named.ByteLength)),
            };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"),
            };
        }

        private HttpResponseMessage Verify(HttpRequestMessage request)
        {
            string body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            Bodies.Add(body);
            using JsonDocument doc = JsonDocument.Parse(body);
            Assert.Equal("opaque-session-token", doc.RootElement.GetProperty("srp_session").GetString());

            // S = (A * v^u)^b mod N — the server's own derivation, from the verifier alone.
            BigInteger u = SrpMath.HashToInt(
                SrpMath.Pad(_aPub, _group.ByteLength), SrpMath.Pad(_bPub, _group.ByteLength));
            BigInteger s = BigInteger.ModPow(
                _aPub * BigInteger.ModPow(_verifier, u, _group.Modulus) % _group.Modulus,
                _bPriv,
                _group.Modulus);
            byte[] sessionKey = SrpMath.Hash(SrpMath.Pad(s, _group.ByteLength));
            byte[] m1 = Convert.FromHexString(doc.RootElement.GetProperty("client_proof").GetString()!);
            string proof = SrpMath.ToHex(SrpMath.Hash(SrpMath.Pad(_aPub, _group.ByteLength), m1, sessionKey));
            if (CorruptServerProof)
            {
                proof = new string('0', proof.Length);
            }

            object payload = MfaRequired
                ? new { challenge_token = "mfa-challenge", available_methods = new[] { "totp" }, server_proof = proof }
                : new { session_id = "55555555-5555-5555-5555-555555555555", expires_in = 900, server_proof = proof };

            var response = new HttpResponseMessage(MfaRequired ? HttpStatusCode.Accepted : HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"),
            };
            // Cookies are set exactly as on /auth/login (§23.5) — including on the
            // corrupt-proof path, so the test can assert the client discards them.
            response.Headers.Add("Set-Cookie", "axiam_access=fake-token; Path=/");
            return response;
        }
    }

    // -----------------------------------------------------------------------

    /// <summary>The happy path against real arithmetic on both sides.</summary>
    [Fact]
    public async Task LoginSrpEstablishesASessionAgainstAServerThatOnlyHoldsAVerifier()
    {
        var fake = new FakeSrpServer(SrpGroup.DefaultWireName);
        var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        Assert.True(client.SrpAvailable());
        LoginResult result = await client.LoginSrpAsync(Identity, Password.ToCharArray());

        Assert.False(result.MfaRequired);
        Assert.Equal(2, fake.Bodies.Count);
    }

    /// <summary>
    /// &#167;23.1's hard requirement that both login paths return the same result type: an
    /// application switching a tenant to SRP must not need a second result handler.
    /// </summary>
    [Fact]
    public async Task LoginSrpReturnsTheSameMfaBranchAsLogin()
    {
        var fake = new FakeSrpServer(SrpGroup.DefaultWireName) { MfaRequired = true };
        var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        LoginResult result = await client.LoginSrpAsync(Identity, Password.ToCharArray());

        Assert.True(result.MfaRequired);
        Assert.NotNull(result.ChallengeToken);
        Assert.Equal("mfa-challenge", result.ChallengeToken!.Value.Expose());
    }

    /// <summary>
    /// <c>A</c> is computed before the server has named a group, so a tenant on a narrower
    /// group must work rather than fail — at the cost of one extra round trip.
    /// </summary>
    [Fact]
    public async Task LoginSrpRestartsWhenTheServerNamesAnotherGroup()
    {
        var fake = new FakeSrpServer("rfc5054_2048") { NamedGroup = "rfc5054_2048" };
        var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        LoginResult result = await client.LoginSrpAsync(Identity, Password.ToCharArray());

        Assert.False(result.MfaRequired);
        Assert.Equal(3, fake.Bodies.Count);
    }

    /// <summary>
    /// &#167;23.7 rule 5. The assertion is on the ABSENCE of a session, not merely on a thrown
    /// message: skipping <c>M2</c> keeps the half of SRP that authenticates the client and
    /// throws away the half that authenticates the server.
    /// </summary>
    [Fact]
    public async Task AWrongServerProofYieldsAuthErrorAndNoSession()
    {
        var fake = new FakeSrpServer(SrpGroup.DefaultWireName) { CorruptServerProof = true };
        var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        AuthError error = await Assert.ThrowsAsync<AuthError>(
            () => client.LoginSrpAsync(Identity, Password.ToCharArray()));
        Assert.Contains("verifier", error.Message, StringComparison.Ordinal);

        // The cookies the rogue server set must not survive: an endpoint that cannot prove it
        // holds the verifier is not the server it claims to be.
        CookieCollection cookies = CookiesOf(client).GetCookies(BaseUrl);
        foreach (Cookie cookie in cookies)
        {
            Assert.True(cookie.Expired, $"cookie {cookie.Name} from an unverified server was kept");
        }
    }

    /// <summary>
    /// A 404 is a property of the tenant, so a caller can fall back to <c>LoginAsync</c>
    /// without mistaking it for a bad password.
    /// </summary>
    [Fact]
    public async Task ATenantWithSrpDisabledIsNotACredentialFailure()
    {
        var handler = new RoutingHandler();
        handler.Map(ChallengePath, _ => new HttpResponseMessage(HttpStatusCode.NotFound));
        using AxiamClient client = Client(handler);

        NetworkError error = await Assert.ThrowsAsync<NetworkError>(
            () => client.LoginSrpAsync(Identity, Password.ToCharArray()));
        Assert.Contains("srp_mode", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AWrongPasswordIsAnAuthError()
    {
        var fake = new FakeSrpServer(SrpGroup.DefaultWireName);
        var handler = new RoutingHandler();
        fake.Map(handler);
        handler.Map(VerifyPath, _ => new HttpResponseMessage(HttpStatusCode.Unauthorized)
        {
            Content = new StringContent("""{"error":"authentication_failed"}""", Encoding.UTF8, "application/json"),
        });
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthError>(() => client.LoginSrpAsync(Identity, "wrong".ToCharArray()));
    }

    /// <summary>
    /// &#167;23.7 rule 7 and &#167;23.3 rule 10. A user whose password is perfectly good must
    /// never be shown "invalid username or password" because the tenant moved to
    /// <c>srp_mode: required</c>.
    /// </summary>
    [Fact]
    public async Task SrpRequiredIsAnAuthzErrorRatherThanAnAuthError()
    {
        var handler = new RoutingHandler();
        handler.Map(LoginPath, _ => new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent(
                """{"error":"srp_required","message":"this tenant requires Secure Remote Password"}""",
                Encoding.UTF8,
                "application/json"),
        });
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthzError>(() => client.LoginAsync(Identity, Password));
    }

    /// <summary>
    /// &#167;23.7 rule 8, and the claim the whole feature rests on: the password never crosses
    /// the wire.
    /// </summary>
    [Fact]
    public async Task ThePasswordNeverCrossesTheWire()
    {
        var fake = new FakeSrpServer(SrpGroup.DefaultWireName);
        var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        await client.LoginSrpAsync(Identity, Password.ToCharArray());

        Assert.NotEmpty(fake.Bodies);
        foreach (string body in fake.Bodies)
        {
            Assert.DoesNotContain(Password, body, StringComparison.Ordinal);
        }
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 11 — enrolment through the client API
    // -----------------------------------------------------------------------

    [Fact]
    public void SrpEnrollmentProducesAVerifierReproducibleFromItsOwnSalt()
    {
        using AxiamClient client = Client(new RoutingHandler());
        var parameters = new SrpKdfParams(SrpKdfParams.Pbkdf2Sha256, 1000);

        SrpEnrollment first = client.SrpEnrollment(Identity, Password.ToCharArray(), parameters: parameters);

        Assert.Equal(SrpGroup.DefaultWireName, first.Group);
        Assert.Equal(64, first.Salt.Length);
        Assert.Equal(0, first.MemoryKib);
        Assert.Equal(0, first.Parallelism);

        byte[] x = SrpMath.DeriveX(Identity, Password.ToCharArray(), Convert.FromHexString(first.Salt), parameters);
        Assert.Equal(first.Verifier, SrpMath.ComputeVerifier(SrpGroup.FromWire(first.Group), x));

        // A reused salt would make every verifier in a tenant equally attackable with one
        // precomputation.
        SrpEnrollment second = client.SrpEnrollment(Identity, Password.ToCharArray(), parameters: parameters);
        Assert.NotEqual(first.Salt, second.Salt);

        // The wire shape is exactly what §23.5 defines: no argon2 keys on a pbkdf2 enrolment.
        Assert.Equal(
            new[] { "group", "kdf", "iterations", "salt", "verifier" },
            first.ToWire().Keys.ToArray());

        // ...and both cost keys are present on an argon2id one.
        SrpEnrollment argon = client.SrpEnrollment(
            Identity,
            Password.ToCharArray(),
            SrpGroup.FromWire("rfc5054_2048"),
            new SrpKdfParams(SrpKdfParams.Argon2id, 1, 8192, 1));
        Assert.Equal("rfc5054_2048", argon.Group);
        Assert.Equal(8192, argon.ToWire()["memory_kib"]);
        Assert.Equal(1, argon.ToWire()["parallelism"]);
    }

    [Fact]
    public void SrpEnrollmentRefusesAKdfThisSdkDoesNotImplement()
    {
        using AxiamClient client = Client(new RoutingHandler());
        Assert.Throws<NetworkError>(() => client.SrpEnrollment(
            Identity, Password.ToCharArray(), parameters: new SrpKdfParams("scrypt", 1)));
    }
}
