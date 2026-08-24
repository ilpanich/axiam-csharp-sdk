using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Opaque;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// <c>LoginOpaqueAsync</c> / <c>OpaqueEnrollmentAsync</c> end to end (CONTRACT.md &#167;23).
/// </summary>
/// <remarks>
/// The protocol is <c>libaxiam_opaque_ffi</c>'s and is covered by
/// <see cref="OpaqueBindingTests"/>. What is tested here is the part the SDK owns: what goes on
/// the wire — and, more importantly, what does <i>not</i> — which failures are
/// <see cref="AuthError"/> and which are <see cref="NetworkError"/>, and that a failed
/// credential check never reaches <c>login/finish</c>.
/// </remarks>
[Trait("Category", "Fast")]
[Collection("Opaque")]
public sealed class OpaqueLoginTests : IDisposable
{
    private static readonly Uri BaseUrl = new("https://axiam.test");
    private const string TenantGuid = "22222222-2222-2222-2222-222222222222";
    private const string User = "alice";

    private const string LoginStartPath = "/api/v1/auth/opaque/login/start";
    private const string LoginFinishPath = "/api/v1/auth/opaque/login/finish";
    private const string RegisterStartPath = "/api/v1/auth/opaque/register/start";
    private const string PasswordLoginPath = "/api/v1/auth/login";

    /// <summary>
    /// The hex KE2 and RegistrationResponse the fake server answers with. Hex because that is
    /// what the wire carries; the binding hands them to the library verbatim and the fake
    /// library echoes them back inside its own payload, which is how these tests see that
    /// nothing was rewritten in between.
    /// </summary>
    private const string WireKe2 = "6b6532";
    private const string WireRegistrationResponse = "726573703a";

    /// <summary>
    /// Minted per run rather than written down: nothing here depends on the value, and a
    /// literal that reads like a credential is a finding for every secret scanner that looks at
    /// this repository.
    /// </summary>
    private static readonly char[] Password =
        ("correct-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8))).ToCharArray();

    private readonly FakeOpaqueNative _lib = new();

    public OpaqueLoginTests() => OpaqueLibrary.SetForTests(_lib);

    public void Dispose()
    {
        OpaqueLibrary.ResetForTests();
        _lib.Dispose();
    }

    private static AxiamClient Client(RoutingHandler handler) =>
        AxiamClient.CreateForTesting(
            BaseUrl,
            TenantGuid,
            new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantGuid },
            handler);

    /// <summary>A server that answers the three OPAQUE endpoints and records what it saw.</summary>
    private sealed class FakeOpaqueServer
    {
        public List<string> LoginStartBodies { get; } = [];

        public List<string> LoginFinishBodies { get; } = [];

        public List<string> RegisterStartBodies { get; } = [];

        /// <summary>Bodies seen at the ordinary password login (&#167;23.4 rule 7 fallback).</summary>
        public List<string> PasswordLoginBodies { get; } = [];

        public HttpStatusCode LoginStartStatus { get; set; } = HttpStatusCode.OK;

        public HttpStatusCode LoginFinishStatus { get; set; } = HttpStatusCode.OK;

        public HttpStatusCode RegisterStartStatus { get; set; } = HttpStatusCode.OK;

        public HttpStatusCode PasswordLoginStatus { get; set; } = HttpStatusCode.OK;

        /// <summary>
        /// The tenant's <c>opaque_mode</c>, echoed as <c>mode</c> by <c>login/start</c>.
        /// <c>null</c> omits the field entirely — a server older than contract 1.29.
        /// </summary>
        public string? Mode { get; set; }

        public bool MfaRequired { get; set; }

        public bool OmitKe2 { get; set; }

        public string Ksf { get; set; } = "argon2id";

        public void Map(RoutingHandler handler)
        {
            handler.Map(LoginStartPath, LoginStart);
            handler.Map(LoginFinishPath, LoginFinish);
            handler.Map(RegisterStartPath, RegisterStart);
            handler.Map(PasswordLoginPath, PasswordLogin);
        }

        private string KsfFields() => Ksf == "scrypt"
            ? "\"ksf\":\"scrypt\",\"log_n\":15,\"r\":8,\"p\":1"
            : "\"ksf\":\"" + Ksf + "\",\"memory_kib\":19456,\"iterations\":2,\"parallelism\":1";

        private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
            new(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };

        private static string Read(HttpRequestMessage request) =>
            request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();

        private HttpResponseMessage LoginStart(HttpRequestMessage request)
        {
            LoginStartBodies.Add(Read(request));
            if (LoginStartStatus != HttpStatusCode.OK)
            {
                return new HttpResponseMessage(LoginStartStatus);
            }

            string ke2 = OmitKe2 ? string.Empty : "\"ke2\":\"" + WireKe2 + "\",";
            string mode = Mode is null ? string.Empty : "\"mode\":\"" + Mode + "\",";
            return Json(
                HttpStatusCode.OK,
                "{\"opaque_session\":\"handle-42\"," + mode + ke2 + KsfFields() + "}");
        }

        /// <summary>
        /// <c>POST /api/v1/auth/login</c> — reached only by &#167;23.4 rule 7's `optional`
        /// fallback. Answers exactly what the password login answers, so the result the caller
        /// sees is indistinguishable from an ordinary <c>LoginAsync</c>.
        /// </summary>
        private HttpResponseMessage PasswordLogin(HttpRequestMessage request)
        {
            PasswordLoginBodies.Add(Read(request));
            if (PasswordLoginStatus != HttpStatusCode.OK)
            {
                return new HttpResponseMessage(PasswordLoginStatus);
            }

            HttpResponseMessage response = Json(
                HttpStatusCode.OK,
                "{\"session_id\":\"66666666-6666-6666-6666-666666666666\",\"expires_in\":900}");
            response.Headers.Add("Set-Cookie", "axiam_access=fallback-token; Path=/");
            return response;
        }

        private HttpResponseMessage LoginFinish(HttpRequestMessage request)
        {
            LoginFinishBodies.Add(Read(request));
            if (LoginFinishStatus != HttpStatusCode.OK)
            {
                return new HttpResponseMessage(LoginFinishStatus);
            }

            if (MfaRequired)
            {
                return Json(
                    HttpStatusCode.Accepted,
                    "{\"challenge_token\":\"mfa-challenge\",\"available_methods\":[\"totp\"]}");
            }

            HttpResponseMessage response = Json(
                HttpStatusCode.OK,
                "{\"session_id\":\"55555555-5555-5555-5555-555555555555\",\"expires_in\":900}");
            response.Headers.Add("Set-Cookie", "axiam_access=fake-token; Path=/");
            return response;
        }

        private HttpResponseMessage RegisterStart(HttpRequestMessage request)
        {
            RegisterStartBodies.Add(Read(request));
            if (RegisterStartStatus != HttpStatusCode.OK)
            {
                return new HttpResponseMessage(RegisterStartStatus);
            }

            return Json(
                HttpStatusCode.OK,
                "{\"opaque_session\":\"reg-handle\",\"registration_response\":\"" +
                WireRegistrationResponse + "\"," + KsfFields() + "}");
        }
    }

    private static JsonElement Parse(string body) => JsonDocument.Parse(body).RootElement;

    private static string? Field(string body, string name) =>
        Parse(body).TryGetProperty(name, out JsonElement value) ? value.GetString() : null;

    // -----------------------------------------------------------------
    // What crosses the wire
    // -----------------------------------------------------------------

    [Fact]
    public async Task LoginStartCarriesKe1AndNoPasswordField()
    {
        var fake = new FakeOpaqueServer();
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        await client.LoginOpaqueAsync(User, (char[])Password.Clone());

        JsonElement body = Parse(fake.LoginStartBodies[0]);
        // The entire point of the exchange. A body that still carried a password
        // would be SRP's failure mode with extra steps.
        Assert.False(body.TryGetProperty("password", out _));
        Assert.Equal(User, body.GetProperty("username_or_email").GetString());
        Assert.Equal(
            "ke1:" + new string(Password),
            FakeOpaqueNative.Decode(body.GetProperty("ke1").GetString()!));
    }

    [Fact]
    public async Task RegisterStartNamesNoAccountAtAll()
    {
        var fake = new FakeOpaqueServer();
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        OpaqueEnrollment enrollment = await client.OpaqueEnrollmentAsync((char[])Password.Clone());

        Assert.Equal("reg-handle", enrollment.OpaqueSession);
        Assert.StartsWith(
            "record:" + new string(Password) + ":" + WireRegistrationResponse + ":",
            FakeOpaqueNative.Decode(enrollment.RegistrationRecord),
            StringComparison.Ordinal);

        JsonElement body = Parse(fake.RegisterStartBodies[0]);
        Assert.False(body.TryGetProperty("password", out _));
        // No username either: a record binds to a credential identifier the
        // server chooses, which is why a later rename cannot invalidate one.
        Assert.False(body.TryGetProperty("username_or_email", out _));
        Assert.Equal(
            "req:" + new string(Password),
            FakeOpaqueNative.Decode(body.GetProperty("registration_request").GetString()!));
    }

    [Fact]
    public async Task LoginFinishEchoesTheSessionHandleTheServerIssued()
    {
        var fake = new FakeOpaqueServer();
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        await client.LoginOpaqueAsync(User, (char[])Password.Clone());

        Assert.Equal("handle-42", Field(fake.LoginFinishBodies[0], "opaque_session"));
        Assert.StartsWith(
            "ke3:" + new string(Password) + ":" + WireKe2 + ":",
            FakeOpaqueNative.Decode(Field(fake.LoginFinishBodies[0], "ke3")!),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheServerNamedKsfIsTheOneUsed()
    {
        // §23.4 rule 2: never local defaults. A credential enrolled under one
        // cost keeps working after a tenant raises its policy, so a client that
        // guessed would fail against a record that is perfectly good.
        var fake = new FakeOpaqueServer { Ksf = "scrypt" };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        await client.LoginOpaqueAsync(User, (char[])Password.Clone());

        // The fake encodes the handle it was given; scrypt handles start 0xb.
        string ke3 = FakeOpaqueNative.Decode(Field(fake.LoginFinishBodies[0], "ke3")!);
        Assert.EndsWith(":" + (0xB0000 + 15 + 8 + 1).ToString("x"), ke3, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------
    // Results
    // -----------------------------------------------------------------

    [Fact]
    public async Task ASuccessfulLoginReturnsWhatLoginReturns()
    {
        var fake = new FakeOpaqueServer();
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        Assert.True(client.OpaqueAvailable());
        LoginResult result = await client.LoginOpaqueAsync(User, (char[])Password.Clone());
        Assert.False(result.MfaRequired);
    }

    [Fact]
    public async Task TheMfaRequiredBranchSurvivesTheOpaquePath()
    {
        // One result handler must serve both login paths, so the second phase has
        // to arrive here exactly as it does from LoginAsync.
        var fake = new FakeOpaqueServer { MfaRequired = true };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        LoginResult result = await client.LoginOpaqueAsync(User, (char[])Password.Clone());
        Assert.True(result.MfaRequired);
        Assert.NotNull(result.ChallengeToken);
    }

    // -----------------------------------------------------------------
    // Failures -- which exception, and why it matters
    // -----------------------------------------------------------------

    [Fact]
    public async Task ADisabledTenantIsANetworkErrorACallerCanFallBackFrom()
    {
        // A 404 is a property of the tenant, not of the credentials. As an
        // AuthError it would be shown as "invalid password" and send a user to
        // reset a working one, while stopping a fallback to LoginAsync.
        var fake = new FakeOpaqueServer { LoginStartStatus = HttpStatusCode.NotFound };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        NetworkError error = await Assert.ThrowsAsync<NetworkError>(
            () => client.LoginOpaqueAsync(User, (char[])Password.Clone()));
        Assert.Contains("opaque_mode is disabled", error.Message, StringComparison.Ordinal);
        Assert.Empty(fake.LoginFinishBodies);
    }

    [Fact]
    public async Task EnrolmentReportsADisabledTenantTheSameWay()
    {
        var fake = new FakeOpaqueServer { RegisterStartStatus = HttpStatusCode.NotFound };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        NetworkError error = await Assert.ThrowsAsync<NetworkError>(
            () => client.OpaqueEnrollmentAsync((char[])Password.Clone()));
        Assert.Contains("opaque_mode is disabled", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A401AtLoginStartIsAnAuthError()
    {
        var fake = new FakeOpaqueServer { LoginStartStatus = HttpStatusCode.Unauthorized };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthError>(
            () => client.LoginOpaqueAsync(User, (char[])Password.Clone()));
    }

    [Fact]
    public async Task AWrongPasswordNeverReachesLoginFinish()
    {
        // §23.4 rule 7. The envelope failing to open IS the authentication check;
        // sending anything afterwards would ask the server to decide something
        // the client has already decided.
        _lib.Fail("login_finish");
        var fake = new FakeOpaqueServer();
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthError>(
            () => client.LoginOpaqueAsync(User, (char[])Password.Clone()));
        Assert.Empty(fake.LoginFinishBodies);
    }

    // -----------------------------------------------------------------
    // §23.4 rule 7 -- what a failed KE2 means depends only on `mode`
    // -----------------------------------------------------------------

    [Fact]
    public async Task OptionalModeRetriesOverThePasswordLoginAndReturnsItsSuccess()
    {
        // Under `optional` an account with no registration record is the ordinary
        // case, not an error: every account has none the moment an operator enables
        // OPAQUE, and acquires one only as it next sets a password. Reporting the
        // failed exchange as final would lock out every user of a tenant
        // mid-migration -- the exact state `optional` exists to serve.
        _lib.Fail("login_finish");
        var fake = new FakeOpaqueServer { Mode = "optional" };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        LoginResult result = await client.LoginOpaqueAsync(User, (char[])Password.Clone());

        Assert.False(result.MfaRequired);
        // The exchange still stopped dead: rule 7 forbids KE3 either way.
        Assert.Empty(fake.LoginFinishBodies);
        Assert.Equal(1, handler.CountFor(PasswordLoginPath));
        JsonElement body = Parse(fake.PasswordLoginBodies[0]);
        Assert.Equal(User, body.GetProperty("username_or_email").GetString());
        Assert.Equal(new string(Password), body.GetProperty("password").GetString());
    }

    [Fact]
    public async Task OptionalModeReportsThePasswordLoginsOwnFailure()
    {
        // The fallback's verdict is the caller's verdict. Credentials that are wrong
        // for both paths are still an AuthError -- just one the server decided.
        _lib.Fail("login_finish");
        var fake = new FakeOpaqueServer
        {
            Mode = "optional",
            PasswordLoginStatus = HttpStatusCode.Unauthorized,
        };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthError>(
            () => client.LoginOpaqueAsync(User, (char[])Password.Clone()));

        Assert.Equal(1, handler.CountFor(PasswordLoginPath));
        Assert.Empty(fake.LoginFinishBodies);
    }

    [Fact]
    public async Task RequiredModeNeverPutsThePlaintextOnTheWire()
    {
        // `required` answers 403 opaque_required for every principal, so a retry
        // would hand a plaintext password to an endpoint that cannot accept it --
        // and to a server that just failed to prove it holds the record.
        _lib.Fail("login_finish");
        var fake = new FakeOpaqueServer { Mode = "required" };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthError>(
            () => client.LoginOpaqueAsync(User, (char[])Password.Clone()));

        Assert.Equal(0, handler.CountFor(PasswordLoginPath));
        Assert.Empty(fake.PasswordLoginBodies);
        Assert.Empty(fake.LoginFinishBodies);
    }

    [Fact]
    public async Task AnAbsentModeIsTreatedExactlyLikeRequired()
    {
        // A server older than contract 1.29 sends no `mode` at all. Fail closed:
        // guessing `optional` would leak a password to a tenant that never offered
        // the fallback.
        _lib.Fail("login_finish");
        var fake = new FakeOpaqueServer { Mode = null };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthError>(
            () => client.LoginOpaqueAsync(User, (char[])Password.Clone()));

        Assert.Equal(0, handler.CountFor(PasswordLoginPath));
        Assert.Empty(fake.LoginFinishBodies);
    }

    [Fact]
    public async Task AnUnrecognisedModeFailsClosed()
    {
        // Anything that is not exactly `optional` is `required`. A value this SDK
        // does not know is not a reason to widen what it will send.
        _lib.Fail("login_finish");
        var fake = new FakeOpaqueServer { Mode = "sometimes" };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthError>(
            () => client.LoginOpaqueAsync(User, (char[])Password.Clone()));

        Assert.Equal(0, handler.CountFor(PasswordLoginPath));
        Assert.Empty(fake.LoginFinishBodies);
    }

    [Fact]
    public async Task OptionalModeDoesNotFallBackFromAConfigurationFailure()
    {
        // An unusable KSF is a NetworkError, not a credential check -- there is no
        // verdict to second-guess, and rule 7's fallback is for AuthError only.
        var fake = new FakeOpaqueServer { Mode = "optional", Ksf = "bcrypt" };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<NetworkError>(
            () => client.LoginOpaqueAsync(User, (char[])Password.Clone()));

        Assert.Equal(0, handler.CountFor(PasswordLoginPath));
        Assert.Empty(fake.LoginFinishBodies);
    }

    [Fact]
    public async Task AnUnsupportedKsfIsAConfigurationErrorNotABadPassword()
    {
        var fake = new FakeOpaqueServer { Ksf = "bcrypt" };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        NetworkError error = await Assert.ThrowsAsync<NetworkError>(
            () => client.LoginOpaqueAsync(User, (char[])Password.Clone()));
        Assert.Contains("bcrypt", error.Message, StringComparison.Ordinal);
        Assert.Empty(fake.LoginFinishBodies);
    }

    [Fact]
    public async Task AStartResponseWithoutKe2IsAMalformedResponse()
    {
        var fake = new FakeOpaqueServer { OmitKe2 = true };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        NetworkError error = await Assert.ThrowsAsync<NetworkError>(
            () => client.LoginOpaqueAsync(User, (char[])Password.Clone()));
        Assert.Contains("no `ke2`", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A5xxAtLoginFinishIsANetworkError()
    {
        var fake = new FakeOpaqueServer { LoginFinishStatus = HttpStatusCode.ServiceUnavailable };
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<NetworkError>(
            () => client.LoginOpaqueAsync(User, (char[])Password.Clone()));
    }

    [Fact]
    public async Task AnAbsentLibraryIsReportedBeforeAnyRequestIsSent()
    {
        OpaqueLibrary.SetForTests(null);
        var fake = new FakeOpaqueServer();
        using var handler = new RoutingHandler();
        fake.Map(handler);
        using AxiamClient client = Client(handler);

        Assert.False(client.OpaqueAvailable());
        NetworkError error = await Assert.ThrowsAsync<NetworkError>(
            () => client.LoginOpaqueAsync(User, (char[])Password.Clone()));
        Assert.Contains("libaxiam_opaque_ffi", error.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Requests);
    }
}
