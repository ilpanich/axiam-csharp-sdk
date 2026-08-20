using System.Security.Cryptography;
using System.Text.Json;
using Axiam.Sdk.Core;
using Axiam.Sdk.Opaque;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// The P/Invoke binding to <c>libaxiam_opaque_ffi</c>.
/// </summary>
/// <remarks>
/// &#167;23.1 forbids this SDK from implementing OPAQUE, so there is no cryptography here to
/// test. What these cover is the part a binding gets wrong: ownership of library-allocated
/// strings, single-use state handles, the key-stretching function the <i>server</i> named being
/// the one used, and an absent library reporting rather than resembling a wrong password.
/// </remarks>
[Trait("Category", "Fast")]
[Collection("Opaque")]
public sealed class OpaqueBindingTests : IDisposable
{
    /// <summary>
    /// Minted per run rather than written down. Nothing here depends on the value — only on the
    /// two differing — and a literal that reads like a credential is a finding for every secret
    /// scanner that looks at this repository, which trains people to wave those findings
    /// through.
    /// </summary>
    private static char[] Password(string label) =>
        (label + "-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8))).ToCharArray();

    private static readonly char[] Correct = Password("correct");
    private static readonly char[] Incorrect = Password("incorrect");

    private const string Ke2 = "ke2-hex";
    private const string RegistrationResponse = "resp-hex";

    private readonly FakeOpaqueNative _lib = new();

    public OpaqueBindingTests() => OpaqueLibrary.SetForTests(_lib);

    public void Dispose()
    {
        OpaqueLibrary.ResetForTests();
        _lib.Dispose();
    }

    private static KsfParams Argon2id() => KsfParams.FromWire(JsonDocument.Parse(
        """{"ksf":"argon2id","memory_kib":19456,"iterations":2,"parallelism":1}""").RootElement);

    private static KsfParams Scrypt() => KsfParams.FromWire(JsonDocument.Parse(
        """{"ksf":"scrypt","log_n":15,"r":8,"p":1}""").RootElement);

    // -----------------------------------------------------------------
    // Availability (§23.2) -- reporting, never throwing
    // -----------------------------------------------------------------

    [Fact]
    public void AvailableIsTrueWhenTheLibraryLoadsAndSaysYes() => Assert.True(OpaqueProtocol.Available());

    [Fact]
    public void ALibraryPresentButBuiltWithoutOpaqueReportsFalse()
    {
        // Present is not the same as usable, and answering from the file's
        // existence would strand a caller at login.
        _lib.AvailableValue = 0;
        Assert.False(OpaqueProtocol.Available());
    }

    [Fact]
    public void AnAbsentLibraryReportsFalseRatherThanThrowing()
    {
        OpaqueLibrary.SetForTests(null);
        Assert.False(OpaqueProtocol.Available());
    }

    [Fact]
    public void AnAbsentLibraryNamesTheArtifactNotThePassword()
    {
        OpaqueLibrary.SetForTests(null);
        NetworkError error = Assert.Throws<NetworkError>(() => OpaqueProtocol.StartLogin(Correct));
        Assert.Contains("libaxiam_opaque_ffi", error.Message, StringComparison.Ordinal);
        Assert.Contains("AXIAM_OPAQUE_LIBRARY", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheRealLoaderReportsAbsentRatherThanThrowingAndMemoizesIt()
    {
        // No libaxiam_opaque_ffi is installed in CI, so this exercises the genuine
        // load failure path -- including that retrying it is not a per-login
        // filesystem walk.
        OpaqueLibrary.ResetForTests();
        Environment.SetEnvironmentVariable(
            OpaqueLibrary.PathEnvironmentVariable, "/nonexistent/libaxiam_opaque_ffi_absent.so");
        try
        {
            Assert.Null(OpaqueLibrary.Load());
            Assert.Null(OpaqueLibrary.Load());
        }
        finally
        {
            Environment.SetEnvironmentVariable(OpaqueLibrary.PathEnvironmentVariable, null);
            OpaqueLibrary.SetForTests(_lib);
        }
    }

    // -----------------------------------------------------------------
    // KsfParams -- absence preserved, bounds enforced (§23.4 rules 2-5)
    // -----------------------------------------------------------------

    [Fact]
    public void FromWirePreservesAbsenceRatherThanDefaultingToZero()
    {
        KsfParams p = Argon2id();
        Assert.Equal("argon2id", p.Ksf);
        Assert.Equal(19456, p.MemoryKib);
        // scrypt's fields do not apply. Reading them as 0 would stretch at the
        // wrong cost and fail against a record that is perfectly good.
        Assert.Null(p.LogN);
        Assert.Null(p.R);
        Assert.Null(p.P);
    }

    [Fact]
    public void ANumericStringIsCoerced()
    {
        KsfParams p = KsfParams.FromWire(JsonDocument.Parse(
            """{"ksf":"scrypt","log_n":"15","r":"8","p":"1"}""").RootElement);
        Assert.Equal(15, p.LogN);
        Assert.Equal(8, p.R);
        Assert.Equal(1, p.P);
    }

    [Fact]
    public void ACostTheNamedFunctionNeedsButTheServerOmittedIsRefused()
    {
        KsfParams p = KsfParams.FromWire(JsonDocument.Parse(
            """{"ksf":"argon2id","iterations":2,"parallelism":1}""").RootElement);
        NetworkError error = Assert.Throws<NetworkError>(() => p.Build(_lib));
        Assert.Contains("without `memory_kib`", error.Message, StringComparison.Ordinal);
        Assert.Equal(0, _lib.KsfAlive);
    }

    [Theory]
    [InlineData("argon2id", "memory_kib", 4096)]
    [InlineData("argon2id", "memory_kib", 2097152)]
    [InlineData("argon2id", "iterations", 0)]
    [InlineData("argon2id", "iterations", 99)]
    [InlineData("argon2id", "parallelism", 64)]
    [InlineData("scrypt", "log_n", 13)]
    [InlineData("scrypt", "log_n", 21)]
    [InlineData("scrypt", "r", 0)]
    [InlineData("scrypt", "p", 17)]
    public void ACostOutsideTheAcceptedBandIsRefusedNamingTheField(string ksf, string field, int value)
    {
        // A server is trusted to name its own policy, not to name a cost that
        // would wedge every device an account owns.
        string baseline = ksf == "argon2id"
            ? "\"ksf\":\"argon2id\",\"memory_kib\":19456,\"iterations\":2,\"parallelism\":1"
            : "\"ksf\":\"scrypt\",\"log_n\":15,\"r\":8,\"p\":1";
        string json = "{" + baseline + ",\"" + field + "\":" + value + "}";
        KsfParams p = KsfParams.FromWire(JsonDocument.Parse(json).RootElement);

        NetworkError error = Assert.Throws<NetworkError>(() => p.Build(_lib));
        Assert.Contains(field, error.Message, StringComparison.Ordinal);
        Assert.Equal(0, _lib.KsfAlive);
    }

    [Theory]
    [InlineData("bcrypt")]
    [InlineData("pbkdf2_sha256")]
    [InlineData("")]
    public void AnUnrecognisedKeyStretchingFunctionIsRefusedNeverSubstituted(string ksf)
    {
        // Substituting produces a well-formed randomized password no AXIAM
        // server agrees with, which surfaces to the user as a wrong password.
        KsfParams p = KsfParams.FromWire(
            JsonDocument.Parse("{\"ksf\":\"" + ksf + "\"}").RootElement);
        Assert.Throws<NetworkError>(() => p.Build(_lib));
        Assert.Equal(0, _lib.KsfAlive);
    }

    [Fact]
    public void ANullKsfHandleReportsTheLibrarysOwnMessage()
    {
        _lib.Fail("ksf_argon2id");
        NetworkError error = Assert.Throws<NetworkError>(() => Argon2id().Build(_lib));
        Assert.Contains("argon2id parameters rejected", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void BothKeyStretchingFunctionsAreReachable()
    {
        foreach (KsfParams p in new[] { Argon2id(), Scrypt() })
        {
            _lib.KsfFree(p.Build(_lib));
        }

        Assert.Equal(0, _lib.KsfAlive);
    }

    // -----------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------

    [Fact]
    public void ARegistrationRoundTripFreesEveryAllocationExactlyOnce()
    {
        using RegistrationExchange exchange = OpaqueProtocol.StartRegistration(Correct);
        Assert.Equal("req:" + new string(Correct), FakeOpaqueNative.Decode(exchange.Request));

        string record = exchange.Finish(Correct, RegistrationResponse, Argon2id());

        Assert.StartsWith(
            $"record:{new string(Correct)}:{RegistrationResponse}:",
            FakeOpaqueNative.Decode(record),
            StringComparison.Ordinal);
        // Two library allocations were handed over -- the request and the record
        // -- and both were released. A binding that leaks here leaks once per
        // enrolment.
        Assert.Equal(2, _lib.Freed.Count);
        Assert.Equal(2, _lib.Freed.Distinct().Count());
        Assert.Equal(0, _lib.AllocationsAlive);
        Assert.Equal(0, _lib.KsfAlive);
        Assert.Equal(0, _lib.StatesAlive);
    }

    [Fact]
    public void AFailedRegistrationStartReportsTheLibrarysMessage()
    {
        _lib.Fail("registration_start");
        NetworkError error = Assert.Throws<NetworkError>(() => OpaqueProtocol.StartRegistration(Correct));
        Assert.Contains("registration could not be started", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AFailedRegistrationFinishStillConsumedTheHandleAndLeaksNothing()
    {
        _lib.Fail("registration_finish");
        using RegistrationExchange exchange = OpaqueProtocol.StartRegistration(Correct);
        NetworkError error = Assert.Throws<NetworkError>(
            () => exchange.Finish(Correct, RegistrationResponse, Argon2id()));
        Assert.Contains("the envelope could not be sealed", error.Message, StringComparison.Ordinal);
        // The library consumes the state whether it succeeds or fails, so the
        // binding must not free it again -- and must not leak the ksf either.
        Assert.Equal(0, _lib.StatesAlive);
        Assert.Equal(0, _lib.KsfAlive);
    }

    // -----------------------------------------------------------------
    // Login
    // -----------------------------------------------------------------

    [Fact]
    public void ALoginRoundTripFreesEveryAllocationExactlyOnce()
    {
        using LoginExchange exchange = OpaqueProtocol.StartLogin(Correct);
        Assert.Equal("ke1:" + new string(Correct), FakeOpaqueNative.Decode(exchange.Ke1));

        string ke3 = exchange.Finish(Correct, Ke2, Scrypt());

        Assert.StartsWith(
            $"ke3:{new string(Correct)}:{Ke2}:",
            FakeOpaqueNative.Decode(ke3),
            StringComparison.Ordinal);
        Assert.Equal(2, _lib.Freed.Count);
        Assert.Equal(0, _lib.AllocationsAlive);
        Assert.Equal(0, _lib.KsfAlive);
        Assert.Equal(0, _lib.StatesAlive);
    }

    [Fact]
    public void AFailedLoginStartReportsTheLibrarysMessage()
    {
        _lib.Fail("login_start");
        NetworkError error = Assert.Throws<NetworkError>(() => OpaqueProtocol.StartLogin(Correct));
        Assert.Contains("login could not be started", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AFailedLoginFinishIsAnAuthErrorBecauseItIsTheCredentialCheck()
    {
        // Both halves of the mutual authentication live here: the envelope only
        // opens under the right password, and KE2's MAC only verifies if the
        // server actually holds the record. AuthError rather than NetworkError is
        // what keeps a misconfigured KSF from being shown as a wrong password.
        _lib.Fail("login_finish");
        using LoginExchange exchange = OpaqueProtocol.StartLogin(Incorrect);
        AuthError error = Assert.Throws<AuthError>(() => exchange.Finish(Incorrect, Ke2, Argon2id()));
        Assert.Contains("invalid credentials", error.Message, StringComparison.Ordinal);
        Assert.Equal(0, _lib.StatesAlive);
        Assert.Equal(0, _lib.KsfAlive);
    }

    [Fact]
    public void ASilentLibraryStillProducesASentence()
    {
        _lib.Fail("login_finish");
        _lib.FailMessage("login_finish", string.Empty);
        using LoginExchange exchange = OpaqueProtocol.StartLogin(Incorrect);
        AuthError error = Assert.Throws<AuthError>(() => exchange.Finish(Incorrect, Ke2, Argon2id()));
        Assert.Contains("the OPAQUE envelope did not open", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnExchangeIsSingleUse()
    {
        using LoginExchange exchange = OpaqueProtocol.StartLogin(Correct);
        exchange.Finish(Correct, Ke2, Argon2id());
        NetworkError error = Assert.Throws<NetworkError>(() => exchange.Finish(Correct, Ke2, Argon2id()));
        Assert.Contains("already been completed", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ARefusedKsfLeavesTheExchangeIntact()
    {
        // The key-stretching handle is built before the state is spent, so a
        // refusal is not a spent exchange. Built the other way round the state
        // would be out of its one-shot slot and unreachable by Dispose() or the
        // finalizer -- a leaked Rust allocation per refused attempt, which is
        // once per login against a misconfigured tenant.
        using RegistrationExchange exchange = OpaqueProtocol.StartRegistration(Correct);
        KsfParams unknown = KsfParams.FromWire(JsonDocument.Parse("""{"ksf":"bcrypt"}""").RootElement);

        Assert.Throws<NetworkError>(() => exchange.Finish(Correct, RegistrationResponse, unknown));

        Assert.Equal(1, _lib.StatesAlive);
        Assert.Equal(0, _lib.KsfAlive);

        // And a caller who fixes the parameters can simply carry on.
        string record = exchange.Finish(Correct, RegistrationResponse, Argon2id());
        Assert.StartsWith("record:", FakeOpaqueNative.Decode(record), StringComparison.Ordinal);
        Assert.Equal(0, _lib.StatesAlive);
    }

    [Fact]
    public void AnOutOfBandCostAlsoLeavesTheExchangeIntact()
    {
        using LoginExchange exchange = OpaqueProtocol.StartLogin(Correct);
        KsfParams tooSmall = KsfParams.FromWire(JsonDocument.Parse(
            """{"ksf":"argon2id","memory_kib":4096,"iterations":2,"parallelism":1}""").RootElement);

        Assert.Throws<NetworkError>(() => exchange.Finish(Correct, Ke2, tooSmall));

        Assert.Equal(1, _lib.StatesAlive);
        // Nothing spent it, so the ordinary release path still works.
        exchange.Dispose();
        Assert.Equal(0, _lib.StatesAlive);
    }

    [Fact]
    public void DisposeReleasesAnExchangeThatWasNeverFinished()
    {
        using (LoginExchange exchange = OpaqueProtocol.StartLogin(Correct))
        {
            Assert.Equal(1, _lib.StatesAlive);
            Assert.NotEmpty(exchange.Ke1);
        }

        Assert.Equal(0, _lib.StatesAlive);
    }

    [Fact]
    public void DisposeAfterAFinishIsANoOpNotADoubleFree()
    {
        using LoginExchange exchange = OpaqueProtocol.StartLogin(Correct);
        exchange.Finish(Correct, Ke2, Argon2id());
        exchange.Dispose();
        Assert.Equal(0, _lib.StatesAlive);
    }

    [Fact]
    public void AnAbandonedRegistrationIsReleasedToo()
    {
        using (RegistrationExchange exchange = OpaqueProtocol.StartRegistration(Correct))
        {
            Assert.Equal(1, _lib.StatesAlive);
            Assert.NotEmpty(exchange.Request);
        }

        Assert.Equal(0, _lib.StatesAlive);
    }

    // -----------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------

    [Fact]
    public void PasswordsCrossTheAbiAsUtf8NotThePlatformCharset()
    {
        // A password that encoded differently under a different platform default
        // would derive a randomized password no AXIAM server agrees with, and
        // would surface as a wrong password on that machine only. The conformance
        // vectors require UTF-8.
        char[] accented = "pàsswörd-ünïcøde-🔐".ToCharArray();
        using LoginExchange exchange = OpaqueProtocol.StartLogin(accented);
        Assert.Equal("ke1:" + new string(accented), FakeOpaqueNative.Decode(exchange.Ke1));
    }

    [Fact]
    public void AnEmptyPasswordIsStillAPassword()
    {
        using LoginExchange exchange = OpaqueProtocol.StartLogin([]);
        Assert.Equal("ke1:", FakeOpaqueNative.Decode(exchange.Ke1));
    }
}

/// <summary>
/// Serialises the OPAQUE tests.
/// </summary>
/// <remarks>
/// <see cref="OpaqueLibrary"/> memoizes one binding per process, so two classes swapping it
/// concurrently would each see the other's fake. xUnit runs classes in parallel by default;
/// this collection is what stops that.
/// </remarks>
[CollectionDefinition("Opaque", DisableParallelization = true)]
public sealed class OpaqueCollection
{
}
