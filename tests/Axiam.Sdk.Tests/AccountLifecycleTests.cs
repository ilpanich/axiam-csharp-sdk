using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.Account;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;25 — account lifecycle and MFA enrolment.
/// </summary>
/// <remarks>
/// The two assertions worth reading twice are the &#167;25.4 pair:
/// <c>RequestPasswordReset_SaysNothingAboutWhetherTheAccountExists</c> pins the
/// account-enumeration guarantee to the SDK's <i>surface</i> rather than to the server's
/// behaviour, and <c>PasswordResetContext_SendsTheTokenAsAQueryParameter</c> exists because
/// building that URL by concatenation percent-escapes the <c>?</c> into the path — a bug
/// that produces a 404 reading exactly like an expired token.
/// </remarks>
[Trait("Category", "Fast")]
public class AccountLifecycleTests
{
    private static readonly Uri BaseUrl = new("https://axiam.test");
    private const string TenantGuid = "22222222-2222-2222-2222-222222222222";
    private const string OrgSlug = "globex";
    private const string SetupToken = "setup-token-fixture-do-not-log";
    private const string ResetToken = "reset-token-fixture-do-not-log";
    private const string Secret = "JBSWY3DPEHPK3PXP";

    private const string LoginPath = "/api/v1/auth/login";
    private const string MfaEnrollPath = "/api/v1/auth/mfa/enroll";
    private const string MfaConfirmPath = "/api/v1/auth/mfa/confirm";
    private const string MfaSetupEnrollPath = "/api/v1/auth/mfa/setup/enroll";
    private const string MfaSetupConfirmPath = "/api/v1/auth/mfa/setup/confirm";
    private const string VerifyEmailPath = "/api/v1/auth/verify-email";
    private const string ResendVerificationPath = "/api/v1/auth/resend-verification";
    private const string ResendOwnVerificationPath = "/api/v1/users/me/resend-verification";
    private const string ResetPath = "/api/v1/auth/reset";
    private const string ResetContextPath = "/api/v1/auth/reset/context";
    private const string ResetConfirmPath = "/api/v1/auth/reset/confirm";

    private static AxiamClient Client(RoutingHandler handler, AxiamClientOptions? options = null) =>
        AxiamClient.CreateForTesting(
            BaseUrl,
            TenantGuid,
            options ?? new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantGuid, OrgSlug = OrgSlug },
            handler);

    private static HttpResponseMessage EnrollmentResponse() => OidcTestKit.JsonOk($$"""
        {"secret_base32":"{{Secret}}",
         "totp_uri":"otpauth://totp/AXIAM:alice?secret={{Secret}}&issuer=AXIAM"}
        """);

    // -----------------------------------------------------------------------
    // §25.2 rule 1 — login gains a third outcome
    // -----------------------------------------------------------------------

    [Fact]
    public async Task Login_403MfaSetupRequired_IsTheThirdOutcome()
    {
        using var handler = new RoutingHandler();
        handler.Map(LoginPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.Forbidden,
            $$"""{"mfa_setup_required":true,"setup_token":"{{SetupToken}}"}"""));
        using AxiamClient client = Client(handler);

        LoginResult result = await client.LoginAsync("alice@example.com", "pw");

        Assert.True(result.MfaSetupRequired, "a tenant that requires MFA on an account without it is not a failure");
        Assert.False(result.MfaRequired, "the account has no factor to challenge yet");
        Assert.NotNull(result.SetupToken);
        Assert.Equal(SetupToken, result.SetupToken!.Value.Reveal());
        Assert.DoesNotContain(SetupToken, result.SetupToken.ToString());
    }

    [Fact]
    public async Task Login_OrdinaryForbidden_IsStillAFailure()
    {
        using var handler = new RoutingHandler();
        // §25.2 rule 1 keys the third outcome on the error BODY, never on the status
        // alone: a plain 403 must keep throwing, and must keep its §2 authz mapping —
        // including the action the server named.
        handler.Map(LoginPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.Forbidden,
            """{"error":"authorization_denied","message":"tenant suspended","action":"auth:login"}"""));
        using AxiamClient client = Client(handler);

        AuthzError error = await Assert.ThrowsAsync<AuthzError>(() =>
            client.LoginAsync("alice@example.com", "pw"));
        Assert.Equal("auth:login", error.Action);
    }

    [Fact]
    public async Task Login_NonJson403_DoesNotBecomeAParseFailure()
    {
        using var handler = new RoutingHandler();
        handler.Map(LoginPath, _ => new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent("forbidden", Encoding.UTF8, "text/plain"),
        });
        using AxiamClient client = Client(handler);

        // Peeking the body for a setup token must leave the §2 mapping intact.
        await Assert.ThrowsAsync<AuthzError>(() => client.LoginAsync("alice@example.com", "pw"));
    }

    [Fact]
    public void TheThreeOutcomesAreMutuallyExclusive()
    {
        // Additive, so every pre-1.28 construction still compiles and reads false for the
        // new flag.
        var challenge = new LoginResult(true, Sensitive.Of("chal"));
        Assert.True(challenge.MfaRequired);
        Assert.False(challenge.MfaSetupRequired);
        Assert.Null(challenge.SetupToken);
    }

    // -----------------------------------------------------------------------
    // §25.1 — voluntary enrolment
    // -----------------------------------------------------------------------

    [Fact]
    public async Task MfaEnroll_ReturnsTheSecretAndItsUri()
    {
        using var handler = new RoutingHandler();
        handler.Map(MfaEnrollPath, _ => EnrollmentResponse());
        using AxiamClient client = Client(handler);

        MfaEnrollment enrollment = await client.MfaEnrollAsync();

        Assert.Equal(Secret, enrollment.SecretBase32.Reveal());
        Assert.StartsWith("otpauth://totp/", enrollment.TotpUri.Reveal());
        Assert.Equal(1, handler.CountFor(MfaEnrollPath));
    }

    [Fact]
    public async Task BothHalvesOfAnEnrolmentAreSensitive()
    {
        using var handler = new RoutingHandler();
        handler.Map(MfaEnrollPath, _ => EnrollmentResponse());
        using AxiamClient client = Client(handler);

        MfaEnrollment enrollment = await client.MfaEnrollAsync();

        // §25.3: the otpauth URI CONTAINS the secret. Wrapping only the bare secret and
        // printing the URI leaks the same bytes — this is the mistake the rule names.
        Assert.DoesNotContain(Secret, enrollment.SecretBase32.ToString());
        Assert.DoesNotContain(Secret, enrollment.TotpUri.ToString());
        Assert.DoesNotContain(Secret, enrollment.ToString());
    }

    [Fact]
    public async Task MfaConfirm_ReportsWhetherTheFactorIsLive()
    {
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(MfaConfirmPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return OidcTestKit.JsonOk("""{"mfa_enabled":true}""");
        });
        using AxiamClient client = Client(handler);

        Assert.True(await client.MfaConfirmAsync("123456"));
        Assert.Equal("123456", body.GetProperty("totp_code").GetString());
    }

    [Fact]
    public async Task MfaConfirm_WrongCode_IsAnAuthError()
    {
        using var handler = new RoutingHandler();
        handler.Map(MfaConfirmPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.Unauthorized, """{"message":"invalid code"}"""));
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthError>(() => client.MfaConfirmAsync("000000"));
    }

    [Fact]
    public async Task MfaEnroll_DoesNotClearTheDecisionMemo()
    {
        var resource = Guid.Parse("44444444-4444-4444-4444-444444444444");
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/authz/check", _ => OidcTestKit.JsonOk("""{"allowed":true}"""));
        handler.Map(MfaEnrollPath, _ => EnrollmentResponse());

        var options = new AxiamClientOptions
        {
            BaseUrl = BaseUrl,
            TenantId = TenantGuid,
            OrgSlug = OrgSlug,
            DecisionMemoTtl = TimeSpan.FromMinutes(5),
        };
        using AxiamClient client = Client(handler, options);

        await client.Authz.CheckAccessAsync("read", resource);
        await client.MfaEnrollAsync();
        await client.Authz.CheckAccessAsync("read", resource);

        // §25.2 rule 3: the subject has not changed, and discarding a warm memo on an
        // unrelated profile action costs a round trip on every check that follows.
        Assert.Equal(1, handler.CountFor("/api/v1/authz/check"));
    }

    // -----------------------------------------------------------------------
    // §25.1 / §25.2 rule 2 — forced enrolment completes a login
    // -----------------------------------------------------------------------

    [Fact]
    public async Task MfaSetupEnroll_AuthenticatesWithTheSetupTokenAlone()
    {
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(MfaSetupEnrollPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return EnrollmentResponse();
        });
        using AxiamClient client = Client(handler);

        await client.MfaSetupEnrollAsync(Sensitive.Of(SetupToken));

        // There is no session yet — the setup token IS the credential.
        Assert.Equal(SetupToken, body.GetProperty("setup_token").GetString());
    }

    [Fact]
    public async Task MfaSetupConfirm_CompletesTheLogin()
    {
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(MfaSetupConfirmPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return OidcTestKit.JsonOk("{}");
        });
        using AxiamClient client = Client(handler);

        LoginResult result = await client.MfaSetupConfirmAsync(Sensitive.Of(SetupToken), "123456");

        // §25.2 rule 2: this IS the completion of a login, so the credentials it returns
        // are adopted exactly as LoginAsync adopts them.
        Assert.False(result.MfaRequired);
        Assert.False(result.MfaSetupRequired);
        Assert.Equal(SetupToken, body.GetProperty("setup_token").GetString());
        Assert.Equal("123456", body.GetProperty("totp_code").GetString());
    }

    // -----------------------------------------------------------------------
    // §25.1 — email verification
    // -----------------------------------------------------------------------

    [Fact]
    public async Task VerifyEmail_CarriesTheTenantInTheBody()
    {
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(VerifyEmailPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return OidcTestKit.Empty(HttpStatusCode.NoContent);
        });
        using AxiamClient client = Client(handler);

        await client.VerifyEmailAsync(Sensitive.Of("verify-token"), Guid.Parse(TenantGuid));

        // Not ?tenant_id=: §12.1 rule 2's query convention is scoped to the /oauth2
        // endpoints, and this is not one of those.
        Assert.Equal(TenantGuid, body.GetProperty("tenant_id").GetString());
        Assert.Equal("verify-token", body.GetProperty("token").GetString());
    }

    [Fact]
    public async Task ResendVerification_Accepts202()
    {
        using var handler = new RoutingHandler();
        handler.Map(ResendVerificationPath, _ => OidcTestKit.Empty(HttpStatusCode.Accepted));
        using AxiamClient client = Client(handler);

        await client.ResendVerificationAsync("alice@example.com", Guid.Parse(TenantGuid));

        Assert.Equal(1, handler.CountFor(ResendVerificationPath));
    }

    // -----------------------------------------------------------------------
    // §25.7 — the two resends are two operations
    // -----------------------------------------------------------------------

    /// <summary>The authenticated resend carries no address, and hits its own path.</summary>
    /// <remarks>
    /// The body assertion is the one that matters: a signature with no address parameter
    /// proves nothing about what the SDK serializes, and an address on this endpoint
    /// would let an authenticated session mail an arbitrary one.
    /// </remarks>
    [Fact]
    public async Task ResendOwnVerification_SendsNoAddress()
    {
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(ResendOwnVerificationPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return OidcTestKit.JsonOk("""{"sent":true}""");
        });
        using AxiamClient client = Client(handler);

        await client.ResendOwnVerificationAsync();

        Assert.Equal(1, handler.CountFor(ResendOwnVerificationPath));
        Assert.Empty(body.EnumerateObject());
    }

    /// <summary>The two resends are distinct operations against distinct paths.</summary>
    /// <remarks>
    /// An SDK that aliased one to the other would reintroduce the exact defect §25.7
    /// exists to describe, and every other test here would still pass — so this asserts
    /// on the path each one actually reached.
    /// </remarks>
    [Fact]
    public async Task TheTwoResends_ReachDifferentEndpoints()
    {
        using var handler = new RoutingHandler();
        handler.Map(ResendVerificationPath, _ => OidcTestKit.Empty(HttpStatusCode.OK));
        handler.Map(ResendOwnVerificationPath, _ => OidcTestKit.JsonOk("""{"sent":true}"""));
        using AxiamClient client = Client(handler);

        await client.ResendVerificationAsync("alice@example.com", Guid.Parse(TenantGuid));
        await client.ResendOwnVerificationAsync();

        Assert.Equal(1, handler.CountFor(ResendVerificationPath));
        Assert.Equal(1, handler.CountFor(ResendOwnVerificationPath));
    }

    /// <summary>A 409 surfaces, and is not retried through the public endpoint.</summary>
    /// <remarks>
    /// The bug this operation exists to fix was a success return on a request that
    /// achieved nothing, so "throws" is the assertion — and the public endpoint's zero
    /// calls is what rules out the §25.7 rule 2 fallback, which would turn both failures
    /// back into a normal return with an extra round-trip.
    /// </remarks>
    [Fact]
    public async Task ResendOwnVerification_Surfaces409_WithoutFallingBack()
    {
        using var handler = new RoutingHandler();
        handler.Map(ResendVerificationPath, _ => OidcTestKit.Empty(HttpStatusCode.OK));
        handler.Map(ResendOwnVerificationPath, _ => OidcTestKit.Empty(HttpStatusCode.Conflict));
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<AuthzError>(() => client.ResendOwnVerificationAsync());

        Assert.Equal(1, handler.CountFor(ResendOwnVerificationPath));
        Assert.Equal(0, handler.CountFor(ResendVerificationPath));
    }

    /// <summary>A 429 surfaces too, as the §2 mapping of a rate limit.</summary>
    [Fact]
    public async Task ResendOwnVerification_SurfacesTheDailyLimit()
    {
        using var handler = new RoutingHandler();
        handler.Map(ResendVerificationPath, _ => OidcTestKit.Empty(HttpStatusCode.OK));
        handler.Map(ResendOwnVerificationPath, _ => OidcTestKit.Empty(HttpStatusCode.TooManyRequests));
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<NetworkError>(() => client.ResendOwnVerificationAsync());

        Assert.Equal(0, handler.CountFor(ResendVerificationPath));
    }

    // -----------------------------------------------------------------------
    // §5.2 — organization-level principals
    // -----------------------------------------------------------------------

    /// <summary><c>OrganizationLevel</c> is carried through from the login response.</summary>
    /// <remarks>
    /// It is what an application checks <i>before</i> offering a tenant switch: such a
    /// principal changes the tenant it acts on with a header on the next request, and an
    /// ordinary one cannot, so offering the switch to both turns a distinction the server
    /// made into a 403 the user discovers.
    /// <para>
    /// The absent case is the one that matters: a server older than contract 1.31 omits
    /// the field, and <c>false</c> is the safe reading — the client then offers no
    /// cross-tenant action rather than one that would fail.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("""{"id":"u1","organization_level":true}""", true)]
    [InlineData("""{"id":"u1","organization_level":false}""", false)]
    [InlineData("""{"id":"u1"}""", false)]
    public async Task Login_ReportsAnOrganizationLevelPrincipal(string userJson, bool expected)
    {
        using var handler = new RoutingHandler();
        handler.Map(LoginPath, _ => OidcTestKit.JsonOk(
            $$"""{"user":{{userJson}},"session_id":"s1","expires_in":900}"""));
        using AxiamClient client = Client(handler);

        LoginResult result = await client.LoginAsync("alice@example.com", "correct horse");

        Assert.Equal(expected, result.OrganizationLevel);
    }

    [Fact]
    public async Task VerifyEmail_ExpiredToken_IsAnError()
    {
        using var handler = new RoutingHandler();
        handler.Map(VerifyEmailPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.BadRequest, """{"message":"token expired"}"""));
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<NetworkError>(() =>
            client.VerifyEmailAsync(Sensitive.Of("stale"), Guid.Parse(TenantGuid)));
    }

    // -----------------------------------------------------------------------
    // §25.4 — password reset
    // -----------------------------------------------------------------------

    [Fact]
    public async Task RequestPasswordReset_SaysNothingAboutWhetherTheAccountExists()
    {
        using var handler = new RoutingHandler();
        handler.Map(ResetPath, _ => OidcTestKit.Empty(HttpStatusCode.Accepted));
        using AxiamClient client = Client(handler);

        // Both an existing and an unknown address answer 202 with an empty body, and the
        // SDK returns a bare Task — there is no field, no boolean and no exception for a
        // caller to build an enumeration oracle out of.
        await client.RequestPasswordResetAsync(new PasswordResetRequest { Email = "alice@example.com" });
        await client.RequestPasswordResetAsync(new PasswordResetRequest { Email = "nobody@example.com" });

        Assert.Equal(2, handler.CountFor(ResetPath));
    }

    [Fact]
    public async Task RequestPasswordReset_FillsTheWorkspaceFromTheClient()
    {
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(ResetPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return OidcTestKit.Empty(HttpStatusCode.Accepted);
        });
        using AxiamClient client = Client(handler);

        await client.RequestPasswordResetAsync(new PasswordResetRequest { Email = "alice@example.com" });

        Assert.Equal(OrgSlug, body.GetProperty("org_slug").GetString());
        Assert.Equal(TenantGuid, body.GetProperty("tenant_id").GetString());
    }

    [Fact]
    public async Task RequestPasswordReset_ExplicitWorkspaceWins()
    {
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(ResetPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return OidcTestKit.Empty(HttpStatusCode.Accepted);
        });
        using AxiamClient client = Client(handler);

        await client.RequestPasswordResetAsync(new PasswordResetRequest
        {
            Email = "alice@example.com",
            OrgSlug = "other-org",
            TenantSlug = "other-tenant",
        });

        Assert.Equal("other-org", body.GetProperty("org_slug").GetString());
        Assert.Equal("other-tenant", body.GetProperty("tenant_slug").GetString());
        Assert.False(body.TryGetProperty("tenant_id", out _), "a chosen tenant_slug makes tenant_id ambiguous");
    }

    [Fact]
    public async Task PasswordResetContext_SendsTheTokenAsAQueryParameter()
    {
        string? query = null;
        using var handler = new RoutingHandler();
        handler.Map(ResetContextPath, request =>
        {
            query = request.RequestUri!.Query;
            return OidcTestKit.JsonOk("""{"opaque":null}""");
        });
        using AxiamClient client = Client(handler);

        await client.PasswordResetContextAsync(Sensitive.Of(ResetToken));

        // Not percent-escaped into the path, which 404s in a way that reads exactly like
        // an expired token.
        Assert.Equal($"?token={ResetToken}", query);
        Assert.Equal(ResetContextPath, handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal(HttpMethod.Get, handler.Requests[0].Method);
    }

    [Fact]
    public async Task PasswordResetContext_NoOpaque_ReportsNoPolicy()
    {
        using var handler = new RoutingHandler();
        handler.Map(ResetContextPath, _ => OidcTestKit.JsonOk("""{"opaque":null}"""));
        using AxiamClient client = Client(handler);

        PasswordResetContext context = await client.PasswordResetContextAsync(Sensitive.Of(ResetToken));

        Assert.Null(context.Opaque);
    }

    [Fact]
    public async Task PasswordResetContext_WithOpaque_ForwardsTheParametersUntouched()
    {
        const string opaque = """
            {"mode":"required","cipher_suite":"ristretto255-sha512",
             "server_public_key":"c2VydmVyLXBr","vendorSpecific":"must-survive"}
            """;
        using var handler = new RoutingHandler();
        handler.Map(ResetContextPath, _ => OidcTestKit.JsonOk($$"""{"opaque":{{opaque}}}"""));
        using AxiamClient client = Client(handler);

        PasswordResetContext context = await client.PasswordResetContextAsync(Sensitive.Of(ResetToken));

        // Structural equality: the SDK does not model, validate or re-encode the §23
        // parameter block, it forwards it.
        Assert.NotNull(context.Opaque);
        using JsonDocument expected = JsonDocument.Parse(opaque);
        Assert.Equal(
            JsonSerializer.Serialize(expected.RootElement),
            JsonSerializer.Serialize(context.Opaque!.Value));
    }

    [Fact]
    public async Task PasswordResetContext_UnknownExpiredAndConsumed_AllLookAlike()
    {
        using var handler = new RoutingHandler();
        // §25.4 rule 3: the server refuses to distinguish these three, and the SDK must
        // not invent a distinction of its own.
        handler.Map(ResetContextPath, _ => OidcTestKit.JsonStatus(HttpStatusCode.NotFound, "{}"));
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<NetworkError>(() =>
            client.PasswordResetContextAsync(Sensitive.Of(ResetToken)));
    }

    [Fact]
    public async Task ConfirmPasswordReset_PlaintextPath()
    {
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(ResetConfirmPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return OidcTestKit.Empty(HttpStatusCode.NoContent);
        });
        using AxiamClient client = Client(handler);

        await client.ConfirmPasswordResetAsync(new PasswordResetConfirmation
        {
            Token = Sensitive.Of(ResetToken),
            NewPassword = Sensitive.Of("new-password"),
            TenantId = Guid.Parse(TenantGuid),
        });

        Assert.Equal("new-password", body.GetProperty("new_password").GetString());
        Assert.False(body.TryGetProperty("opaque", out _));
    }

    [Fact]
    public async Task ConfirmPasswordReset_ForwardsTheOpaqueRecordVerbatim()
    {
        const string record = """{"registration_record":"cmVjb3Jk","export_key_hint":"aGludA"}""";
        JsonElement body = default;
        using var handler = new RoutingHandler();
        handler.Map(ResetConfirmPath, request =>
        {
            body = OidcTestKit.ReadJsonBody(request);
            return OidcTestKit.Empty(HttpStatusCode.NoContent);
        });
        using AxiamClient client = Client(handler);
        using JsonDocument doc = JsonDocument.Parse(record);

        await client.ConfirmPasswordResetAsync(new PasswordResetConfirmation
        {
            Token = Sensitive.Of(ResetToken),
            NewPassword = Sensitive.Of("unused"),
            TenantId = Guid.Parse(TenantGuid),
            Opaque = doc.RootElement.Clone(),
        });

        Assert.Equal(
            JsonSerializer.Serialize(doc.RootElement),
            JsonSerializer.Serialize(body.GetProperty("opaque")));
    }

    [Fact]
    public async Task ConfirmPasswordReset_RejectedByPolicy_Surfaces()
    {
        using var handler = new RoutingHandler();
        handler.Map(ResetConfirmPath, _ => OidcTestKit.JsonStatus(
            HttpStatusCode.BadRequest, """{"message":"password does not meet policy"}"""));
        using AxiamClient client = Client(handler);

        await Assert.ThrowsAsync<NetworkError>(() => client.ConfirmPasswordResetAsync(
            new PasswordResetConfirmation
            {
                Token = Sensitive.Of(ResetToken),
                NewPassword = Sensitive.Of("x"),
                TenantId = Guid.Parse(TenantGuid),
            }));
    }
}
