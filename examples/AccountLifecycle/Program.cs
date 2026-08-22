using Axiam.Sdk;
using Axiam.Sdk.Account;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;

// CONTRACT.md §25 — account lifecycle and MFA enrolment: the calls a user makes about
// their own account, none of which is administration.
//
// Four demonstrations:
//   1. Forced enrolment — the third LoginAsync outcome. A tenant that requires MFA meets
//      an account that has none, and the login is neither a success nor a failure.
//   2. Voluntary enrolment — the same two calls from inside an existing session.
//   3. Email verification — unauthenticated, because a user whose address is unverified
//      may have no session at all.
//   4. Password reset — including the §23 detour a tenant with OPAQUE enabled forces, and
//      the enumeration guarantee that makes the first call return nothing useful on
//      purpose.
//
// Running against a live AXIAM server is manual-only.

Uri baseUrl = new(Environment.GetEnvironmentVariable("AXIAM_BASE_URL") ?? "https://localhost:8443");
string tenantSlug = Environment.GetEnvironmentVariable("AXIAM_TENANT") ?? "acme";
Guid tenantId = Guid.TryParse(Environment.GetEnvironmentVariable("AXIAM_TENANT_ID"), out Guid parsed)
    ? parsed
    : Guid.Empty;

var options = new AxiamClientOptions
{
    BaseUrl = baseUrl,
    TenantId = tenantSlug,
    OrgSlug = Environment.GetEnvironmentVariable("AXIAM_ORG_SLUG") ?? "acme",
};

using var client = new AxiamClient(baseUrl, tenantSlug, options);

await LoginWithForcedEnrolmentAsync(client);
await EnrolVoluntarilyAsync(client);
await VerifyAnEmailAddressAsync(client, tenantId);
await ResetAPasswordAsync(client, tenantId);

// ---------------------------------------------------------------------------
// 1. The third login outcome (§25.2 rule 1)
// ---------------------------------------------------------------------------

static async Task LoginWithForcedEnrolmentAsync(AxiamClient client)
{
    Console.WriteLine("== login ==");
    try
    {
        LoginResult result = await client.LoginAsync(
            "alice@example.com", Environment.GetEnvironmentVariable("AXIAM_PASSWORD") ?? "pw");

        if (result.MfaSetupRequired)
        {
            // Not a failure. The tenant requires MFA, this account has none, and the
            // server handed back a setup token to finish with. There is no session yet —
            // the token IS the credential for the next two calls.
            Sensitive<string> setupToken = result.SetupToken!;

            MfaEnrollment enrollment = await client.MfaSetupEnrollAsync(setupToken);
            Console.WriteLine($"  scan this: {enrollment.TotpUri.Expose()}");

            // MfaSetupConfirmAsync completes the LOGIN, not just the enrolment: it adopts
            // credentials exactly as LoginAsync does (§25.2 rule 2), so there is nothing
            // left for the caller to install.
            await client.MfaSetupConfirmAsync(setupToken, PromptForCode());
            Console.WriteLine("  signed in");
        }
        else if (result.MfaRequired)
        {
            // The account already HAS a factor — challenge it, don't enrol.
            await client.VerifyMfaAsync(result.ChallengeToken!, PromptForCode());
            Console.WriteLine("  signed in after an MFA challenge");
        }
        else
        {
            Console.WriteLine("  signed in");
        }
    }
    catch (NetworkError e)
    {
        Console.WriteLine($"  no reachable server: {e.Message}");
    }
}

// ---------------------------------------------------------------------------
// 2. Voluntary enrolment (§25.1)
// ---------------------------------------------------------------------------

static async Task EnrolVoluntarilyAsync(AxiamClient client)
{
    Console.WriteLine("== enrolling TOTP from inside a session ==");
    try
    {
        MfaEnrollment enrollment = await client.MfaEnrollAsync();

        // Both halves are Sensitive, and the second one matters: the otpauth URI CONTAINS
        // the secret (§25.3). Wrapping the bare secret and then printing the URI into a
        // log leaks exactly the same bytes.
        Console.WriteLine($"  secret (redacted in ToString): {enrollment.SecretBase32}");
        RenderQrCode(enrollment.TotpUri.Expose());

        if (await client.MfaConfirmAsync(PromptForCode()))
        {
            Console.WriteLine("  MFA is live on this account");
        }

        // Note what did NOT happen: the §17 decision memo was not cleared. The subject has
        // not changed, and discarding a warm memo on an unrelated profile action costs a
        // round trip on every check that follows (§25.2 rule 3).
    }
    catch (AuthError e)
    {
        Console.WriteLine($"  enrolment needs a session: {e.Message}");
    }
    catch (NetworkError e)
    {
        Console.WriteLine($"  no reachable server: {e.Message}");
    }
}

// ---------------------------------------------------------------------------
// 3. Email verification (§25.1) — no session required
// ---------------------------------------------------------------------------

static async Task VerifyAnEmailAddressAsync(AxiamClient client, Guid tenantId)
{
    Console.WriteLine("== verifying an email address ==");
    try
    {
        // The tenant is a BODY field here. §12.1 rule 2's ?tenant_id= convention is scoped
        // to the /oauth2 endpoints, and this is not one of those.
        await client.VerifyEmailAsync(Sensitive<string>.Wrap(TokenFromTheVerificationMail()), tenantId);
        Console.WriteLine("  verified");
    }
    catch (Exception e) when (e is NetworkError or AuthError or AuthzError)
    {
        Console.WriteLine("  that link has expired — sending another");
        try
        {
            await client.ResendVerificationAsync("alice@example.com", tenantId);
        }
        catch (NetworkError)
        {
            // Nothing reachable; the shape is what this example documents.
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Password reset (§25.4)
// ---------------------------------------------------------------------------

static async Task ResetAPasswordAsync(AxiamClient client, Guid tenantId)
{
    Console.WriteLine("== resetting a password ==");
    try
    {
        // Returns a bare Task, whether or not the address exists, and this SDK exposes no
        // way to tell the two apart. That is not an omission to improve on: a client that
        // surfaced a "no such user" state — even one inferred from timing — would turn the
        // endpoint into the account-enumeration oracle its uniform response exists to
        // prevent.
        await client.RequestPasswordResetAsync(new PasswordResetRequest { Email = "alice@example.com" });
        Console.WriteLine("  if that address has an account, a mail is on its way");

        // Sensitive<T>.Wrap is public precisely for this: the token arrives from the
        // user's mail client as a bare string, and wrapping a value can never leak it —
        // only Expose() can.
        Sensitive<string> token = Sensitive<string>.Wrap(TokenFromTheResetMail());

        // Ask the context BEFORE building anything. On a tenant with §23 enabled the
        // client has to construct an OPAQUE registration record, and building one needs
        // parameters it cannot know before it has a token to ask with. Sending a plaintext
        // password to a tenant in opaque_mode: required is refused, and refused late
        // (§25.4 rule 1).
        PasswordResetContext context = await client.PasswordResetContextAsync(token);

        if (context.Opaque is not null)
        {
            Console.WriteLine($"  this tenant uses OPAQUE: {context.Opaque}");
            // Build the record with the SDK's §23 helpers, then pass it as
            // PasswordResetConfirmation.Opaque.
        }
        else
        {
            await client.ConfirmPasswordResetAsync(new PasswordResetConfirmation
            {
                Token = token,
                NewPassword = Sensitive<string>.Wrap("a new correct horse battery staple"),
                TenantId = tenantId,
            });
            Console.WriteLine("  password changed");
        }
    }
    catch (Exception e) when (e is NetworkError or AuthError or AuthzError)
    {
        // A 404 means unknown, expired OR already-consumed, deliberately without
        // distinguishing them (§25.4 rule 3). Neither does this.
        Console.WriteLine("  that reset link is no longer usable");
    }
}

// ---------------------------------------------------------------------------

static string PromptForCode() => Environment.GetEnvironmentVariable("AXIAM_TOTP_CODE") ?? "123456";

static string TokenFromTheVerificationMail() =>
    Environment.GetEnvironmentVariable("AXIAM_VERIFY_TOKEN") ?? "paste-the-token-from-the-mail";

static string TokenFromTheResetMail() =>
    Environment.GetEnvironmentVariable("AXIAM_RESET_TOKEN") ?? "paste-the-token-from-the-mail";

static void RenderQrCode(string otpauthUri) =>
    Console.WriteLine($"  [QR code for {otpauthUri[..Math.Min(20, otpauthUri.Length)]}...]");
