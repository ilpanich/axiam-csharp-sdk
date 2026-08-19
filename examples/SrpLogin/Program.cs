using Axiam.Sdk;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Srp;

// The SRP-6a login path (CONTRACT.md §23), using ONLY the SDK's public surface.
//
// SRP proves the password to the server without the password — or anything from which it can
// be cheaply recovered — ever crossing the wire. What the server receives is A and a proof,
// neither of which is useful without the account's verifier, so a TLS-terminating proxy, an
// accidentally verbose request log or a heap dump cannot capture a plaintext password.
//
// It does NOT protect against a compromised AXIAM server. Nothing client-side can.
//
// Three things this example is built to show:
//
//   1. LoginSrpAsync returns the SAME LoginResult as LoginAsync, MFA branch included, so the
//      result handling below is identical to the Quickstart's.
//   2. A tenant with srp_mode: disabled answers the challenge endpoint with 404, which
//      reaches the caller as NetworkError and NOT as a credential failure — so falling back
//      to LoginAsync is correct and safe.
//   3. A tenant with srp_mode: required answers /auth/login with 403 srp_required, which is
//      an AuthzError. A user whose password is perfectly good must never be shown "invalid
//      username or password".
//
// Running this against a live AXIAM server is manual-only; it compiles and documents the
// shape without one.

Uri baseUrl = new(Environment.GetEnvironmentVariable("AXIAM_BASE_URL") ?? "https://localhost:8443");
string tenantId = Environment.GetEnvironmentVariable("AXIAM_TENANT_ID") ?? "acme";
string orgSlug = Environment.GetEnvironmentVariable("AXIAM_ORG_SLUG") ?? "acme";
string username = Environment.GetEnvironmentVariable("AXIAM_USERNAME") ?? "alice";

// A char[] rather than a string so it can be cleared. The SDK clears every copy it makes; it
// cannot clear this one.
char[] password = (Environment.GetEnvironmentVariable("AXIAM_PASSWORD") ?? "hunter2").ToCharArray();

using var client = new AxiamClient(baseUrl, tenantId, new AxiamClientOptions
{
    BaseUrl = baseUrl,
    TenantId = tenantId,
    OrgSlug = orgSlug,
});

try
{
    // On .NET this is always true. It exists because PHP — the one language with no native
    // bignum — genuinely answers false, and §23.1 puts the probe in every SDK's vocabulary so
    // portable code can ask.
    if (!client.SrpAvailable())
    {
        Console.Error.WriteLine("this SDK build cannot perform SRP");
        return;
    }

    LoginResult result;
    try
    {
        result = await client.LoginSrpAsync(username, (char[])password.Clone());
    }
    catch (NetworkError ex)
    {
        // A tenant that has not enabled SRP is not a failed login. Fall back rather than
        // reporting a credential problem the user does not have.
        Console.WriteLine($"SRP unavailable on this tenant ({ex.Message}) — falling back to password login");
        try
        {
            result = await client.LoginAsync(username, new string(password));
        }
        catch (AuthzError denied)
        {
            // srp_mode: required. The credentials were never examined.
            Console.Error.WriteLine($"this tenant refuses password login: {denied.Message}");
            return;
        }
    }

    if (result.MfaRequired)
    {
        // Identical to the non-SRP path — that is the point of §23.1's same-result-type
        // requirement.
        string? code = Environment.GetEnvironmentVariable("AXIAM_TOTP_CODE");
        if (string.IsNullOrEmpty(code))
        {
            Console.Error.WriteLine("MFA required; set AXIAM_TOTP_CODE");
            return;
        }

        result = await client.VerifyMfaAsync(result.ChallengeToken!.Value, code);
    }

    Console.WriteLine("authenticated");

    // Enrolment, for any request that SETS a password. The server cannot compute a verifier —
    // it never sees the plaintext — so it has to arrive with the request or not at all. Read
    // the tenant's parameters from GET /api/v1/auth/me (or the reset context) rather than
    // hard-coding them: the server dictates the costs per exchange, and a verifier enrolled
    // under different costs stays valid.
    string? newPassword = Environment.GetEnvironmentVariable("AXIAM_NEW_PASSWORD");
    if (!string.IsNullOrEmpty(newPassword))
    {
        char[] fresh = newPassword.ToCharArray();
        try
        {
            SrpEnrollment enrolment = client.SrpEnrollment(
                // The account's USERNAME, which is the canonical identity the challenge
                // endpoint hands back. An email here produces a verifier no login can ever
                // satisfy.
                username,
                fresh,
                parameters: new SrpKdfParams(SrpKdfParams.Argon2id, 0));

            // Send enrolment.ToWire() as the `srp` member of the change-password body. Never
            // log it: salt and verifier are §23.3 rule 12 material.
            Console.WriteLine($"enrolment ready: group={enrolment.Group} kdf={enrolment.Kdf}");
        }
        finally
        {
            Array.Clear(fresh);
        }
    }
}
catch (Exception ex) when (ex is AuthError or AuthzError or NetworkError)
{
    // Illustrative: without a reachable server this is the expected path.
    Console.Error.WriteLine($"{ex.GetType().Name}: {ex.Message}");
}
finally
{
    Array.Clear(password);
}
