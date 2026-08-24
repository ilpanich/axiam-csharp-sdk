using Axiam.Sdk;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Opaque;
using Axiam.Sdk.Options;

// The OPAQUE (RFC 9807) login path (CONTRACT.md §23), using ONLY the SDK's public surface.
//
// OPAQUE proves the password to the server without the password — or anything from which it
// can be cheaply recovered — ever crossing the wire. What the server receives is a blinded
// group element and a MAC, neither useful without the account's registration record AND the
// tenant's OPRF seed. So a TLS-terminating proxy, an accidentally verbose request log or a
// heap dump cannot capture a plaintext password, and a stolen record database is not
// offline-crackable on its own — the pre-computation resistance the SRP-6a this replaces
// could not offer.
//
// It does NOT protect against a compromised AXIAM server. Nothing client-side can.
//
// Four things this example is built to show:
//
//   1. OpaqueAvailable() is asked FIRST, and genuinely answers false when it should: the
//      protocol comes from libaxiam_opaque_ffi, a per-platform release asset rather than a
//      NuGet package.
//   2. LoginOpaqueAsync returns the SAME LoginResult as LoginAsync, MFA branch included, so
//      the result handling below is identical to the Quickstart's.
//   3. A tenant with opaque_mode: disabled answers the start endpoint with 404, which reaches
//      the caller as NetworkError and NOT as a credential failure — so falling back to
//      LoginAsync is correct and safe. An AuthError is the opposite case and must NOT be
//      retried that way: under opaque_mode: optional the SDK has already done the one retry
//      §23.4 rule 7 allows, and under required there is nothing to retry into.
//   4. A tenant with opaque_mode: required answers /auth/login with 403, which is an
//      AuthzError. A user whose password is perfectly good must never be shown "invalid
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
char[] password = (Environment.GetEnvironmentVariable("AXIAM_PASSWORD") ?? string.Empty).ToCharArray();

using var client = new AxiamClient(baseUrl, tenantId, new AxiamClientOptions
{
    BaseUrl = baseUrl,
    TenantId = tenantId,
    OrgSlug = orgSlug,
});

try
{
    LoginResult result;

    // Ask up front rather than discovering the gap mid-exchange. Unlike the SrpAvailable()
    // this replaces — hard-coded true on .NET — this can really be false.
    if (!client.OpaqueAvailable())
    {
        Console.WriteLine("libaxiam_opaque_ffi is not installed — using password login");
        result = await client.LoginAsync(username, new string(password));
    }
    else
    {
        try
        {
            // OPAQUE first, password second. The reverse order would mean a tenant running
            // opaque_mode: optional never sees a single OPAQUE login — which is the mode
            // operators run for the whole of a migration.
            result = await client.LoginOpaqueAsync(username, (char[])password.Clone());
        }
        catch (NetworkError ex) when (ex.Message.Contains("opaque_mode is disabled", StringComparison.Ordinal))
        {
            // A tenant that has not enabled OPAQUE is not a failed login. Fall back rather
            // than reporting a credential problem the user does not have. Any OTHER
            // NetworkError — a key-stretching function this build cannot perform, a cost
            // outside the accepted band — is a configuration problem: falling back would hide
            // it, and the plaintext would go to the server anyway, so it propagates.
            Console.WriteLine($"OPAQUE unavailable on this tenant ({ex.Message}) — falling back");
            try
            {
                result = await client.LoginAsync(username, new string(password));
            }
            catch (AuthzError denied)
            {
                // opaque_mode: required. The credentials were never examined.
                Console.Error.WriteLine($"this tenant refuses password login: {denied.Message}");
                return;
            }
        }
        catch (AuthError ex)
        {
            // This covers BOTH halves of the mutual authentication: the envelope only opens
            // under the right password, and KE2's MAC only verifies if the server actually
            // holds the record. Reaching here means the tenant is opaque_mode: required (or
            // is a server older than contract 1.29, which sends no `mode` at all): under
            // optional the SDK has ALREADY retried over LoginAsync for you and this is that
            // call's verdict. Either way, do not retry over LoginAsync yourself — that hands
            // the plaintext to an endpoint that just failed to prove it holds the record, and
            // required refuses it with 403 anyway (§23.4 rule 7).
            Console.Error.WriteLine($"login failed: {ex.Message}");
            Console.Error.WriteLine("Not retrying with a password.");
            return;
        }
    }

    if (result.MfaRequired)
    {
        // Identical to the non-OPAQUE path — that is the point of the same-result-type
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

    // Enrolment, for any request that SETS a password. The server cannot build a registration
    // record — it never sees the plaintext — so it has to arrive with the request or not at
    // all.
    //
    // Note what is NOT passed. No identity: a record binds to a credential identifier the
    // server chooses, so unlike the SRP verifier this replaces there is no username/email
    // confusion that can produce a credential no login will ever satisfy. And no group or
    // KDF: those come from the register/start response, so a caller cannot pick a cost the
    // server will not honour.
    string? newPassword = Environment.GetEnvironmentVariable("AXIAM_NEW_PASSWORD");
    if (!string.IsNullOrEmpty(newPassword))
    {
        char[] fresh = newPassword.ToCharArray();
        try
        {
            OpaqueEnrollment enrolment = await client.OpaqueEnrollmentAsync(fresh);

            // Send enrolment.ToWire() as the `opaque` member of the change-password body.
            // Never log the record itself.
            Console.WriteLine($"enrolment ready for session {enrolment.OpaqueSession}");
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
