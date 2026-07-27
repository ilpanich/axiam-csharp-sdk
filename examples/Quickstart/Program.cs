using Axiam.Sdk;
using Axiam.Sdk.Amqp;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Grpc;
using Axiam.Sdk.Options;

// Quickstart: demonstrates AxiamClient's core capabilities using ONLY the SDK's
// PUBLIC entry points (the Axiam.Sdk surface — no internal/generated
// references): two-phase login+MFA, REST authorization, gRPC authorization,
// OIDC service-account machine-to-machine login (CONTRACT.md §12), and AMQP
// event consumption with HMAC verify-before-handler. Running this against a
// live AXIAM server/broker is manual-only (21-VALIDATION.md) — see README.md.
// Each phase is wrapped so the example still documents the shape and compiles
// cleanly even without a reachable server.

Uri baseUrl = new(Environment.GetEnvironmentVariable("AXIAM_BASE_URL") ?? "https://localhost:8443");
string tenantId = Environment.GetEnvironmentVariable("AXIAM_TENANT_ID") ?? "acme";
string orgSlug = Environment.GetEnvironmentVariable("AXIAM_ORG_SLUG") ?? "acme";

// SC#1: tenantId is a required, positional constructor argument — there is no
// overload or default that omits it. login/refresh additionally require
// organization context — a tenant slug is only unique within an organization —
// so OrgSlug (or OrgId) is supplied via AxiamClientOptions; a login body without
// it is rejected by the server with 400 "must provide org_id or org_slug"
// (CONTRACT.md §5.1). OidcClientId/OidcClientSecret (CONTRACT.md §12.1) are
// this relying party's OAuth2 client credentials, used by the OIDC phase below
// — client_id/client_secret are CLIENT CONFIGURATION here, never a per-call
// argument.
using AxiamClient client = new(baseUrl, tenantId, new AxiamClientOptions
{
    BaseUrl = baseUrl,
    TenantId = tenantId,
    OrgSlug = orgSlug,
    OidcClientId = Environment.GetEnvironmentVariable("AXIAM_OIDC_CLIENT_ID") ?? "quickstart-service-account",
    OidcClientSecret = Environment.GetEnvironmentVariable("AXIAM_OIDC_CLIENT_SECRET"),
});

try
{
    // --- 1. Two-phase login (LoginAsync -> VerifyMfaAsync) -----------------
    LoginResultShim login = await LoginAsync(client);
    Console.WriteLine("Login complete.");

    // --- 2. REST authorization (CheckAccessAsync / CanAsync) ---------------
    Guid documentId = Guid.NewGuid();
    bool canRead = await client.Authz.CanAsync("documents:read", documentId);
    Console.WriteLine($"REST CanAsync(documents:read) => {canRead}");

    // --- 3. gRPC authorization (CheckAccessAsync over Grpc.Net.Client) -----
    using AxiamGrpcAuthzClient grpcAuthz = new(client);
    bool grpcAllowed = await grpcAuthz.CheckAccessAsync("documents:read", documentId.ToString());
    Console.WriteLine($"gRPC CheckAccessAsync(documents:read) => {grpcAllowed}");
}
catch (Exception ex)
{
    Console.WriteLine($"Login/authz phase skipped — no reachable AXIAM server ({ex.Message}). See README.md.");
}

// --- 4. OIDC machine-to-machine login (CONTRACT.md §12) ----------------
// LoginClientCredentialsAsync/IntrospectAsync/RevokeAsync need a UUID
// tenant_id for the /oauth2/* query parameter (§12.3 rule 4); since this
// client was constructed with a SLUG (tenantId above), pass one explicitly
// here (a real app resolves it from its own configuration/service registry).
Guid? oidcTenantId = Guid.TryParse(Environment.GetEnvironmentVariable("AXIAM_TENANT_UUID"), out Guid parsedTenantId)
    ? parsedTenantId
    : null;
try
{
    OidcTokenSet serviceTokens = await client.LoginClientCredentialsAsync(new LoginClientCredentialsParams
    {
        TenantId = oidcTenantId,
    });
    // AccessToken is Sensitive<string> (§12.5) — Expose() is the documented
    // §7-vs-§12 accessor (see Sensitive<T>.Expose's doc comment): §12 delivers
    // tokens directly in the response body, so the caller must be able to read
    // them back out to use/store/revoke them. Never pass the exposed value to a
    // log/Console.WriteLine call.
    string accessToken = serviceTokens.AccessToken.Expose();
    Console.WriteLine($"OIDC client_credentials login succeeded — access_token expires in {serviceTokens.ExpiresIn}s.");

    IntrospectionResult introspection = await client.IntrospectAsync(new IntrospectParams
    {
        Token = serviceTokens.AccessToken,
        TenantId = oidcTenantId,
    });
    Console.WriteLine($"IntrospectAsync => active={introspection.Active}");

    await client.RevokeAsync(new RevokeParams { Token = serviceTokens.AccessToken, TenantId = oidcTenantId });
    Console.WriteLine("RevokeAsync completed (idempotent — succeeds even if the token was already invalid).");
}
catch (AuthError ex)
{
    Console.WriteLine($"OIDC phase skipped — {ex.Message}. Set AXIAM_OIDC_CLIENT_SECRET/AXIAM_TENANT_UUID. See README.md.");
}
catch (Exception ex)
{
    Console.WriteLine($"OIDC phase skipped — no reachable AXIAM server ({ex.Message}). See README.md.");
}

// --- 5. AMQP event consumption (AsyncEventingBasicConsumer + HMAC verify) --
await using AxiamAmqpConsumer amqpConsumer = new();
try
{
    string amqpUri = Environment.GetEnvironmentVariable("AXIAM_AMQP_URI") ?? "amqp://guest:guest@localhost:5672";
    byte[] signingKey = Convert.FromHexString(Environment.GetEnvironmentVariable("AXIAM_AMQP_SIGNING_KEY_HEX") ?? "00");

    // The handler is invoked ONLY after Hmac.Verify succeeds — it never sees an
    // unverified message (§8, D-11).
    await amqpConsumer.StartAsync(amqpUri, "axiam.audit.events", signingKey, async (body, ct) =>
    {
        Console.WriteLine($"Verified AMQP event received ({body.Length} bytes).");
        await Task.CompletedTask;
    });

    Console.WriteLine("AMQP consumer registered — press Ctrl+C to exit.");
    await Task.Delay(Timeout.Infinite);
}
catch (Exception ex)
{
    Console.WriteLine($"AMQP phase skipped — no reachable broker ({ex.Message}). See README.md.");
}

// Local helper isolating the two-phase MFA dance so the top-level flow above
// reads linearly; returns once a session has been fully established.
static async Task<LoginResultShim> LoginAsync(AxiamClient client)
{
    Axiam.Sdk.Auth.LoginResult login = await client.LoginAsync(
        email: Environment.GetEnvironmentVariable("AXIAM_EMAIL") ?? "alice@example.com",
        password: Environment.GetEnvironmentVariable("AXIAM_PASSWORD") ?? "correct horse battery staple");

    if (login.MfaRequired)
    {
        Console.WriteLine("MFA challenge issued — verifying with a TOTP code...");
        // login.ChallengeToken is a Sensitive<string> (CONTRACT.md §7) — passed
        // straight through to VerifyMfaAsync; this example never reveals it.
        login = await client.VerifyMfaAsync(
            login.ChallengeToken!.Value,
            totpCode: Environment.GetEnvironmentVariable("AXIAM_TOTP_CODE") ?? "123456");
    }

    return new LoginResultShim(login.MfaRequired);
}

// Minimal marker type so the local LoginAsync helper's return value cannot
// accidentally leak a Sensitive<string> outward — the caller only ever needs to
// know the flow completed.
internal sealed record LoginResultShim(bool MfaRequired);
