using Axiam.Sdk;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Axiam.Sdk.Webauthn;

// CONTRACT.md §24 — WebAuthn / passkeys, from .NET.
//
// A server or CLI runtime has no authenticator, so §24.6b's linked-API helper is
// deliberately absent from this SDK: rule 2 forbids emulating one in software, and a
// "credential" held in process memory is not a second factor. What is here is the half
// that talks to AXIAM, plus §24.6a's JSON bridge — which is what lets a Blazor WASM, MAUI
// or Uno front end run the ceremony with its own platform API and hand the response
// string straight back to an ASP.NET Core relying party.
//
// Three demonstrations, each compilable against the SDK's public surface. Running them
// against a live AXIAM server is manual-only.

Uri baseUrl = new(Environment.GetEnvironmentVariable("AXIAM_BASE_URL") ?? "https://localhost:8443");
string tenantId = Environment.GetEnvironmentVariable("AXIAM_TENANT_ID") ?? "acme";
string orgSlug = Environment.GetEnvironmentVariable("AXIAM_ORG_SLUG") ?? "acme";

var options = new AxiamClientOptions
{
    BaseUrl = baseUrl,
    TenantId = tenantId,
    OrgSlug = orgSlug,
};

using var client = new AxiamClient(baseUrl, tenantId, options);

await EnrolAPasskeyAsync(client);
await SignInWithADiscoverableCredentialAsync(client);
ClassifyWhatWentWrong();
ShowTheBrowserHalf();

// ---------------------------------------------------------------------------
// 1. Enrolment — requires a session (§24.1)
// ---------------------------------------------------------------------------

static async Task EnrolAPasskeyAsync(AxiamClient client)
{
    Console.WriteLine("== enrolling a passkey ==");
    try
    {
        await client.LoginAsync("alice@example.com", Environment.GetEnvironmentVariable("AXIAM_PASSWORD") ?? "pw");

        // The server chooses every option: the challenge, the RP id, the algorithms, the
        // attestation policy, whether a resident key is required. This SDK defaults
        // nothing and validates nothing (§24.0) — a client that "helpfully" filled in a
        // missing field would be overriding a policy decision it cannot see.
        WebauthnChallenge challenge = await client.WebauthnRegisterStartAsync();

        // §24.6a rule 1: this string is what the browser half needs. Send it down as-is.
        Console.WriteLine($"  options for the browser: {challenge.RequestJson}");

        string authenticatorResponse = CreateCredentialSomehow();

        WebauthnCredential credential = await client.WebauthnRegisterFinishAsync(
            challenge.StateToken, "Alice's laptop", authenticatorResponse);

        Console.WriteLine($"  enrolled: {credential.Name} ({credential.CredentialType}), id {credential.Id}");
    }
    catch (AuthzError e)
    {
        // §24.4 rule 1: a 403 here is the tenant's ATTESTATION POLICY rejecting this
        // particular authenticator, and the server's message is the only place that says
        // which one would be accepted. Printing a generic "forbidden" strands the person
        // holding the key.
        Console.WriteLine($"  policy refused this authenticator: {e.Message}");
    }
    catch (AuthError e)
    {
        Console.WriteLine($"  not signed in — passkey enrolment needs a session: {e.Message}");
    }
    catch (NetworkError e)
    {
        // §24.4 rule 2: a 503 from register/start means the tenant's attestation policy
        // needs FIDO metadata the server cannot reach. That is a CONFIGURATION state, not
        // a transient one — the SDK does not retry it, and neither should this loop.
        Console.WriteLine($"  enrolment unavailable: {e.Message}");
    }
}

// ---------------------------------------------------------------------------
// 2. Sign-in — the discoverable ceremony (§24.1)
// ---------------------------------------------------------------------------

static async Task SignInWithADiscoverableCredentialAsync(AxiamClient client)
{
    Console.WriteLine("== signing in with a passkey ==");
    try
    {
        // No username. The authenticator already knows which accounts it holds for this
        // relying party, so the workspace — not the user — is what the server needs, and
        // it comes from the client's own configuration when the argument is null.
        WebauthnChallenge challenge = await client.WebauthnDiscoverableStartAsync();

        WebauthnLoginResult result = await client.WebauthnDiscoverableFinishAsync(
            challenge.StateToken, GetCredentialSomehow());

        // As of contract 1.28 the server sets the session cookie triple on this response
        // as well, so the client is signed in for every cookie-driven call that follows.
        // Before that fix a completed ceremony left the caller with no session at all.
        Console.WriteLine($"  signed in, session {result.SessionId} valid for {result.ExpiresIn}s");
    }
    catch (AuthError e)
    {
        Console.WriteLine($"  the assertion did not verify: {e.Message}");
    }
    catch (NetworkError e)
    {
        Console.WriteLine($"  no reachable server: {e.Message}");
    }
}

// ---------------------------------------------------------------------------
// 3. Saying something useful when the ceremony fails (§24.6b rule 5)
// ---------------------------------------------------------------------------

static void ClassifyWhatWentWrong()
{
    Console.WriteLine("== classifying a ceremony failure ==");

    // A browser reports a DOMException; Android's Credential Manager reports a
    // CreateCredentialException. Both carry one machine-readable thing — a name — and
    // translating it once beats translating it in every caller. This SDK links neither
    // platform, so it classifies whatever name the front end relays.
    WebauthnFailure outcome = WebauthnFailures.Classify("InvalidStateError");
    Console.WriteLine($"  {outcome}: {outcome.Message()}");

    // The distinction that matters: AlreadyRegistered is the only one whose remedy is
    // "use a different device" rather than "try again".
    if (outcome != WebauthnFailure.AlreadyRegistered)
    {
        throw new InvalidOperationException("classification regressed");
    }

    // And the one that must never accuse the user. Cancelled covers both an explicit
    // refusal and a silent timeout, because the spec refuses to distinguish them —
    // telling a website which happened would leak whether an authenticator was present.
    Console.WriteLine($"  {WebauthnFailures.Classify("NotAllowedError").Message()}");
}

// ---------------------------------------------------------------------------
// 4. The browser half — what the §24.6a bridge is for
// ---------------------------------------------------------------------------

static void ShowTheBrowserHalf()
{
    Console.WriteLine("== the browser half ==");
    Console.WriteLine("""
          // The ASP.NET Core relying party sends challenge.RequestJson down; the browser
          // hands it straight to the platform, and hands the result straight back.
          const options = PublicKeyCredential.parseCreationOptionsFromJSON(requestJson);
          const credential = await navigator.credentials.create({ publicKey: options });
          await fetch('/passkeys/finish', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            // Verbatim: nothing destructured, nothing re-encoded (§24.0).
            body: JSON.stringify({ stateToken, response: credential.toJSON() }),
          });
        """);
}

// ---------------------------------------------------------------------------

// Stands in for navigator.credentials.create() / Credential Manager.
static string CreateCredentialSomehow() => """
    {"id":"Y3JlZC1pZA","rawId":"Y3JlZC1pZA",
     "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                 "attestationObject":"o2NmbXRkbm9uZQ"},
     "type":"public-key","clientExtensionResults":{}}
    """;

// Stands in for navigator.credentials.get() / Credential Manager.
static string GetCredentialSomehow() => """
    {"id":"Y3JlZC1pZA","rawId":"Y3JlZC1pZA",
     "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                 "authenticatorData":"YXV0aC1kYXRh","signature":"c2ln",
                 "userHandle":"dXNlci1oYW5kbGU"},
     "type":"public-key","clientExtensionResults":{}}
    """;
