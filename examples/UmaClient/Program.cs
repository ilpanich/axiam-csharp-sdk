using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;

// UMA 2.0 (CONTRACT.md §20) — the CLIENT half of the example pair.
//
// Run examples/UmaResourceServer first; this program talks to it.
//
// The flow, which is the whole reason UMA exists:
//
//   1. Ask for the invoice with the user's ordinary token. The resource server
//      refuses — but its 403 carries `WWW-Authenticate: UMA` naming a ticket and
//      an authorization server.
//   2. PARSE the challenge. Note what happens next, and what does not: parsing
//      performs no exchange (§20.3). The as_uri in that header is a host the
//      *server we just failed against* chose; auto-redeeming would send the
//      user's token wherever a 403 pointed.
//   3. Decide to trust it, then EXCHANGE the ticket for an RPT.
//   4. Retry with the RPT.
//
// Step 3 is a decision, not a formality — this example makes it explicitly, by
// comparing the nominated as_uri against the issuer this client already trusts,
// and refusing when they differ.
string Env(string key, string fallback) =>
    Environment.GetEnvironmentVariable(key) is { Length: > 0 } value ? value : fallback;

string resourceServer = Env("AXIAM_RESOURCE_SERVER", "http://127.0.0.1:5081");
// The resource server printed this id when it registered.
string invoiceId = Env("AXIAM_INVOICE_ID", "00000000-0000-0000-0000-000000000000");
// The requesting party's own token — what this program would normally send and,
// in step 3, the claim_token that names *who* is asking.
string userToken = Env("AXIAM_USER_TOKEN", "the-requesting-partys-access-token");

var url = new Uri($"{resourceServer}/invoices/{invoiceId}");
using var http = new HttpClient();

// The exchange is a token-endpoint grant, so this client is confidential.
using var client = new AxiamClient(
    new Uri(Env("AXIAM_BASE_URL", "https://localhost:8443")),
    Env("AXIAM_TENANT_ID", "acme"),
    new AxiamClientOptions
    {
        BaseUrl = new Uri(Env("AXIAM_BASE_URL", "https://localhost:8443")),
        TenantId = Env("AXIAM_TENANT_ID", "acme"),
        OidcClientId = Env("AXIAM_OIDC_CLIENT_ID", "invoices-client"),
        OidcClientSecret = Env("AXIAM_OIDC_CLIENT_SECRET", "client-secret"),
    });

// ---- 1. The refusal ----
using HttpResponseMessage refused = await Get(url, userToken).ConfigureAwait(false);
Console.WriteLine($"first attempt: {(int)refused.StatusCode}");

if (!refused.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? headerValues))
{
    // A resource server that refuses without a challenge is telling you it has
    // nothing to offer — there is no ticket to redeem, and retrying the same
    // request would be pointless.
    Console.WriteLine("no WWW-Authenticate header: this refusal is not actionable.");
    return;
}

// ---- 2. Parse, and only parse ----
UmaChallenge? challenge = UmaChallenge.Parse(string.Join(", ", headerValues));
if (challenge?.Ticket is not Sensitive<string> ticket)
{
    Console.WriteLine("the challenge names no ticket; nothing to redeem.");
    return;
}

// Nothing from the challenge is echoed, and there are two separate reasons for
// that.
//
// The ticket, because §20.6 says so: its 60-second life does not make it
// harmless — for those 60 seconds it IS the credential that converts into an
// RPT, so a header in a log line is a live credential in a log line.
//
// The realm and as_uri, because they are strings a *remote* server chose. They
// are not secrets, but echoing attacker-controlled text into a terminal or a log
// file is its own small hazard (escape sequences, log forging), and an example
// is the last place to teach the habit. What matters here is the shape of the
// challenge, not its contents.
Console.WriteLine($"challenge parsed: as_uri present={challenge.AsUri is not null}, ticket present=true");

// ---- 3. The trust decision ----
//
// This is the step §20.3 exists to keep in the caller's hands. The SDK parsed
// the header and stopped; deciding whether to send the user's token to the host
// it names is this program's call, and it is a real one — a compromised or
// merely misconfigured resource server could nominate anything here.
OidcConfiguration configuration = await client.OidcDiscoverAsync().ConfigureAwait(false);
if (challenge.AsUri is string nominated &&
    !nominated.TrimEnd('/').Equals(configuration.Issuer.TrimEnd('/'), StringComparison.Ordinal))
{
    // Neither side of the comparison is echoed. The nominated value for the
    // reasons above; our own issuer because it is reached through a client
    // constructed with a client secret, and an example that prints values
    // derived from that object is teaching a habit that is fine here and wrong
    // three refactors later. The decision and its outcome are what a reader
    // needs; the values are two lines away in a debugger.
    Console.WriteLine("refusing to redeem: the challenge nominates an authorization server");
    Console.WriteLine("that is not the issuer this client already trusts.");
    Console.WriteLine("this is the auto-exchange §20.3 forbids, and why it forbids it.");
    return;
}

Console.WriteLine("as_uri matches the issuer we already trust; redeeming.");

// ---- 4. Exchange, then retry ----
//
// One request. A ticket is spent whether or not this succeeds (§20.2 rule 6), so
// on failure the next step is a *new* ticket — which means going back to step 1,
// not resending this one.
RequestingPartyToken rpt;
try
{
    rpt = await client.UmaExchangeTicketAsync(new UmaExchangeTicketParams(
        Ticket: ticket,
        ClaimToken: Sensitive<string>.Wrap(userToken),
        Configuration: configuration)).ConfigureAwait(false);
}
catch (AuthError error)
{
    // OAuthProtocolError (invalid_grant on a spent ticket, access_denied on a
    // refused one) derives from AuthError, so this catch covers both.
    Console.WriteLine($"exchange failed: {error.GetType().Name}");
    Console.WriteLine("the ticket is spent either way — request a new one by retrying.");
    return;
}

Console.WriteLine($"got an RPT, valid for {rpt.ExpiresIn}s");

using HttpResponseMessage allowed = await Get(url, rpt.AccessToken.Expose()).ConfigureAwait(false);
Console.WriteLine($"second attempt: {(int)allowed.StatusCode}");

// Issues a bearer-authenticated GET against the resource server. Plain
// HttpClient rather than the SDK client: the resource server is this program's
// own peer, not the AXIAM deployment.
async Task<HttpResponseMessage> Get(Uri target, string token)
{
    using var request = new HttpRequestMessage(HttpMethod.Get, target);
    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
    return await http.SendAsync(request).ConfigureAwait(false);
}
