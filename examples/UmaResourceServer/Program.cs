using Axiam.Sdk;
using Axiam.Sdk.AspNetCore;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Microsoft.AspNetCore.Authorization;

// UMA 2.0 (CONTRACT.md §20) — the RESOURCE-SERVER half of the example pair.
//
// The situation: this service holds invoices that belong to *users*, not to
// itself. When someone asks for one, the useful answer is not just "no" — it is
// "not with what you're carrying, and here is where to go and get better". That
// actionable refusal is what UMA adds over plain RBAC.
//
// What this shows, in order:
//
//   1. Mint a PAT — a client-credentials token carrying `uma_protection`.
//      §20.2 rule 1 requires a *client* token: a minted ticket is bound to the
//      client_id that minted it, so a user token cannot stand in.
//   2. Register the resource this service guards. The returned id IS the AXIAM
//      resource id — there is no parallel resource store to keep in sync.
//   3. Register a UmaChallenger, so a denied [Authorize(Policy=…)] carries
//      `WWW-Authenticate: UMA` with a fresh ticket.
//
// Its counterpart is examples/UmaClient, which consumes that header.
var builder = WebApplication.CreateBuilder(args);

Uri baseUrl = new(builder.Configuration["Axiam:BaseUrl"] ?? "https://localhost:8443");
string tenantId = builder.Configuration["Axiam:TenantId"] ?? "acme";
string clientId = builder.Configuration["Axiam:OidcClientId"] ?? "invoices-resource-server";
string clientSecret = builder.Configuration["Axiam:OidcClientSecret"] ?? "resource-server-secret";

builder.Services.AddAxiamAspNetCore(options =>
{
    options.BaseUrl = baseUrl;
    options.DefaultTenantId = tenantId;
    options.OidcClientId = clientId;
    // The Protection API needs a confidential client: the PAT below is a
    // client-credentials token, and that grant authenticates with the secret.
    options.OidcClientSecret = clientSecret;
});

// The bootstrap below needs a client before the host is built, so it constructs
// its own rather than resolving the DI singleton. Both point at the same server;
// only this one is used for registration and minting.
using var bootstrapClient = new AxiamClient(baseUrl, tenantId, new AxiamClientOptions
{
    BaseUrl = baseUrl,
    TenantId = tenantId,
    OidcClientId = clientId,
    OidcClientSecret = clientSecret,
});

// ---- 1. The PAT ----
//
// §20.2 rule 1: a client-credentials token carrying `uma_protection`. Not a user
// token, and not this client's ambient session — the SDK will not substitute
// either, and the Protection API would refuse them anyway.
OidcTokenSet session = await bootstrapClient
    .LoginClientCredentialsAsync(new LoginClientCredentialsParams { Scope = "uma_protection" })
    .ConfigureAwait(false);
Sensitive<string> pat = session.AccessToken;

// ---- 2. Registration ----
//
// Registering the same name twice creates two resources, so a real service
// registers once at provisioning time and stores the id, or reconciles by
// listing. Inline here because it is the step that shows the returned id is the
// AXIAM resource id.
ResourceSet registered = await bootstrapClient.UmaRegisterResourceAsync(
    pat,
    new ResourceSet(
        Name: "invoice-7",
        Type: "invoice",
        // The declared scopes are the allow-list the permission endpoint
        // validates a ticket request against. A resource registered with none
        // can never appear in a ticket.
        ResourceScopes: new[] { "invoices:read", "invoices:approve" })).ConfigureAwait(false);

// ---- 3. The challenger ----
//
// AsUri names where the caller should redeem the ticket. Read it from the
// discovery document rather than assembling it by hand — a deployment is free to
// move its endpoints, which is why §12.3 rule 6 forbids hardcoding them.
OidcConfiguration configuration = await bootstrapClient.OidcDiscoverAsync().ConfigureAwait(false);

// The load-bearing line. Without it this is an ordinary §11 policy handler and a
// denial is a bare 403; with it, the denial carries a ticket and the caller can
// act on it.
builder.Services.AddAxiamUmaChallenge(new UmaChallenger("invoices", configuration.Issuer, pat));

var app = builder.Build();

app.UseMiddleware<AxiamAuthMiddleware>();
app.UseAuthorization();

// Reached only when the engine allowed it — including honouring any deny rule,
// which UMA does not bypass: the ticket minted on a refusal asks for the same
// action this check just evaluated, so the same grants and denies apply to
// whatever RPT comes back.
app.MapGet("/invoices/{id:guid}", (Guid id) => Results.Json(new { id, total = "42.00", currency = "EUR" }))
   .RequireAuthorization("invoices:read");

Console.WriteLine($"registered invoice-7 as {registered.Id}");
Console.WriteLine($"try:  curl -i http://127.0.0.1:5081/invoices/{registered.Id}");

await app.RunAsync().ConfigureAwait(false);
