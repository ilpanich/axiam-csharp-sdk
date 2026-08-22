using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;

// CONTRACT.md §26 — Pushed Authorization Requests (RFC 9126).
//
// PAR moves the authorization request off the browser. Instead of putting scope,
// redirect_uri, state and the PKCE challenge into a URL the user agent carries, the client
// POSTs them straight to AXIAM over an authenticated back channel and puts an opaque
// request_uri in the redirect. What travels through the browser is then a random string
// that cannot be edited into meaning something else.
//
// A FAPI 2.0 client has no choice: profile: "fapi2" refuses a registration that does not
// set require_par, so such a client cannot authorize any other way (§21.1).

string redirectUri = "https://app.example.com/callback";

Uri baseUrl = new(Environment.GetEnvironmentVariable("AXIAM_BASE_URL") ?? "https://localhost:8443");
string tenantId = Environment.GetEnvironmentVariable("AXIAM_TENANT_ID")
                  ?? "00000000-0000-0000-0000-000000000000";

var options = new AxiamClientOptions
{
    BaseUrl = baseUrl,
    TenantId = tenantId,
    OidcClientId = Environment.GetEnvironmentVariable("AXIAM_CLIENT_ID") ?? "app",
    OidcClientSecret = Environment.GetEnvironmentVariable("AXIAM_CLIENT_SECRET") ?? "s3cret",
};

using var client = new AxiamClient(baseUrl, tenantId, options);

try
{
    OidcConfiguration config = await client.OidcDiscoverAsync();

    // §26 is optional, so a server may advertise no endpoint at all. The SDK refuses
    // client-side rather than concatenating a URL onto the issuer and POSTing a
    // fully-formed authorization request at a 404 (§12.7.2 rule 1).
    if (string.IsNullOrEmpty(config.PushedAuthorizationRequestEndpoint))
    {
        Console.WriteLine("this server does not support RFC 9126 — fall back to the plain OidcBegin redirect");
        return;
    }

    await PushAndRedirectAsync(client, config, redirectUri);
}
catch (NetworkError e)
{
    Console.WriteLine($"no reachable server: {e.Message}");
}

static async Task PushAndRedirectAsync(AxiamClient client, OidcConfiguration config, string redirectUri)
{
    // OidcBegin still runs first, and still owns state/nonce/PKCE. §26.2 rule 1 forbids a
    // second generator: two sources for any of those are two things that can disagree.
    AuthorizationRequest begun = client.OidcBegin(
        config, new OidcBeginParams { RedirectUri = redirectUri, Scope = "openid profile" });

    PushedAuthorizationRequest pushed;
    try
    {
        pushed = await client.OidcParAsync(new OidcParParams
        {
            Request = begun,
            RedirectUri = redirectUri,
            Configuration = config,
            Scope = "openid profile",
        });
    }
    catch (OAuthProtocolError e)
    {
        Console.WriteLine($"the server rejected the push: {e.Error}");
        return;
    }
    catch (AuthError e)
    {
        Console.WriteLine($"no PAR endpoint: {e.Message}");
        return;
    }
    // Note there is no retry here, and there must not be. This is a POST that creates
    // server state, so it falls outside §16.2's read-only eligibility. The safe recovery
    // is a fresh push, which costs one round trip and cannot double-consume anything
    // (§26.2 rule 4).

    // The URL carries EXACTLY client_id and request_uri. The server refuses a request that
    // mixes a request_uri with inline authorization parameters rather than merging them —
    // an attacker supplies the inline value they want and lets the pushed copy satisfy
    // whichever check reads the other one. Re-adding scope "for compatibility" restores
    // the attack (§26.2 rule 2).
    Console.WriteLine($"redirect the browser to: {pushed.Url}");
    Console.WriteLine($"the handle expires in {pushed.ExpiresIn}s");

    // Persist these three exactly as a non-PAR login would — the redirect being opaque
    // changes nothing about the callback's obligations. A real application uses its own
    // HTTP session, or an IOidcStateStore; the SDK stores nothing (§12.3 rule 1).
    Console.WriteLine("  stashed state/nonce/verifier for the callback");

    await CompleteTheCallbackAsync(client, config, pushed, redirectUri);
}

static async Task CompleteTheCallbackAsync(
    AxiamClient client, OidcConfiguration config, PushedAuthorizationRequest pushed, string redirectUri)
{
    string returnedState = Environment.GetEnvironmentVariable("AXIAM_STATE") ?? "the-state-from-the-redirect";
    if (!string.Equals(pushed.State, returnedState, StringComparison.Ordinal))
    {
        // state is not a secret (§12.3 rule 2), but this comparison is the CSRF guard, so
        // a real application makes it constant-time.
        Console.WriteLine("state mismatch — drop this callback on the floor");
        return;
    }

    try
    {
        // The exchange is the ordinary §12 one. The request_uri is spent by now: it is
        // single-use, and a second redirect through it fails.
        OidcTokenSet tokens = await client.OidcExchangeAsync(new OidcExchangeParams
        {
            Code = Environment.GetEnvironmentVariable("AXIAM_AUTH_CODE") ?? "the-code-from-the-redirect",
            CodeVerifier = pushed.CodeVerifier,
            RedirectUri = redirectUri,
            Nonce = pushed.Nonce,
            Configuration = config,
        });
        Console.WriteLine($"signed in, id token subject: {tokens.IdClaims?.Sub ?? "(none)"}");
    }
    catch (Exception e) when (e is NetworkError or AuthError or OAuthProtocolError)
    {
        Console.WriteLine($"the exchange did not complete: {e.Message}");
    }
}
