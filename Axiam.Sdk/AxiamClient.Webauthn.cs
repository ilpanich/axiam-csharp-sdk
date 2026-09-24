using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Rest;
using Axiam.Sdk.Webauthn;

namespace Axiam.Sdk;

// CONTRACT.md §24 — WebAuthn / passkeys, the relying-party layer.
//
// .NET on a server or a CLI has no authenticator, so §24.6b's linked-API helper is
// deliberately absent: rule 2 forbids emulating one in software, and a "credential" held
// in process memory is not a second factor. What is here is the half that talks to AXIAM,
// plus §24.6a's JSON bridge — which is what lets a Blazor WASM, MAUI or Uno front end run
// the ceremony with its own platform API and hand the response string straight back.
public sealed partial class AxiamClient
{
    private const string WebauthnRegisterStartPath = "/api/v1/auth/webauthn/register/start";
    private const string WebauthnRegisterFinishPath = "/api/v1/auth/webauthn/register/finish";
    private const string WebauthnAuthStartPath = "/api/v1/auth/webauthn/authenticate/start";
    private const string WebauthnAuthFinishPath = "/api/v1/auth/webauthn/authenticate/finish";
    private const string WebauthnDiscoverableStartPath = "/api/v1/auth/webauthn/authenticate/discoverable/start";
    private const string WebauthnDiscoverableFinishPath = "/api/v1/auth/webauthn/authenticate/discoverable/finish";
    private const string WebauthnSetupRegisterStartPath = "/api/v1/auth/webauthn/setup/register/start";
    private const string WebauthnSetupRegisterFinishPath = "/api/v1/auth/webauthn/setup/register/finish";

    /// <summary>
    /// <c>POST /api/v1/auth/webauthn/register/start</c> (CONTRACT.md &#167;24.1) — begin
    /// enrolling a passkey for the signed-in user.
    /// </summary>
    /// <remarks>
    /// Requires a session, and refuses <b>client-side with no wire call</b> when there is
    /// none — the shape &#167;1.1 rule 3 requires of <c>GetUserInfoAsync</c>.
    /// <para>
    /// The returned options are the server's, untouched (&#167;24.0). A <c>503</c> here
    /// means the tenant's attestation policy needs FIDO metadata the server cannot reach:
    /// a configuration state, not a transient one, and &#167;24.4 rule 2 deliberately does
    /// not retry it.
    /// </para>
    /// </remarks>
    public async Task<WebauthnChallenge> WebauthnRegisterStartAsync(CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        RequireWebauthnSession(nameof(WebauthnRegisterStartAsync));
        return await WebauthnStartAsync(WebauthnRegisterStartPath, "{}", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /api/v1/auth/webauthn/register/finish</c> (CONTRACT.md &#167;24.1) — hand
    /// the authenticator's answer back and store the credential.
    /// </summary>
    /// <param name="stateToken">The token from <see cref="WebauthnRegisterStartAsync"/>.</param>
    /// <param name="credentialName">The label to store the credential under.</param>
    /// <param name="response">
    /// The platform's own response JSON, <b>verbatim</b> (&#167;24.6a rule 2):
    /// <c>credential.toJSON()</c> from a browser, or <c>registrationResponseJson</c> from
    /// Android's Credential Manager relayed by a MAUI host. It reaches the wire byte for
    /// byte, because re-encoding a signed buffer is three chances to corrupt it in service
    /// of nothing.
    /// </param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async Task<WebauthnCredential> WebauthnRegisterFinishAsync(
        Sensitive<string> stateToken,
        string credentialName,
        string response,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        RequireWebauthnSession(nameof(WebauthnRegisterFinishAsync));
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialName);

        string body = WebauthnFinishBody(
            stateToken,
            response,
            nameof(WebauthnRegisterFinishAsync),
            ("credential_name", credentialName));

        using HttpResponseMessage http =
            await PostRawJsonAsync(WebauthnRegisterFinishPath, body, cancellationToken).ConfigureAwait(false);

        if (http.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.Created))
        {
            throw await RegisterFinishErrorAsync(http, cancellationToken).ConfigureAwait(false);
        }

        JsonElement wire = await ReadJsonAsync(http, cancellationToken).ConfigureAwait(false);
        string lastUsed = ReadString(wire, "last_used_at");
        return new WebauthnCredential(
            Guid.Parse(ReadString(wire, "id")),
            ReadString(wire, "credential_id"),
            ReadString(wire, "name"),
            ReadString(wire, "credential_type"),
            ReadString(wire, "created_at"),
            lastUsed.Length == 0 ? null : lastUsed);
    }

    /// <summary>
    /// <c>POST /api/v1/auth/webauthn/authenticate/start</c> (CONTRACT.md &#167;24.1) —
    /// begin the <b>second-factor</b> ceremony.
    /// </summary>
    /// <remarks>
    /// Continues a <see cref="LoginAsync"/> that answered <c>MfaRequired</c> with
    /// <c>"webauthn"</c> among its available methods; <paramref name="challengeToken"/> is
    /// that login's token. A different flow from
    /// <see cref="WebauthnDiscoverableStartAsync"/>, not the same one with a flag
    /// (&#167;24.2) — which is why the token is required here and absent there.
    /// </remarks>
    public async Task<WebauthnChallenge> WebauthnAuthenticateStartAsync(
        Sensitive<string> challengeToken,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        var body = new StringBuilder("{");
        AppendJsonString(body, "challenge_token", challengeToken.Reveal());
        body.Append('}');
        return await WebauthnStartAsync(WebauthnAuthStartPath, body.ToString(), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /api/v1/auth/webauthn/authenticate/finish</c> (CONTRACT.md &#167;24.1).
    /// </summary>
    /// <remarks>
    /// On success the client is signed in: the server sets the same cookie triple
    /// <c>POST /api/v1/auth/login</c> sets, and the &#167;17 decision memo is cleared
    /// because the subject changed (&#167;24.3).
    /// </remarks>
    public Task<WebauthnLoginResult> WebauthnAuthenticateFinishAsync(
        Sensitive<string> stateToken,
        string response,
        CancellationToken cancellationToken = default) =>
        WebauthnFinishAsync(
            WebauthnAuthFinishPath, stateToken, response, nameof(WebauthnAuthenticateFinishAsync), cancellationToken);

    /// <summary>
    /// <c>POST /api/v1/auth/webauthn/authenticate/discoverable/start</c> (CONTRACT.md
    /// &#167;24.1) — begin the usernameless ceremony.
    /// </summary>
    /// <remarks>
    /// A <b>primary factor</b>: nothing precedes it, <c>allowCredentials</c> comes back
    /// empty, and the assertion itself identifies the user. Pass <c>null</c> for
    /// <paramref name="workspace"/> to have it filled from this client's own configured
    /// identity.
    /// <para>
    /// Unlike <c>authenticate/finish</c>, <c>discoverable/finish</c> fires the
    /// <c>login.post_auth</c> reactor hook (&#167;22.5) — the former continues a login
    /// already gated at its password step, and this one has no such step.
    /// </para>
    /// </remarks>
    public async Task<WebauthnChallenge> WebauthnDiscoverableStartAsync(
        WebauthnWorkspace? workspace = null,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        return await WebauthnStartAsync(
            WebauthnDiscoverableStartPath, WebauthnWorkspaceBody(workspace), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /api/v1/auth/webauthn/authenticate/discoverable/finish</c> (CONTRACT.md
    /// &#167;24.1). Adopts credentials exactly as
    /// <see cref="WebauthnAuthenticateFinishAsync"/> does.
    /// </summary>
    public Task<WebauthnLoginResult> WebauthnDiscoverableFinishAsync(
        Sensitive<string> stateToken,
        string response,
        CancellationToken cancellationToken = default) =>
        WebauthnFinishAsync(
            WebauthnDiscoverableFinishPath, stateToken, response, nameof(WebauthnDiscoverableFinishAsync), cancellationToken);

    /// <summary>
    /// <c>POST /api/v1/auth/webauthn/setup/register/start</c> (CONTRACT.md &#167;24.1,
    /// contract 1.45) — begin enrolling a passkey or security key as the <b>first</b>
    /// factor during forced MFA setup at login.
    /// </summary>
    /// <remarks>
    /// The WebAuthn twin of <see cref="MfaSetupEnrollAsync"/>: reached when
    /// <see cref="LoginAsync"/> answers <see cref="LoginResult.MfaSetupRequired"/>, there
    /// is no session yet, and <paramref name="setupToken"/> — from that <c>403</c> — is
    /// the only credential. Unlike <see cref="WebauthnRegisterStartAsync"/> this call
    /// takes <b>no</b> session and runs over a dedicated transport that never carries this
    /// client's own session credential (&#167;24.1: "an SDK MUST NOT attach its session
    /// credential to these two"), even when one happens to be configured on this instance.
    /// <para>
    /// The server refuses an account that already has a factor with the same <c>400</c>
    /// <c>mfa_setup_enroll</c> gives — a setup token adds the first factor, never a
    /// second. A <c>503</c> means the tenant's attestation policy needs FIDO metadata the
    /// server cannot reach and, exactly as <see cref="WebauthnRegisterStartAsync"/>,
    /// &#167;24.4 rule 2 means this is deliberately not retried.
    /// </para>
    /// </remarks>
    /// <param name="setupToken">The setup token from <see cref="LoginResult.MfaSetupRequired"/>.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async Task<WebauthnChallenge> WebauthnSetupRegisterStartAsync(
        Sensitive<string> setupToken, CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        var body = new StringBuilder("{");
        AppendJsonString(body, "setup_token", setupToken.Reveal());
        body.Append('}');

        using HttpResponseMessage http = await PostAnonymousRawJsonAsync(
            WebauthnSetupRegisterStartPath, body.ToString(), cancellationToken).ConfigureAwait(false);
        if (http.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(http, $"{nameof(WebauthnSetupRegisterStartAsync)} failed");
        }

        JsonElement wire = await ReadJsonAsync(http, cancellationToken).ConfigureAwait(false);
        JsonElement challenge;
        if (wire.TryGetProperty("challenge", out JsonElement served))
        {
            challenge = served.Clone();
        }
        else
        {
            using JsonDocument empty = JsonDocument.Parse("{}");
            challenge = empty.RootElement.Clone();
        }
        return new WebauthnChallenge(challenge, Sensitive.Of(ReadString(wire, "state_token")));
    }

    /// <summary>
    /// <c>POST /api/v1/auth/webauthn/setup/register/finish</c> (CONTRACT.md &#167;24.1,
    /// &#167;25.2 rule 2, contract 1.45) — complete forced enrolment with a passkey or
    /// security key, and with it the login that was interrupted.
    /// </summary>
    /// <remarks>
    /// Adopts credentials <b>exactly as</b> <see cref="MfaSetupConfirmAsync"/> does
    /// (&#167;25.2 rule 2, &#167;24.3's five adoption rules): the client is left
    /// authenticated in the same state a successful <see cref="LoginAsync"/> leaves it,
    /// and the &#167;17 decision memo is cleared, because the subject just changed. The two
    /// completions of a forced first-login enrolment — this one and
    /// <see cref="MfaSetupConfirmAsync"/> — MUST leave the client in the same state, or a
    /// caller's next request succeeds or fails depending on which factor the user
    /// happened to choose.
    /// <para>
    /// Runs over the same session-credential-free transport as
    /// <see cref="WebauthnSetupRegisterStartAsync"/> — the setup token is the only
    /// credential this call sends — but the new session the server issues on success is
    /// still adopted into this client's own cookie jar, exactly as every other login path
    /// in this SDK adopts one.
    /// </para>
    /// </remarks>
    /// <param name="setupToken">The setup token from <see cref="LoginResult.MfaSetupRequired"/>.</param>
    /// <param name="stateToken">The token from <see cref="WebauthnSetupRegisterStartAsync"/>.</param>
    /// <param name="credentialName">The label to store the credential under.</param>
    /// <param name="response">
    /// The platform's own response JSON, <b>verbatim</b> (&#167;24.6a rule 2) — see
    /// <see cref="WebauthnRegisterFinishAsync"/>'s parameter of the same name.
    /// </param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async Task<LoginResult> WebauthnSetupRegisterFinishAsync(
        Sensitive<string> setupToken,
        Sensitive<string> stateToken,
        string credentialName,
        string response,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        // §17.1 rule 9 / §24.3 rule 4: memo entries are keyed by subject, and this call
        // changes the subject — exactly as MfaSetupConfirmAsync's own call to this does.
        OnCredentialChange();
        ReleaseDeviceCredential();
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialName);

        string body = WebauthnFinishBody(
            stateToken,
            response,
            nameof(WebauthnSetupRegisterFinishAsync),
            ("setup_token", setupToken.Reveal()),
            ("credential_name", credentialName));

        using HttpResponseMessage http = await PostAnonymousRawJsonAsync(
            WebauthnSetupRegisterFinishPath, body, cancellationToken).ConfigureAwait(false);
        if (http.StatusCode != HttpStatusCode.OK)
        {
            throw await RegisterFinishErrorAsync(
                http, cancellationToken, nameof(WebauthnSetupRegisterFinishAsync)).ConfigureAwait(false);
        }

        // §24.3 rule 2: a cookie-jar SDK adopts through the jar. This call ran over the
        // anonymous, session-credential-free transport, so the server's Set-Cookie triple
        // landed in THAT transport's own jar rather than the shared one every other call
        // reads from — copy it across before this client is asked to act on the new
        // session. Also mirrors AxiamHttpMessageHandler's own X-CSRF-Token capture, so the
        // very next state-changing call already carries it.
        AdoptAnonymousCookies();
        _authHandler.CaptureCsrfToken(http);

        (bool organizationLevel, PrincipalScope? scope) =
            await ReadLoginScopeAsync(http, cancellationToken).ConfigureAwait(false);
        return new LoginResult(false, OrganizationLevel: organizationLevel, Scope: scope);
    }

    // ------------------------------------------------------------------
    // Shared mechanics
    // ------------------------------------------------------------------

    /// <summary>Runs either <c>*_start</c> call and returns the options untouched.</summary>
    private async Task<WebauthnChallenge> WebauthnStartAsync(string path, string body, CancellationToken cancellationToken)
    {
        using HttpResponseMessage http =
            await PostRawJsonAsync(path, body, cancellationToken).ConfigureAwait(false);
        if (http.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(http, "webauthn start failed");
        }

        JsonElement wire = await ReadJsonAsync(http, cancellationToken).ConfigureAwait(false);
        JsonElement challenge;
        if (wire.TryGetProperty("challenge", out JsonElement served))
        {
            challenge = served.Clone();
        }
        else
        {
            using JsonDocument empty = JsonDocument.Parse("{}");
            challenge = empty.RootElement.Clone();
        }
        return new WebauthnChallenge(challenge, Sensitive.Of(ReadString(wire, "state_token")));
    }

    /// <summary>The shared tail of both authentication ceremonies.</summary>
    private async Task<WebauthnLoginResult> WebauthnFinishAsync(
        string path,
        Sensitive<string> stateToken,
        string response,
        string operation,
        CancellationToken cancellationToken)
    {
        EnsureNotDisposed();
        // §17.1 rule 9 / §24.3 rule 4: memo entries are keyed by subject, and this call
        // changes the subject.
        OnCredentialChange();
        ReleaseDeviceCredential();

        string body = WebauthnFinishBody(stateToken, response, operation);
        using HttpResponseMessage http =
            await PostRawJsonAsync(path, body, cancellationToken).ConfigureAwait(false);
        if (http.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(http, $"{operation} failed");
        }

        JsonElement wire = await ReadJsonAsync(http, cancellationToken).ConfigureAwait(false);
        return new WebauthnLoginResult(
            Sensitive.Of(ReadString(wire, "access_token")),
            Sensitive.Of(ReadString(wire, "refresh_token")),
            Guid.Parse(ReadString(wire, "session_id")),
            wire.TryGetProperty("expires_in", out JsonElement expiresIn) && expiresIn.TryGetInt64(out long seconds)
                ? seconds
                : 0L);
    }

    /// <summary>
    /// Builds a <c>*_finish</c> body <b>as text</b>, splicing the caller's response JSON in
    /// verbatim (&#167;24.0, &#167;24.6a rule 2).
    /// </summary>
    /// <remarks>
    /// Deserializing the string and re-serializing it would round every number, reorder
    /// nothing predictably, and generally hand the server a byte sequence the authenticator
    /// never signed. The one thing this does check is that the string IS a JSON object —
    /// the SDK will not POST a body it already knows the server cannot verify.
    /// </remarks>
    private static string WebauthnFinishBody(
        Sensitive<string> stateToken,
        string response,
        string operation,
        params (string Key, string Value)[] extraFields)
    {
        ArgumentNullException.ThrowIfNull(response);
        string trimmed = response.Trim();

        JsonValueKind kind;
        try
        {
            using JsonDocument parsed = JsonDocument.Parse(trimmed);
            kind = parsed.RootElement.ValueKind;
        }
        catch (JsonException ex)
        {
            throw new AuthError(
                $"{operation}: the authenticator response string is not valid JSON. Pass the " +
                $"platform's response JSON verbatim (CONTRACT.md §24.6a). {ex.Message}");
        }

        if (kind != JsonValueKind.Object)
        {
            throw new AuthError(
                $"{operation}: the authenticator response must be a JSON object (CONTRACT.md §24.6a).");
        }

        var body = new StringBuilder("{");
        AppendJsonString(body, "state_token", stateToken.Reveal());
        foreach ((string key, string value) in extraFields)
        {
            body.Append(',');
            AppendJsonString(body, key, value);
        }
        body.Append(",\"response\":").Append(trimmed).Append('}');
        return body.ToString();
    }

    /// <summary>Appends <c>"key":"value"</c> with both halves properly JSON-escaped.</summary>
    private static void AppendJsonString(StringBuilder sink, string key, string value)
    {
        sink.Append(JsonSerializer.Serialize(key)).Append(':').Append(JsonSerializer.Serialize(value));
    }

    /// <summary>
    /// &#167;24.1: <c>register/…</c> needs a session, and the refusal is raised client-side
    /// with <b>no wire call</b>.
    /// </summary>
    /// <remarks>
    /// The signal is the cached access cookie rather than a separate flag: this SDK has
    /// never kept one, and a second source of truth for "am I signed in" is a second thing
    /// to get out of step with the jar.
    /// </remarks>
    private void RequireWebauthnSession(string operation)
    {
        if (ReadCookie(AccessCookieName) is null)
        {
            throw new AuthError(
                $"{operation} requires an authenticated session: enrol a passkey while signed in " +
                "(CONTRACT.md §24.1).");
        }
    }

    /// <summary>
    /// &#167;24.4 rule 1: the <c>403</c> from <c>register/finish</c> (and its
    /// <c>setup/register/finish</c> twin, contract 1.45) is the one whose <i>body</i>
    /// matters.
    /// </summary>
    /// <remarks>
    /// The generic &#167;2 mapping would raise an <see cref="AuthzError"/> reading
    /// "WebauthnRegisterFinishAsync failed", which tells the person holding the key nothing
    /// they can act on. The tenant's attestation policy rejected <i>this</i> authenticator,
    /// and the server's message is the only place that says which one would be accepted.
    /// </remarks>
    /// <param name="http">The non-OK/Created response.</param>
    /// <param name="cancellationToken">Cancels the body read.</param>
    /// <param name="operation">
    /// The operation name for the error message — defaults to
    /// <see cref="WebauthnRegisterFinishAsync"/>'s own name; its
    /// <see cref="WebauthnSetupRegisterFinishAsync"/> twin passes its own.
    /// </param>
    private static async Task<Exception> RegisterFinishErrorAsync(
        HttpResponseMessage http, CancellationToken cancellationToken, string operation = nameof(WebauthnRegisterFinishAsync))
    {
        string context = $"{operation} failed";
        if (http.StatusCode == HttpStatusCode.Forbidden)
        {
            try
            {
                string raw = await http.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(raw))
                {
                    using JsonDocument doc = JsonDocument.Parse(raw);
                    if (doc.RootElement.TryGetProperty("message", out JsonElement messageEl) &&
                        messageEl.ValueKind == JsonValueKind.String &&
                        messageEl.GetString() is { Length: > 0 } policy)
                    {
                        context = $"{context}: {policy}";
                    }
                }
            }
            catch (JsonException)
            {
                // A malformed body must not mask the 403 itself.
            }
        }
        return ErrorMapper.FromHttpResponse(http, context);
    }

    /// <summary>
    /// Fills the discoverable ceremony's workspace from this client's own configuration
    /// when the caller passed none.
    /// </summary>
    /// <remarks>
    /// Only fields that actually have a value are emitted: the server takes either form at
    /// either level, and sending <c>null</c> for the ones it does not have is
    /// indistinguishable from asking it to resolve nothing.
    /// </remarks>
    private string WebauthnWorkspaceBody(WebauthnWorkspace? workspace)
    {
        Guid? orgId = workspace?.OrgId;
        string? orgSlug = workspace?.OrgSlug;
        if (orgId is null && orgSlug is null)
        {
            orgId = _tenant.OrgId;
            orgSlug = _tenant.OrgSlug;
        }

        var body = new StringBuilder("{");
        if (orgId is Guid resolvedOrgId)
        {
            AppendJsonString(body, "org_id", resolvedOrgId.ToString());
        }
        else if (orgSlug is not null)
        {
            AppendJsonString(body, "org_slug", orgSlug);
        }
        else
        {
            throw new AuthError(
                "WebauthnDiscoverableStartAsync needs an organization: construct the client with " +
                "one, or pass it in the workspace argument (CONTRACT.md §24.1).");
        }

        body.Append(',');
        if (workspace?.TenantId is Guid tenantGuid)
        {
            AppendJsonString(body, "tenant_id", tenantGuid.ToString());
        }
        else if (workspace?.TenantSlug is { } slug)
        {
            AppendJsonString(body, "tenant_slug", slug);
        }
        else if (Guid.TryParse(_tenant.TenantId, out Guid ownTenant))
        {
            AppendJsonString(body, "tenant_id", ownTenant.ToString());
        }
        else
        {
            AppendJsonString(body, "tenant_slug", _tenant.TenantId);
        }

        body.Append('}');
        return body.ToString();
    }

    /// <summary>
    /// POSTs a body that is already JSON <b>text</b>, so the caller's bytes reach the wire
    /// unmodified (&#167;24.0). Goes through the same <c>_httpClient</c> every other REST
    /// call uses, so &#167;3 CSRF, &#167;4 cookies, &#167;5 tenant header and &#167;6 TLS
    /// all apply.
    /// </summary>
    private async Task<HttpResponseMessage> PostRawJsonAsync(string path, string json, CancellationToken cancellationToken)
    {
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = content };
        try
        {
            return await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw NetworkError.FromException(ex, $"POST {path} failed");
        }
        catch (OperationCanceledException ex) when (ex.CancellationToken != cancellationToken)
        {
            throw NetworkError.FromException(ex, $"POST {path} timed out");
        }
    }

    /// <summary>
    /// POSTs a body that is already JSON <b>text</b> over the <b>anonymous</b> transport
    /// (&#167;24.1, contract 1.45) — <see cref="_anonymousHttpClient"/>, not
    /// <c>_httpClient</c>. Used <b>only</b> by <see cref="WebauthnSetupRegisterStartAsync"/>
    /// and <see cref="WebauthnSetupRegisterFinishAsync"/>: those two calls take a setup
    /// token in the body as their sole credential and an SDK MUST NOT attach a stray
    /// <c>Authorization</c> header or a session cookie to them, even when this client
    /// instance already has a session. <see cref="_anonymousHttpClient"/> is built over its
    /// own, permanently empty cookie jar for exactly this reason — there is nothing in it
    /// for the real transport to send, and it never runs through
    /// <see cref="AxiamHttpMessageHandler"/>'s Authorization-header derivation at all.
    /// </summary>
    /// <remarks>
    /// Still applies &#167;5's <c>X-Tenant-Id</c> (unconditional, rule 2 admits no
    /// exceptions) by hand, since that responsibility normally belongs to
    /// <see cref="AxiamHttpMessageHandler"/> and this path deliberately does not go through
    /// it. It also applies &#167;5.2 rule 1's <c>X-Axiam-Tenant</c> the same way, when this
    /// handle has an acting tenant set: &#167;5.2.2 rule 4 is explicit that a self-service or
    /// setup call is NOT exempt from sending it — "an SDK MUST NOT work around that by
    /// clearing or rewriting X-Axiam-Tenant" — so bypassing <c>AxiamHttpMessageHandler</c>
    /// for the session/Authorization withholding above must not silently drop it too.
    /// Both headers go through the same <see cref="AxiamClient.ApplyAnonymousTenantHeaders"/>
    /// helper <see cref="AxiamClient.AuthenticateDeviceAsync"/> uses, so the two
    /// anonymous-transport call sites cannot drift on this. No CSRF header is added:
    /// &#167;3 rule 3 already says to omit it when no <c>axiam_csrf</c> cookie exists yet,
    /// which is always true of a jar that starts empty and is never written to before this
    /// request.
    /// </remarks>
    private async Task<HttpResponseMessage> PostAnonymousRawJsonAsync(string path, string json, CancellationToken cancellationToken)
    {
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = content };
        ApplyAnonymousTenantHeaders(request);
        try
        {
            return await _anonymousHttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw NetworkError.FromException(ex, $"POST {path} failed");
        }
        catch (OperationCanceledException ex) when (ex.CancellationToken != cancellationToken)
        {
            throw NetworkError.FromException(ex, $"POST {path} timed out");
        }
    }

    /// <summary>
    /// &#167;24.3 rule 2 for a call that ran over the anonymous transport: copies whatever
    /// cookies <see cref="_anonymousPrimaryHandler"/>'s own jar captured (a real
    /// <see cref="HttpClientHandler"/> in production parses the server's Set-Cookie triple
    /// into it exactly as it would for any other request) into <see cref="_cookieContainer"/>
    /// — the jar every other call on this client reads from.
    /// </summary>
    /// <remarks>
    /// A no-op when <see cref="_anonymousPrimaryHandler"/> is a test double rather than a
    /// real <see cref="HttpClientHandler"/> (<c>CreateForTesting</c>'s fake transport does
    /// not perform real Set-Cookie parsing at all — see <c>AxiamClientAuthFlowTests</c>'
    /// remarks — so there is nothing here to copy in that case; <see cref="CookieJarBridge"/>
    /// carries its own unit test of the copy logic in isolation).
    /// </remarks>
    private void AdoptAnonymousCookies()
    {
        if (_anonymousPrimaryHandler is HttpClientHandler real)
        {
            CookieJarBridge.Copy(real.CookieContainer, _cookieContainer, _baseUrl);
        }
    }
}
