using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Core;
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
    /// &#167;24.4 rule 1: the <c>403</c> from <c>register/finish</c> is the one whose
    /// <i>body</i> matters.
    /// </summary>
    /// <remarks>
    /// The generic &#167;2 mapping would raise an <see cref="AuthzError"/> reading
    /// "WebauthnRegisterFinishAsync failed", which tells the person holding the key nothing
    /// they can act on. The tenant's attestation policy rejected <i>this</i> authenticator,
    /// and the server's message is the only place that says which one would be accepted.
    /// </remarks>
    private static async Task<Exception> RegisterFinishErrorAsync(HttpResponseMessage http, CancellationToken cancellationToken)
    {
        string context = "WebauthnRegisterFinishAsync failed";
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
}
