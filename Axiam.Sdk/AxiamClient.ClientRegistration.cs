using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Rest;

namespace Axiam.Sdk;

/// <content>
/// RFC 7592 client configuration — CONTRACT.md &#167;28.12 (contract 1.53) — and the
/// session-free transport it, and the &#167;32.7 SSF receiver, share.
/// </content>
public sealed partial class AxiamClient
{
    private readonly object _sessionlessLock = new();
    private HttpClient? _sessionlessHttpClient;

    /// <summary>
    /// A transport that carries <b>no</b> SDK session: no cookie jar, no
    /// <see cref="AxiamHttpMessageHandler"/> (so no session bearer, no CSRF echo, no &#167;5
    /// headers and no &#167;9 refresh), and no redirect following. It shares &#167;6/&#167;6.1's
    /// TLS policy — trust anchors and client certificate — with the session transport.
    /// </summary>
    /// <remarks>
    /// Used where a request carries a credential that is <i>not</i> the SDK's session and
    /// must not be mixed with it: the RFC 7592 registration access token (&#167;28.12.2 rule
    /// 3) and an SSF receiver's poll token (&#167;32.7). Built on first use, per handle, and
    /// disposed with it. Under <c>CreateForTesting</c> it bottoms out at the same fake
    /// transport as everything else, so a test sees exactly what would have gone on the wire.
    /// </remarks>
    internal HttpClient SessionlessHttpClient
    {
        get
        {
            EnsureNotDisposed();
            lock (_sessionlessLock)
            {
                if (_sessionlessHttpClient is null)
                {
                    HttpMessageHandler handler;
                    if (_transportOverride is not null)
                    {
                        handler = _transportOverride;
                    }
                    else
                    {
                        HttpClientHandler primary = AxiamHttpClientFactory.CreatePrimaryHandler(
                            _options.CustomCaPem, _options.ClientCertificatePem, _options.ClientKeyPem);
                        // No cookie jar at all: nothing is read from one, and nothing a
                        // response sets is kept for a later request.
                        primary.UseCookies = false;
                        handler = primary;
                    }

                    _sessionlessHttpClient = new HttpClient(handler, disposeHandler: _transportOverride is null)
                    {
                        Timeout = _options.RequestTimeout,
                    };
                }

                return _sessionlessHttpClient;
            }
        }
    }

    private void DisposeSessionless()
    {
        lock (_sessionlessLock)
        {
            _sessionlessHttpClient?.Dispose();
            _sessionlessHttpClient = null;
        }
    }

    /// <summary>
    /// <c>GET registration_client_uri</c> (RFC 7592 &#167;2.1, CONTRACT.md &#167;28.12) —
    /// reads this client's own registration.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The result carries neither the token nor the client secret (the server never returns
    /// them on a read), but it carries every member an update needs: the usual update is
    /// "read, change a member with a <c>with</c>-expression, update".
    /// </para>
    /// <para>
    /// The request carries <c>Authorization: Bearer &lt;token&gt;</c> and nothing of this
    /// client's session; a <c>401</c> never refreshes the session (&#167;28.12.2 rule 3).
    /// Retried per &#167;16 on a transport failure, <c>5xx</c>, <c>408</c> or <c>429</c> only —
    /// never on another <c>4xx</c>.
    /// </para>
    /// </remarks>
    /// <param name="registrationClientUri">
    /// The <c>registration_client_uri</c> the registration returned, used verbatim (query
    /// included). It must be at this client's configured AXIAM origin.
    /// </param>
    /// <param name="registrationAccessToken">The registration access token.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The registration.</returns>
    /// <exception cref="ValidationError">
    /// The URI is not at this client's origin, or is <c>http</c> against a non-loopback base
    /// URL — raised before any request (&#167;28.12.2 rule 1).
    /// </exception>
    /// <exception cref="OAuthProtocolError">The server answered an error object (e.g. <c>invalid_token</c>).</exception>
    public async Task<ClientRegistration> ReadClientRegistrationAsync(
        string registrationClientUri,
        Sensitive<string> registrationAccessToken,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        Uri uri = CheckRegistrationUri(registrationClientUri, "ReadClientRegistrationAsync");
        return await RetryPolicy.ExecuteAsync(
            "read_client_registration",
            _options,
            _telemetry,
            Random.Shared.NextDouble,
            async _ =>
            {
                using HttpResponseMessage response = await SendRegistrationAsync(
                    HttpMethod.Get, uri, registrationAccessToken, body: null, "ReadClientRegistrationAsync", cancellationToken)
                    .ConfigureAwait(false);
                return await DecodeRegistrationAsync(response, "ReadClientRegistrationAsync", cancellationToken)
                    .ConfigureAwait(false);
            },
            cancellationToken,
            retryable: RetryPolicy.IsTransient).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>PUT registration_client_uri</c> (RFC 7592 &#167;2.2, CONTRACT.md &#167;28.12) —
    /// <b>replaces</b> this client's registration and returns it with a <b>rotated</b>
    /// registration access token.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <paramref name="metadata"/> is the <b>whole</b> registration: a member it omits is a
    /// member the server deletes. Start from <see cref="ReadClientRegistrationAsync"/>'s
    /// result, which carries every member (<c>jwks</c> / <c>jwks_uri</c> and unknown members
    /// in <see cref="ClientRegistration.Extra"/> included), and change what you mean to change.
    /// The SDK sets <c>client_id</c> to <see cref="ClientRegistration.ClientId"/> and never
    /// sends <c>registration_access_token</c>, <c>registration_client_uri</c>,
    /// <c>client_secret_expires_at</c>, <c>client_id_issued_at</c> or <c>client_secret</c>.
    /// </para>
    /// <para>
    /// <b>Persist the returned <see cref="ClientRegistration.RegistrationAccessToken"/>
    /// before doing anything else.</b> From the moment the server answers it is the only valid
    /// token: the one you presented is dead for every operation (&#167;28.12.2 rule 5).
    /// </para>
    /// <para>
    /// <b>Never retried</b> — not on a transport error, not on a <c>5xx</c>. An update that
    /// reached the server and lost its response has already rotated the token; repeating it
    /// with the old one is a <c>401</c> that locks you out of your own registration. On a lost
    /// answer, read the registration with the token you hold: a <c>401</c> means the update
    /// landed.
    /// </para>
    /// </remarks>
    /// <param name="registrationClientUri">The <c>registration_client_uri</c>, used verbatim.</param>
    /// <param name="registrationAccessToken">The current registration access token.</param>
    /// <param name="metadata">The whole registration to store.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The stored registration, carrying the rotated token.</returns>
    /// <exception cref="ValidationError">The URI fails &#167;28.12.2 rule 1 — before any request.</exception>
    /// <exception cref="OAuthProtocolError">The server answered an error object (e.g. <c>invalid_client_metadata</c>).</exception>
    public async Task<ClientRegistration> UpdateClientRegistrationAsync(
        string registrationClientUri,
        Sensitive<string> registrationAccessToken,
        ClientRegistration metadata,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        EnsureNotDisposed();
        Uri uri = CheckRegistrationUri(registrationClientUri, "UpdateClientRegistrationAsync");
        using HttpResponseMessage response = await SendRegistrationAsync(
            HttpMethod.Put, uri, registrationAccessToken, metadata.ToUpdateBody(), "UpdateClientRegistrationAsync", cancellationToken)
            .ConfigureAwait(false);
        return await DecodeRegistrationAsync(response, "UpdateClientRegistrationAsync", cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// <c>DELETE registration_client_uri</c> (RFC 7592 &#167;2.3, CONTRACT.md &#167;28.12) —
    /// deletes this client's registration. A <c>204</c> completes normally.
    /// </summary>
    /// <remarks>
    /// <b>Never retried</b>: a retry after a lost <c>204</c> would read <c>401</c> and report a
    /// successful deletion as a failure (&#167;28.12.2 rule 5).
    /// </remarks>
    /// <param name="registrationClientUri">The <c>registration_client_uri</c>, used verbatim.</param>
    /// <param name="registrationAccessToken">The registration access token.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>A task that completes when the server has answered.</returns>
    /// <exception cref="ValidationError">The URI fails &#167;28.12.2 rule 1 — before any request.</exception>
    /// <exception cref="OAuthProtocolError">The server answered an error object (e.g. <c>invalid_token</c>).</exception>
    public async Task DeleteClientRegistrationAsync(
        string registrationClientUri,
        Sensitive<string> registrationAccessToken,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        Uri uri = CheckRegistrationUri(registrationClientUri, "DeleteClientRegistrationAsync");
        using HttpResponseMessage response = await SendRegistrationAsync(
            HttpMethod.Delete, uri, registrationAccessToken, body: null, "DeleteClientRegistrationAsync", cancellationToken)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await MapOAuth2ErrorAnyStatusAsync(response, "DeleteClientRegistrationAsync failed", cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// &#167;28.12.2 rule 1: accept <paramref name="registrationClientUri"/> only at the
    /// configured AXIAM origin. The refusal names no part of the URI — it is caller input, and
    /// an error message is the thing most often logged.
    /// </summary>
    private Uri CheckRegistrationUri(string registrationClientUri, string operation)
    {
        ValidationError Refuse(string why) => new(
            $"{operation}: registration_client_uri {why} (CONTRACT.md §28.12.2 rule 1); no request was sent",
            new[] { new FieldError("registration_client_uri", why) });

        if (string.IsNullOrEmpty(registrationClientUri) ||
            !Uri.TryCreate(registrationClientUri, UriKind.Absolute, out Uri? parsed))
        {
            throw Refuse("is not an absolute URL");
        }

        if (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp)
        {
            throw Refuse("must be an https URL");
        }

        if (!IsSameOrigin(parsed, _baseUrl))
        {
            throw Refuse(
                "is not at the configured AXIAM origin (scheme, host and port must match the client's base URL)");
        }

        if (parsed.Scheme == Uri.UriSchemeHttp && !IsLoopbackHost(_baseUrl))
        {
            throw Refuse("must be https unless the base URL is http on a loopback host");
        }

        return parsed;
    }

    /// <summary>Scheme, lower-cased host and port (the scheme's default when absent) all equal.</summary>
    internal static bool IsSameOrigin(Uri a, Uri b) =>
        string.Equals(a.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(a.IdnHost, b.IdnHost, StringComparison.OrdinalIgnoreCase)
        && a.Port == b.Port;

    /// <summary><c>localhost</c>, <c>127.0.0.1</c> or <c>::1</c>.</summary>
    internal static bool IsLoopbackHost(Uri uri)
    {
        string host = uri.IdnHost.Trim('[', ']');
        return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
               || host == "127.0.0.1"
               || host == "::1";
    }

    private async Task<HttpResponseMessage> SendRegistrationAsync(
        HttpMethod method,
        Uri uri,
        Sensitive<string> token,
        string? body,
        string operation,
        CancellationToken cancellationToken)
    {
        // Not `using`: HttpClient.SendAsync disposes neither the request nor its content, and
        // the content of a short-lived request needs no deterministic disposal.
        var request = new HttpRequestMessage(method, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Reveal());
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        try
        {
            return await SessionlessHttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw NetworkError.FromException(ex, $"{operation}: request failed");
        }
        catch (OperationCanceledException ex) when (ex.CancellationToken != cancellationToken)
        {
            throw NetworkError.FromException(ex, $"{operation}: request timed out");
        }
    }

    private static async Task<ClientRegistration> DecodeRegistrationAsync(
        HttpResponseMessage response, string operation, CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw await MapOAuth2ErrorAnyStatusAsync(response, $"{operation} failed", cancellationToken)
                .ConfigureAwait(false);
        }

        string text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using JsonDocument document = JsonDocument.Parse(text);
            return ClientRegistration.FromElement(document.RootElement);
        }
        catch (JsonException)
        {
            throw NetworkError.FromMessage($"{operation}: could not parse the server's response");
        }
    }

    /// <summary>
    /// CONTRACT.md &#167;2's <c>/oauth2/*</c> row as contract 1.12 states it: a response
    /// whose body is an error object with a non-empty <c>error</c> member is an
    /// <see cref="OAuthProtocolError"/> <b>at any status</b> (a <c>401</c>, a <c>429</c>
    /// <c>rate_limit_exceeded</c> included), with <c>error_description</c> optional; anything
    /// else maps by status through <see cref="ErrorMapper"/>.
    /// </summary>
    /// <remarks>
    /// Used by the operations contract 1.53+ added (&#167;28.12.3, &#167;33.4). The older
    /// <see cref="MapOAuth2ErrorAsync"/> keeps its 400/401 scope for the &#167;12/&#167;14/
    /// &#167;15 callers whose tests pin it.
    /// </remarks>
    internal static async Task<Exception> MapOAuth2ErrorAnyStatusAsync(
        HttpResponseMessage response, string context, CancellationToken cancellationToken)
    {
        string body;
        try
        {
            body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException)
        {
            body = string.Empty;
        }

        if (TryReadOAuth2Error(body, out string? error, out string? description))
        {
            return new OAuthProtocolError(error!, description ?? string.Empty);
        }

        return ErrorMapper.FromHttpResponse(response, context);
    }

    /// <summary>Whether <paramref name="body"/> is an object with a non-empty string <c>error</c>.</summary>
    internal static bool TryReadOAuth2Error(string body, out string? error, out string? description)
    {
        error = null;
        description = null;
        if (string.IsNullOrWhiteSpace(body))
        {
            return false;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(body);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("error", out JsonElement errorEl) ||
                errorEl.ValueKind != JsonValueKind.String ||
                string.IsNullOrEmpty(errorEl.GetString()))
            {
                return false;
            }

            error = errorEl.GetString();
            if (root.TryGetProperty("error_description", out JsonElement descEl) &&
                descEl.ValueKind == JsonValueKind.String)
            {
                description = descEl.GetString();
            }

            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
