using System.Net;
using System.Net.Http;
using System.Text.Json;
using Axiam.Sdk.Account;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;

namespace Axiam.Sdk;

// CONTRACT.md §25 — account lifecycle and MFA enrolment: the calls a user makes about
// their own account, none of which is administration.
public sealed partial class AxiamClient
{
    private const string MfaEnrollPath = "/api/v1/auth/mfa/enroll";
    private const string MfaConfirmPath = "/api/v1/auth/mfa/confirm";
    private const string MfaSetupEnrollPath = "/api/v1/auth/mfa/setup/enroll";
    private const string MfaSetupConfirmPath = "/api/v1/auth/mfa/setup/confirm";
    private const string VerifyEmailPath = "/api/v1/auth/verify-email";
    private const string ResendVerificationPath = "/api/v1/auth/resend-verification";
    private const string ResendOwnVerificationPath = "/api/v1/users/me/resend-verification";
    private const string ResetPath = "/api/v1/auth/reset";
    private const string ResetContextPath = "/api/v1/auth/reset/context";
    private const string ResetConfirmPath = "/api/v1/auth/reset/confirm";

    /// <summary>
    /// <c>POST /api/v1/auth/mfa/enroll</c> (CONTRACT.md &#167;25.1) — start voluntary TOTP
    /// enrolment for the signed-in user.
    /// </summary>
    /// <remarks>
    /// Changes nothing about the current session. In particular it does <b>not</b> clear
    /// the &#167;17 decision memo: the subject has not changed, and discarding a warm memo
    /// on an unrelated profile action costs a round trip on every check that follows
    /// (&#167;25.2 rule 3).
    /// </remarks>
    public async Task<MfaEnrollment> MfaEnrollAsync(CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        using HttpResponseMessage http = await PostJsonAsync(
            MfaEnrollPath, new Dictionary<string, object?>(), cancellationToken).ConfigureAwait(false);
        return await ReadMfaEnrollmentAsync(http, nameof(MfaEnrollAsync), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /api/v1/auth/mfa/confirm</c> (CONTRACT.md &#167;25.1) — activate the factor
    /// <see cref="MfaEnrollAsync"/> offered. Returns whether MFA is now enabled.
    /// </summary>
    public async Task<bool> MfaConfirmAsync(string totpCode, CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(totpCode);

        var body = new Dictionary<string, object?> { ["totp_code"] = totpCode };
        using HttpResponseMessage http = await PostJsonAsync(MfaConfirmPath, body, cancellationToken).ConfigureAwait(false);
        if (http.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(http, "MfaConfirmAsync failed");
        }

        JsonElement wire = await ReadJsonAsync(http, cancellationToken).ConfigureAwait(false);
        return wire.TryGetProperty("mfa_enabled", out JsonElement enabled) &&
               enabled.ValueKind == JsonValueKind.True;
    }

    /// <summary>
    /// <c>POST /api/v1/auth/mfa/setup/enroll</c> (CONTRACT.md &#167;25.1) — start the
    /// enrolment a <see cref="LoginAsync"/> demanded.
    /// </summary>
    /// <remarks>
    /// Reached when <c>LoginAsync</c> returns <see cref="LoginResult.MfaSetupRequired"/>:
    /// the tenant requires MFA and this account has none. There is no session yet — the
    /// setup token <i>is</i> the credential.
    /// </remarks>
    public async Task<MfaEnrollment> MfaSetupEnrollAsync(Sensitive<string> setupToken, CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        var body = new Dictionary<string, object?> { ["setup_token"] = setupToken.Reveal() };
        using HttpResponseMessage http = await PostJsonAsync(MfaSetupEnrollPath, body, cancellationToken).ConfigureAwait(false);
        return await ReadMfaEnrollmentAsync(http, nameof(MfaSetupEnrollAsync), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /api/v1/auth/mfa/setup/confirm</c> (CONTRACT.md &#167;25.1) — finish forced
    /// enrolment and, with it, the login that was interrupted.
    /// </summary>
    /// <remarks>
    /// Adopts credentials exactly as <see cref="LoginAsync"/> does, because it <i>is</i>
    /// the completion of a login (&#167;25.2 rule 2).
    /// </remarks>
    public async Task<LoginResult> MfaSetupConfirmAsync(
        Sensitive<string> setupToken,
        string totpCode,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        OnCredentialChange();
        ArgumentException.ThrowIfNullOrWhiteSpace(totpCode);

        var body = new Dictionary<string, object?>
        {
            ["setup_token"] = setupToken.Reveal(),
            ["totp_code"] = totpCode,
        };
        using HttpResponseMessage http = await PostJsonAsync(MfaSetupConfirmPath, body, cancellationToken).ConfigureAwait(false);
        if (http.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(http, "MfaSetupConfirmAsync failed");
        }
        return new LoginResult(
            false,
            OrganizationLevel: await OrganizationLevelOfAsync(http, cancellationToken)
                .ConfigureAwait(false));
    }

    /// <summary>
    /// <c>POST /api/v1/auth/verify-email</c> (CONTRACT.md &#167;25.1).
    /// </summary>
    /// <remarks>
    /// Unauthenticated: a user whose address is unverified may have no session at all.
    /// <paramref name="tenantId"/> is a <b>body</b> field here — this is not an
    /// <c>/oauth2</c> endpoint, so &#167;12.1 rule 2's query-parameter convention does not
    /// reach it.
    /// </remarks>
    /// <param name="token">
    /// The token from the verification mail. Build it with
    /// <see cref="Sensitive{T}.Wrap"/>: a caller holding it as a bare string out of a
    /// mail link is the expected case, and wrapping a value can never leak it.
    /// </param>
    /// <param name="tenantId">The tenant the account belongs to.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async Task VerifyEmailAsync(Sensitive<string> token, Guid tenantId, CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        var body = new Dictionary<string, object?>
        {
            ["token"] = token.Reveal(),
            ["tenant_id"] = tenantId.ToString(),
        };
        await PostExpectingNoContentAsync(VerifyEmailPath, body, nameof(VerifyEmailAsync), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /api/v1/auth/resend-verification</c> (CONTRACT.md &#167;25.1) — the
    /// <b>unauthenticated</b> resend, for a caller with no session.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Returns normally whatever the outcome.</b> The address may not exist, may already
    /// be verified, or may be over the daily limit, and this answers identically in all of
    /// them, because it takes an address from an anonymous caller and anything else is an
    /// oracle for which addresses have accounts (&#167;25.7).
    /// </para>
    /// <para>
    /// A caller that <i>is</i> signed in wants <see cref="ResendOwnVerificationAsync"/>,
    /// which says which of those happened. Do not reach for this one because it is the name
    /// you already knew.
    /// </para>
    /// </remarks>
    /// <param name="email">The address to resend to.</param>
    /// <param name="tenantId">The tenant the account belongs to.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async Task ResendVerificationAsync(string email, Guid tenantId, CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        var body = new Dictionary<string, object?>
        {
            ["email"] = email,
            ["tenant_id"] = tenantId.ToString(),
        };
        await PostExpectingNoContentAsync(ResendVerificationPath, body, nameof(ResendVerificationAsync), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /api/v1/users/me/resend-verification</c> (CONTRACT.md &#167;25.1,
    /// &#167;25.7) — resends the <b>signed-in caller's own</b> verification mail, and says
    /// what happened.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Takes no address. The server reads it off the caller's own record, and this
    /// signature deliberately offers no way to name a different one: a parameter here would
    /// let an authenticated session mail an arbitrary address.
    /// </para>
    /// <para>
    /// Unlike <see cref="ResendVerificationAsync"/> this reports the outcome, because the
    /// caller is signed in to the account it is asking about and none of the outcomes tells
    /// it anything it did not already know: it returns when a token was minted and the mail
    /// <b>enqueued</b>; throws <c>AuthzError</c> on <c>409</c> (already verified, or the
    /// account is in a state that must not be sent a live token); and throws
    /// <c>NetworkError</c> on <c>429</c> (the daily resend limit). Delivery is asynchronous
    /// and can still fail at the provider — a queue that accepts everything in front of one
    /// that rejects it looks exactly like this succeeding.
    /// </para>
    /// <para>
    /// &#167;25.7 rule 2 forbids falling back to the unauthenticated endpoint on either of
    /// those, and this SDK does not: the fallback would turn both failures back into a
    /// normal return and restore the bug this operation exists to fix, with an extra
    /// round-trip.
    /// </para>
    /// </remarks>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async Task ResendOwnVerificationAsync(CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        await PostExpectingNoContentAsync(
            ResendOwnVerificationPath,
            new Dictionary<string, object?>(),
            nameof(ResendOwnVerificationAsync),
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /api/v1/auth/reset</c> (CONTRACT.md &#167;25.1) — ask for a reset mail.
    /// </summary>
    /// <remarks>
    /// <b>Returns normally whether or not the address exists</b>, and this SDK exposes no
    /// way to tell the two apart. That is not an omission to improve on: a client that
    /// surfaced a "no such user" state — even one inferred from timing — would turn the
    /// endpoint into the account-enumeration oracle its uniform response exists to prevent
    /// (&#167;25.4).
    /// </remarks>
    public async Task RequestPasswordResetAsync(PasswordResetRequest request, CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Email);

        var body = new Dictionary<string, object?> { ["email"] = request.Email };
        if ((request.OrgSlug ?? _tenant.OrgSlug) is { } orgSlug)
        {
            body["org_slug"] = orgSlug;
        }
        if (request.TenantId is Guid tenantGuid)
        {
            body["tenant_id"] = tenantGuid.ToString();
        }
        else if (request.TenantSlug is { } tenantSlug)
        {
            body["tenant_slug"] = tenantSlug;
        }
        else if (Guid.TryParse(_tenant.TenantId, out Guid ownTenant))
        {
            body["tenant_id"] = ownTenant.ToString();
        }
        else
        {
            body["tenant_slug"] = _tenant.TenantId;
        }

        await PostExpectingNoContentAsync(ResetPath, body, nameof(RequestPasswordResetAsync), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>GET /api/v1/auth/reset/context</c> (CONTRACT.md &#167;25.1) — the OPAQUE policy
    /// for the account a reset token belongs to.
    /// </summary>
    /// <remarks>
    /// Call this before <see cref="ConfirmPasswordResetAsync"/> on any tenant that might
    /// have &#167;23 enabled: the client has to build a registration record, and building
    /// one needs parameters it cannot know before it has a token to ask with. Sending a
    /// plaintext password to a tenant in <c>opaque_mode: required</c> is refused, and
    /// refused late (&#167;25.4 rule 1).
    /// <para>
    /// A <c>404</c> means unknown, expired <b>or</b> already-consumed, deliberately without
    /// distinguishing them; this SDK does not distinguish them either (&#167;25.4 rule 3).
    /// </para>
    /// </remarks>
    /// <param name="token">The token from the reset mail; wrap it with
    /// <see cref="Sensitive{T}.Wrap"/>.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async Task<PasswordResetContext> PasswordResetContextAsync(
        Sensitive<string> token,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();

        // Uri.EscapeDataString, never string concatenation of a raw token: a token spliced
        // onto "?token=" unescaped can end the query early, and one escaped into the PATH
        // 404s in a way that reads exactly like an expired token.
        string path = $"{ResetContextPath}?token={Uri.EscapeDataString(token.Reveal())}";

        HttpResponseMessage http;
        try
        {
            http = await _httpClient.GetAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw NetworkError.FromException(ex, "GET /api/v1/auth/reset/context failed");
        }
        catch (OperationCanceledException ex) when (ex.CancellationToken != cancellationToken)
        {
            throw NetworkError.FromException(ex, "GET /api/v1/auth/reset/context timed out");
        }

        using (http)
        {
            if (http.StatusCode != HttpStatusCode.OK)
            {
                throw ErrorMapper.FromHttpResponse(http, "PasswordResetContextAsync failed");
            }

            JsonElement wire = await ReadJsonAsync(http, cancellationToken).ConfigureAwait(false);
            return new PasswordResetContext(
                wire.TryGetProperty("opaque", out JsonElement opaque) && opaque.ValueKind == JsonValueKind.Object
                    ? opaque.Clone()
                    : null);
        }
    }

    /// <summary>
    /// <c>POST /api/v1/auth/reset/confirm</c> (CONTRACT.md &#167;25.1) — set the new
    /// password.
    /// </summary>
    public async Task ConfirmPasswordResetAsync(
        PasswordResetConfirmation confirmation,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        ArgumentNullException.ThrowIfNull(confirmation);

        var body = new Dictionary<string, object?>
        {
            ["token"] = confirmation.Token.Reveal(),
            ["new_password"] = confirmation.NewPassword.Reveal(),
            ["tenant_id"] = confirmation.TenantId.ToString(),
        };
        if (confirmation.Opaque is JsonElement opaque)
        {
            body["opaque"] = opaque;
        }

        await PostExpectingNoContentAsync(ResetConfirmPath, body, nameof(ConfirmPasswordResetAsync), cancellationToken).ConfigureAwait(false);
    }

    private static async Task<MfaEnrollment> ReadMfaEnrollmentAsync(
        HttpResponseMessage http,
        string operation,
        CancellationToken cancellationToken)
    {
        if (http.StatusCode != HttpStatusCode.OK)
        {
            throw ErrorMapper.FromHttpResponse(http, $"{operation} failed");
        }

        JsonElement wire = await ReadJsonAsync(http, cancellationToken).ConfigureAwait(false);
        return new MfaEnrollment(
            Sensitive.Of(ReadString(wire, "secret_base32")),
            Sensitive.Of(ReadString(wire, "totp_uri")));
    }

    private async Task PostExpectingNoContentAsync(
        string path,
        IDictionary<string, object?> body,
        string operation,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage http = await PostJsonAsync(path, body, cancellationToken).ConfigureAwait(false);
        if (http.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.Accepted or HttpStatusCode.NoContent))
        {
            throw ErrorMapper.FromHttpResponse(http, $"{operation} failed");
        }
    }
}
