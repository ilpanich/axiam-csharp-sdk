using System.Net.Http;
using System.Text.Json;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;

namespace Axiam.Sdk;

/// <summary>
/// The CONTRACT.md &#167;14 device authorization grant, &#167;15 token exchange, and &#167;12.7
/// logout helpers.
/// </summary>
/// <remarks>
/// A separate partial so the nine &#167;12.1/&#167;12.2 operations in
/// <c>AxiamClient.Oidc.cs</c> stay readable; every internal it uses
/// (<c>PostOAuth2FormAsync</c>, <c>MapOAuth2ErrorAsync</c>, <c>GetOidcJwksVerifier</c>) is the same
/// one those operations use, so there is no second transport or key-fetching path.
/// </remarks>
public sealed partial class AxiamClient
{
    /// <summary><c>grant_type</c> of the device access-token request (RFC 8628 &#167;3.4).</summary>
    private const string DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code";

    /// <summary>
    /// How the device polling loop sleeps; <see cref="Task.Delay(TimeSpan, CancellationToken)"/> unless a
    /// test substitutes a recorder (CONTRACT.md &#167;14.6, contract 1.64: "a fake clock or a recorded sleep").
    /// </summary>
    internal Func<TimeSpan, CancellationToken, Task> DevicePollDelay { get; set; } = Task.Delay;

    /// <summary>
    /// The clock the device loop measures the <c>expires_in</c> deadline on (&#167;14.2 rule 4): wall time,
    /// so a slow request counts against it as well as a wait does. A test substitutes its own.
    /// </summary>
    internal TimeProvider DevicePollTime { get; set; } = TimeProvider.System;

    /// <summary>
    /// Polling interval used when the authorization response omits <c>interval</c> (RFC 8628
    /// &#167;3.2, &#167;14.2 rule 2). An SDK MUST NOT hard-code a faster floor.
    /// </summary>
    internal const int DefaultDevicePollIntervalSeconds = 5;

    /// <summary>
    /// Seconds added to the polling interval on each <c>slow_down</c> (&#167;14.2 rule 1). The
    /// increase is permanent and cumulative.
    /// </summary>
    internal const int SlowDownIncrementSeconds = 5;

    /// <summary><c>grant_type</c> of an RFC 8693 exchange.</summary>
    private const string TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    /// <summary>
    /// The <c>actor_token_type</c> this SDK sends, and the <c>subject_token_type</c> it sends when
    /// the caller names none — an AXIAM-issued access token (&#167;15.1).
    /// </summary>
    public const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

    /// <summary>
    /// A JWT from a trusted external issuer — the cross-domain exchange of &#167;15.7.
    /// </summary>
    /// <remarks>
    /// Pass it as <see cref="TokenExchangeParams.SubjectTokenType"/> to exchange a partner IdP's
    /// token. AXIAM also accepts <see cref="AccessTokenType"/> for an external issuer, and refuses
    /// refresh and ID token types <b>by name</b>.
    /// </remarks>
    public const string JwtTokenType = "urn:ietf:params:oauth:token-type:jwt";

    /// <summary>
    /// The <c>events</c> member that distinguishes a logout token from an ID token (OIDC
    /// Back-Channel Logout 1.0 &#167;2.4).
    /// </summary>
    private const string BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    /// <summary>
    /// Maximum accepted age for a logout token's <c>iat</c>, in seconds. AXIAM issues them with a
    /// 120 s lifetime; this bound is the same order and stops a token captured from a
    /// mis-configured RP being replayed days later.
    /// </summary>
    private const long MaxLogoutTokenAgeSeconds = 300;

    // ------------------------------------------------------------------
    // §14 Device Authorization Grant (RFC 8628)
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /oauth2/device_authorization</c> (CONTRACT.md &#167;14.1) — starts the device grant
    /// and obtains the code pair.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Client authentication (contract 1.62, &#167;14.1 rule 2).</b> A client built with a
    /// credential sends it here exactly as it does at <c>/oauth2/token</c>: the client secret
    /// as <c>client_secret</c> in the <b>form body</b> - never <c>Authorization: Basic</c>, for
    /// a <c>client_secret_basic</c> registration too (&#167;12.1 rule 3) - or, for a client
    /// configured with a certificate, the certificate on the connection (the mutual-TLS alias
    /// of this endpoint is preferred when discovery advertises one). A client built with no
    /// secret is a <b>public</b> client: it sends <c>client_id</c> and no credential, and this
    /// method never refuses it client-side (the usual device cannot hold a secret). The SDK
    /// sends a credential only when its caller configured one. This SDK has no
    /// <c>private_key_jwt</c> client assertion (&#167;21.8) and so cannot drive a client
    /// registered for it.
    /// </para>
    /// <para>
    /// A failed client authentication is <c>401</c> <c>invalid_client</c>, surfaced as
    /// <see cref="OAuthProtocolError"/> after one request; it never enters the &#167;9 refresh
    /// guard. A client that does not hold the grant is <c>400 unauthorized_client</c>.
    /// </para>
    /// </remarks>
    /// <param name="params">The request arguments.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The code pair the device shows its user.</returns>
    /// <exception cref="AuthError">
    /// When the discovery document advertises no <c>device_authorization_endpoint</c>. The URL is
    /// never built by concatenation onto the issuer: that works against AXIAM and breaks against
    /// every other OP the same code is pointed at.
    /// </exception>
    public async Task<DeviceAuthorization> DeviceAuthorizeAsync(DeviceAuthorizeParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);
        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        // §21.3 rule 2: prefer the mTLS alias when this call presents a client
        // certificate. Null at BOTH levels still means "unsupported" — never a cue to
        // build the URL by concatenation (§14.1).
        string? endpoint = PreferredEndpoint(
            configuration, a => a.DeviceAuthorizationEndpoint, configuration.DeviceAuthorizationEndpoint);
        if (string.IsNullOrEmpty(endpoint))
        {
            throw new AuthError(
                "the authorization server's discovery document advertises no " +
                "device_authorization_endpoint: this server does not support the device grant " +
                "(CONTRACT.md §14.1)");
        }

        Guid tenantId = ResolveOidcTenantId(@params.TenantId);
        var form = new Dictionary<string, string>
        {
            ["client_id"] = RequireOidcClientId(),
        };
        if (!string.IsNullOrEmpty(@params.Scope))
        {
            form["scope"] = @params.Scope;
        }

        // §14.1 rule 2 (contract 1.62): the credential the client was configured with, by the
        // same rule as its token requests - `client_secret` in the form body, only when set.
        // A public client sends none; the mTLS certificate rides the connection.
        AppendOidcClientSecretIfConfigured(form);

        using HttpResponseMessage response = await PostOAuth2FormAsync(endpoint, form, tenantId, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await MapOAuth2ErrorAsync(response, "device authorization request failed", cancellationToken).ConfigureAwait(false);
        }

        DeviceAuthorizationResponseWire wire =
            await ReadOidcJsonAsync<DeviceAuthorizationResponseWire>(response, cancellationToken).ConfigureAwait(false);

        // §14.2 rule 2: the interval comes from the response; only its absence falls back to the
        // RFC default. A server-sent 0 is treated as absent — polling with no delay is never what
        // the server meant.
        int interval = wire.Interval is > 0 ? wire.Interval.Value : DefaultDevicePollIntervalSeconds;

        return new DeviceAuthorization(
            Sensitive<string>.Wrap(wire.DeviceCode),
            wire.UserCode,
            wire.VerificationUri,
            wire.VerificationUriComplete,
            wire.ExpiresIn,
            interval);
    }

    /// <summary>
    /// <c>POST /oauth2/token</c> with the device-code grant (CONTRACT.md &#167;14.1) —
    /// <b>one</b> poll attempt.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The raw single call, so an application driving its own loop (a UI rendering a countdown,
    /// say) can. The five RFC 8628 &#167;3.5 answers surface as <see cref="OAuthProtocolError"/> -
    /// <c>authorization_pending</c> and <c>slow_down</c> included - but a hand-rolled loop does not see
    /// everything <see cref="DeviceLoginAsync"/> does: a <c>429</c> (<c>rate_limit_exceeded</c>) is an
    /// <see cref="OAuthProtocolError"/> whose HTTP status and <c>Retry-After</c> are internal to the SDK, so only
    /// <see cref="DeviceLoginAsync"/> applies &#167;14.2 rule 9 to it (a wait of at least the <c>Retry-After</c>, the
    /// interval unchanged, even when its body says <c>slow_down</c>). A <c>5xx</c> or transport failure is retried
    /// within the call under &#167;16 (at most <see cref="Options.AxiamClientOptions.MaxRetryAttempts"/> requests, and
    /// none when <see cref="Options.AxiamClientOptions.RetryEnabled"/> is off), then surfaced as a
    /// <see cref="NetworkError"/>; a <c>429</c> is never retried inside the call. Most callers want
    /// <see cref="DeviceLoginAsync"/>.
    /// </para>
    /// <para>
    /// <b>Client authentication (contract 1.62, &#167;14.1 rules 2 and 3).</b> Every poll sends
    /// <c>client_id</c>, and, for a client built with a secret, <c>client_secret</c> in the form
    /// body (never <c>Authorization: Basic</c>); a public client sends no credential, and a
    /// client configured with a certificate presents it on the connection. A <c>401</c>
    /// <c>invalid_client</c> (unknown client, failed or missing credential, a credential sent by
    /// a public client, a client that no longer holds the grant, or a bound client's missing
    /// proof or certificate, &#167;14.2 rule 5) is an <see cref="OAuthProtocolError"/> with that
    /// <c>error</c>, raised after one request, never retried and never refreshed. This SDK
    /// generates no DPoP proof (&#167;21.7.3), so it cannot drive a client registered for
    /// sender-constrained DPoP tokens and surfaces that refusal as given.
    /// </para>
    /// </remarks>
    /// <param name="params">The poll arguments.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The issued token set.</returns>
    public Task<OidcTokenSet> DevicePollAsync(DevicePollParams @params, CancellationToken cancellationToken = default) =>
        DevicePollCoreAsync(@params, deadline: null, cancellationToken);

    /// <summary>
    /// One poll, with its §16 retry. <paramref name="deadline"/> is set by <see cref="DeviceLoginAsync"/>: a retry
    /// wait that would reach it is not served, and the typed <c>expired_token</c> of rule 4 is raised instead (the
    /// P10 analogue, C164-36). The deadline never cancels a request already sent, nor the reading of its answer:
    /// the server has redeemed the device code by then, and the tokens are the caller's (C164-40).
    /// </summary>
    private async Task<OidcTokenSet> DevicePollCoreAsync(DevicePollParams @params, DateTimeOffset? deadline, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(@params);
        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        string clientId = RequireOidcClientId();
        Guid tenantId = ResolveOidcTenantId(@params.TenantId);

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = DeviceCodeGrantType,
            ["device_code"] = @params.DeviceCode.Reveal(),
            ["client_id"] = clientId,
        };

        // §14.1 rules 2 and 3 (contract 1.62): `client_id` on every poll (above), and the
        // credential the client was configured with, at the poll as at `device_authorize`.
        AppendOidcClientSecretIfConfigured(form);

        // §14.2 rule 6, §16.2: a 5xx or a transport failure on the poll is retried inside the attempt (at most
        // MaxRetryAttempts in all), and never a 429, which is the loop's rule-9 wait (C164-25). The 200 is
        // parsed outside the retry: the server may already have redeemed the device code. It is also what makes
        // the poll a request the SDK itself re-sends, so it may share the pooled cookie-less connection (C163-20).
        string endpoint = PreferredRequiredEndpoint(configuration, a => a.TokenEndpoint, configuration.TokenEndpoint);
        string body = await RetryPolicy.ExecuteAsync(
            "device_poll",
            _options,
            _telemetry,
            Random.Shared.NextDouble,
            async _ =>
            {
                using HttpResponseMessage response = await PostOAuth2FormAsync(
                    endpoint, form, tenantId, cancellationToken, retryEligible: true).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    throw await MapDevicePollErrorAsync(response, cancellationToken).ConfigureAwait(false);
                }

                return await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            },
            cancellationToken,
            retryable: e => e is not Axiam.Sdk.Management.ValidationError && e.HttpStatus is null or >= 500,
            delay: (wait, ct) => deadline is { } limit && DevicePollTime.GetUtcNow() + wait >= limit
                ? throw ExpiredDeviceAuthorization()
                : Task.Delay(wait, ct)).ConfigureAwait(false);

        TokenResponseWire wire;
        try
        {
            wire = JsonSerializer.Deserialize<TokenResponseWire>(body)
                   ?? throw NetworkError.FromMessage("the device poll response deserialized to null");
        }
        catch (JsonException ex)
        {
            throw NetworkError.FromException(ex, "failed to parse the device poll response");
        }

        // No nonce: the device grant has no authorization request to carry one.
        var expectations = new IdTokenExpectations(configuration.Issuer, clientId, HasNonce: false, Nonce: null, _oidcClockSkewSeconds);
        return await ToTokenSetAsync(wire, configuration, expectations, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The composed &#167;14.3 helper: starts the grant, hands the caller the user code, polls to
    /// completion.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="DeviceLoginParams.OnUserCode"/> is awaited <b>before the first poll</b> —
    /// &#167;14.3 rule 2 requires the caller to have had the chance to display the code before
    /// polling begins, and a device rendering a QR code may need to await a paint. The SDK never
    /// prints it.
    /// </para>
    /// <para>
    /// Polling follows &#167;14.2: the interval comes from the response; <c>slow_down</c> adds
    /// 5&#160;s <b>permanently</b>; <c>authorization_pending</c> loops; <c>access_denied</c> and
    /// <c>expired_token</c> raise distinct errors; polling stops at
    /// <see cref="DeviceAuthorization.ExpiresIn"/> even if the server has not yet said
    /// <c>expired_token</c>. A 5xx or transport failure mid-poll is <b>not</b> terminal (rule 6) —
    /// a server restart must not lose a grant the user has already approved. A <c>429</c>
    /// (whatever its body names) is not terminal either (contract 1.64, rule 9): the loop waits its
    /// <c>Retry-After</c> (a minimum, capped at the deadline), counts the wait as one interval, does
    /// <b>not</b> raise the interval, and polls again.
    /// </para>
    /// </remarks>
    /// <param name="params">The login arguments, including the user-code callback.</param>
    /// <param name="cancellationToken">Cancels the login; observed between polls.</param>
    /// <returns>The issued token set.</returns>
    /// <exception cref="NotSupportedException">
    /// When <see cref="DeviceLoginParams.AdoptAsCredential"/> is set — this port does not implement
    /// adoption, matching <see cref="LoginClientCredentialsAsync"/> (&#167;14.3 rule 4 defers to the
    /// &#167;12.1 MAY).
    /// </exception>
    public async Task<OidcTokenSet> DeviceLoginAsync(DeviceLoginParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);
        ArgumentNullException.ThrowIfNull(@params.OnUserCode);
        if (@params.AdoptAsCredential)
        {
            throw new NotSupportedException(
                "DeviceLoginAsync's AdoptAsCredential is not implemented in this SDK port " +
                "(CONTRACT.md §14.3 rule 4 defers to §12.1's MAY; see CHANGELOG.md).");
        }

        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        DeviceAuthorization authorization = await DeviceAuthorizeAsync(
            new DeviceAuthorizeParams(@params.Scope, @params.TenantId, configuration),
            cancellationToken).ConfigureAwait(false);

        // §14.2 rule 4 (C164-05): the deadline is a point on the clock, taken as the authorization returns,
        // not expires_in minus the waits slept - request time and the user-code callback count too.
        DateTimeOffset deadline = DevicePollTime.GetUtcNow() + TimeSpan.FromSeconds(authorization.ExpiresIn);

        // §14.3 rule 2 — before any polling.
        await @params.OnUserCode(authorization).ConfigureAwait(false);

        int intervalSeconds = authorization.Interval;

        // §14.2 rule 9 (contract 1.64): the wait a `429` on a poll asked for. A minimum on the next
        // wait, which replaces that interval's wait rather than adding to it; the interval itself is
        // not raised.
        TimeSpan retryAfter = TimeSpan.Zero;

        while (true)
        {
            // §14.2 rule 4: the deadline is authoritative. Checking before waiting keeps the SDK
            // from issuing a request that can only be refused, and reports it under the same
            // expired_token code the server would have used - so a caller's branch does not care
            // which side noticed first. A Retry-After past the deadline is capped by it: the
            // same expired_token, with nothing sent after the deadline.
            TimeSpan wait = TimeSpan.FromSeconds(intervalSeconds);
            if (retryAfter > wait)
            {
                wait = retryAfter;
            }

            retryAfter = TimeSpan.Zero;
            if (DevicePollTime.GetUtcNow() + wait >= deadline)
            {
                throw ExpiredDeviceAuthorization();
            }

            await DevicePollDelay(wait, cancellationToken).ConfigureAwait(false);

            try
            {
                return await DevicePollCoreAsync(
                    new DevicePollParams(authorization.DeviceCode, @params.TenantId, configuration),
                    deadline,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OAuthProtocolError e) when (e.Error is "authorization_pending")
            {
                continue;
            }
            catch (OAuthProtocolError e) when (e.HttpStatus == 429 || e.Error is "rate_limit_exceeded")
            {
                // §14.2 rule 9 (contract 1.64, amended): any 429 is this wait, whatever its body names (a
                // `429 slow_down` from a server before 1.1.2 or an intermediary included). Not terminal,
                // and not a slow_down: wait Retry-After (a minimum), count it as this interval, leave the
                // interval alone.
                retryAfter = e.RetryAfter ?? TimeSpan.Zero;
                continue;
            }
            catch (OAuthProtocolError e) when (e.Error is "slow_down")
            {
                // §14.2 rule 1: cumulative, never reset. Only the 400 gets here (rule 9).
                intervalSeconds += SlowDownIncrementSeconds;
                continue;
            }
            catch (NetworkError e)
            {
                // §14.2 rule 6: transport and 5xx failures are not among the five protocol answers
                // and are not terminal. A bodiless 429 is waited out the same way as rule 9's.
                retryAfter = e.HttpStatus == 429 ? e.RetryAfter ?? TimeSpan.Zero : TimeSpan.Zero;
                continue;
            }

            // expired_token / access_denied / invalid_grant fall through uncaught — terminal.
        }
    }

    /// <summary>The typed <c>expired_token</c> of &#167;14.2 rule 4, raised by the client when its own deadline is reached.</summary>
    private static OAuthProtocolError ExpiredDeviceAuthorization() => new(
        "expired_token",
        "the device authorization expired before the user completed it " +
        "(client-side deadline from expires_in; CONTRACT.md §14.2 rule 4)");

    // ------------------------------------------------------------------
    // §15 Token Exchange (RFC 8693)
    // ------------------------------------------------------------------

    /// <summary>
    /// <c>POST /oauth2/token</c> with the RFC 8693 grant (CONTRACT.md &#167;15.1) — exchanges a
    /// token for a <b>narrower</b> one.
    /// </summary>
    /// <remarks>
    /// <para>What this method deliberately does <i>not</i> do:</para>
    /// <list type="bullet">
    ///   <item><b>No default <c>ActorToken</c></b> (&#167;15.2 rule 1). Passing
    ///     <see langword="null"/> asks for <i>impersonation</i>; the SDK will not quietly reuse the
    ///     client's own session token as the actor and turn that into a delegation.</item>
    ///   <item><b>The actor is this client</b> (rule 9). A delegation's <c>ActorToken</c> is the same
    ///     client's own <c>client_credentials</c> token (<see cref="LoginClientCredentialsAsync"/>), which
    ///     the caller obtains and passes; one issued to another client, a console sign-in or a service
    ///     account is answered <c>invalid_request</c> (<c>actor_token was not issued to the exchanging
    ///     client</c>) and raised unchanged, with one request and no rewriting.</item>
    ///   <item><b>No retry or downgrade on <c>unauthorized_client</c></b> (rule 2) — a registration
    ///     fact an operator must fix.</item>
    ///   <item><b>No auto-narrowing on <c>invalid_scope</c></b> (rule 3). The server refuses
    ///     instead of silently narrowing precisely so the caller finds out here.</item>
    ///   <item><b>No adoption</b> (rule 5), and no flag to enable it — a MUST NOT, where
    ///     <see cref="LoginClientCredentialsAsync"/> adoption is a MAY.</item>
    /// </list>
    /// <para>
    /// A cross-tenant subject token answers <c>invalid_grant</c>, identically to an expired one.
    /// The SDK does not try to tell them apart (&#167;15.3): the server collapses them because
    /// distinguishing them is a tenant-enumeration signal.
    /// </para>
    /// </remarks>
    /// <param name="params">The exchange arguments.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The issued, narrower token.</returns>
    /// <exception cref="AuthError">When no client secret is configured — client-side, with no wire call.</exception>
    public async Task<ExchangedToken> TokenExchangeAsync(TokenExchangeParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);
        // §15.1: SubjectTokenType is required and has no default. The record's
        // positional parameter makes omitting it a compile error, but a caller
        // can still pass null or blank through a nullable-oblivious call site —
        // so refuse here, client-side with no wire call, rather than sending
        // …:access_token on their behalf (§15.7).
        if (string.IsNullOrWhiteSpace(@params.SubjectTokenType))
        {
            throw new AuthError(
                "TokenExchangeAsync requires SubjectTokenType (§15.1): pass "
                + "AxiamClient.AccessTokenType for an AXIAM access token, or "
                + "AxiamClient.JwtTokenType for a trusted external issuer's JWT");
        }
        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        string clientSecret = RequireOidcClientSecret(nameof(TokenExchangeAsync));
        Guid tenantId = ResolveOidcTenantId(@params.TenantId);

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["subject_token"] = @params.SubjectToken.Reveal(),
            // Whatever the caller named, verbatim. The subject token is NEVER decoded to pick
            // this (§15.7): which kind of token the caller holds is the caller's to know, and a
            // guess here is the difference between a request that is refused and one that is
            // silently reinterpreted.
            ["subject_token_type"] = @params.SubjectTokenType ?? AccessTokenType,
            ["client_id"] = RequireOidcClientId(),
            ["client_secret"] = clientSecret,
        };
        if (@params.ActorToken is not null)
        {
            form["actor_token"] = @params.ActorToken.Value.Reveal();
            // Sent exactly when actor_token is: RFC 8693 §2.1 requires the pair, and the type alone
            // is a malformed request.
            form["actor_token_type"] = AccessTokenType;
        }
        if (@params.Scopes is { Count: > 0 })
        {
            form["scope"] = string.Join(' ', @params.Scopes);
        }
        if (!string.IsNullOrEmpty(@params.Audience))
        {
            form["audience"] = @params.Audience;
        }
        if (!string.IsNullOrEmpty(@params.Resource))
        {
            form["resource"] = @params.Resource;
        }

        using HttpResponseMessage response = await PostOAuth2FormAsync(
            PreferredRequiredEndpoint(configuration, a => a.TokenEndpoint, configuration.TokenEndpoint),
            form, tenantId, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await MapOAuth2ErrorAsync(response, "token exchange request failed", cancellationToken).ConfigureAwait(false);
        }

        TokenExchangeResponseWire wire =
            await ReadOidcJsonAsync<TokenExchangeResponseWire>(response, cancellationToken).ConfigureAwait(false);

        return new ExchangedToken(
            Sensitive<string>.Wrap(wire.AccessToken),
            wire.IssuedTokenType,
            wire.TokenType,
            wire.ExpiresIn,
            wire.Scope);
    }

    // ------------------------------------------------------------------
    // §12.7 Logout helpers
    // ------------------------------------------------------------------

    /// <summary>
    /// Builds the RP-initiated logout URL to redirect the user agent to (CONTRACT.md
    /// &#167;12.7.2).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Performs <b>no network I/O</b> beyond the discovery fetch the SDK caches anyway, and does
    /// <b>not</b> clear this client's own session: whether the local session ends is the
    /// application's decision — a backend holding a service-account session must not lose it
    /// because a <i>user</i> logged out.
    /// </para>
    /// <para>
    /// <c>end_session_endpoint</c> is read from discovery and never synthesised from the issuer
    /// (rule 1). <see cref="LogoutUrlParams.PostLogoutRedirectUri"/> is passed through
    /// <b>unvalidated against any local list</b> (rule 3): the allow-list lives in the client's
    /// server-side registration, and a client-side copy would drift and reject a URI an operator
    /// had just registered.
    /// </para>
    /// </remarks>
    /// <param name="params">The logout arguments.</param>
    /// <param name="cancellationToken">Cancels the discovery fetch, if one is needed.</param>
    /// <returns>The absolute logout URL.</returns>
    /// <exception cref="AuthError">When the discovery document advertises no <c>end_session_endpoint</c>.</exception>
    public async Task<string> LogoutUrlAsync(LogoutUrlParams @params, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(@params);
        OidcConfiguration configuration = await ResolveOidcConfigurationAsync(@params.Configuration, cancellationToken).ConfigureAwait(false);
        string? endpoint = configuration.EndSessionEndpoint;
        if (string.IsNullOrEmpty(endpoint))
        {
            throw new AuthError(
                "the authorization server's discovery document advertises no end_session_endpoint: " +
                "this server does not support RP-initiated logout (CONTRACT.md §12.7.2 rule 1)");
        }

        var builder = new UriBuilder(endpoint);
        var query = System.Web.HttpUtility.ParseQueryString(builder.Query);
        query["id_token_hint"] = @params.IdToken.Reveal();
        if (!string.IsNullOrEmpty(@params.PostLogoutRedirectUri))
        {
            query["post_logout_redirect_uri"] = @params.PostLogoutRedirectUri;
        }
        if (!string.IsNullOrEmpty(@params.State))
        {
            query["state"] = @params.State;
        }
        builder.Query = query.ToString();
        return builder.Uri.ToString();
    }

    /// <summary>
    /// Verifies a back-channel logout token the OP POSTed to this application's
    /// <c>backchannel_logout_uri</c> (CONTRACT.md &#167;12.7.3).
    /// </summary>
    /// <remarks>
    /// <para>Every check exists because skipping it has a name:</para>
    /// <list type="number">
    ///   <item><b>Signature</b>, through the same &#167;12.4 JWKS verifier the ID-token path uses —
    ///     no second key-fetching path — which already pins EdDSA and requires a <c>kid</c>, so
    ///     rotation cannot be defeated by omitting it.</item>
    ///   <item><b><c>iss</c>/<c>aud</c></b>: a token minted for another RP is not accepted here.</item>
    ///   <item><b><c>events</c> carries the back-channel-logout key.</b> This is what distinguishes
    ///     a logout token from an ID token; skipping it means accepting a replayed ID token as a
    ///     logout instruction.</item>
    ///   <item><b><c>nonce</c> is absent.</b> Back-Channel Logout 1.0 &#167;2.4 forbids it, and its
    ///     presence is the documented signature of an ID token being replayed. Rejected, not
    ///     ignored.</item>
    ///   <item><b>At least one of <c>sid</c>/<c>sub</c></b> — a token naming neither identifies
    ///     nothing.</item>
    ///   <item><b><c>exp</c> in the future, <c>iat</c> recent.</b></item>
    /// </list>
    /// </remarks>
    /// <param name="logoutToken">The compact JWS the OP posted.</param>
    /// <param name="configuration">A pre-fetched discovery document, or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancels the discovery/JWKS fetches, if needed.</param>
    /// <returns>
    /// The <c>sid</c>/<c>sub</c>/<c>jti</c> the token names — never a bare <see cref="bool"/>,
    /// because the RP has to know <i>which</i> session to end. <b>Dedup on <c>jti</c> yourself</b>:
    /// delivery is at-least-once, and an SDK-side guard would have no durable store and would
    /// silently drop a real second logout after a restart.
    /// </returns>
    /// <exception cref="AuthError">On any failed check.</exception>
    public async Task<VerifiedLogoutToken> VerifyLogoutTokenAsync(
        string logoutToken,
        OidcConfiguration? configuration = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(logoutToken);
        OidcConfiguration config = await ResolveOidcConfigurationAsync(configuration, cancellationToken).ConfigureAwait(false);

        JwksVerifier verifier = GetOidcJwksVerifier(config.JwksUri);
        (JsonElement? payload, OidcSignatureFailure? failure) =
            await verifier.VerifyOidcIdTokenSignatureAsync(logoutToken, cancellationToken).ConfigureAwait(false);
        if (failure is not null)
        {
            // The mapped error never embeds the token: an unverifiable logout token is exactly the
            // case a naive implementation logs verbatim.
            throw IdTokenValidator.SignatureFailureToAuthError(failure.Value);
        }

        JsonElement claims = payload!.Value;

        if (StringClaim(claims, "iss") != config.Issuer)
        {
            throw new AuthError("logout token issuer does not match the discovery document");
        }
        if (!AudienceContains(claims, RequireOidcClientId()))
        {
            throw new AuthError("logout token audience does not match this client_id");
        }

        // Without this check the whole method is an elaborate way to accept an ID token.
        if (!HasBackchannelLogoutEvent(claims))
        {
            throw new AuthError(
                "not a logout token: the events claim does not carry " + BackchannelLogoutEvent);
        }

        if (claims.TryGetProperty("nonce", out _))
        {
            throw new AuthError(
                "logout token carries a nonce, which Back-Channel Logout 1.0 §2.4 forbids: " +
                "this is an ID token being replayed as a logout token");
        }

        string? sid = StringClaim(claims, "sid");
        string? sub = StringClaim(claims, "sub");
        if (sid is null && sub is null)
        {
            throw new AuthError("logout token names neither sid nor sub, so it identifies no session");
        }

        long nowSec = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long skew = _oidcClockSkewSeconds;
        long? exp = NumericClaim(claims, "exp");
        long? iat = NumericClaim(claims, "iat");
        if (exp is null || exp.Value + skew < nowSec)
        {
            throw new AuthError("logout token has expired");
        }
        if (iat is null || iat.Value - skew > nowSec)
        {
            throw new AuthError("logout token was issued in the future");
        }
        if (nowSec - iat.Value > MaxLogoutTokenAgeSeconds + skew)
        {
            throw new AuthError("logout token is too old to be a live delivery");
        }

        string? jti = StringClaim(claims, "jti");
        if (string.IsNullOrEmpty(jti))
        {
            throw new AuthError("logout token carries no jti, so the RP cannot dedup redeliveries");
        }

        return new VerifiedLogoutToken(sid, sub, jti);
    }

    private static string? StringClaim(JsonElement claims, string name) =>
        claims.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static long? NumericClaim(JsonElement claims, string name) =>
        claims.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.Number
            ? value.GetInt64()
            : null;

    /// <summary>
    /// <c>aud</c> may be a single string or an array (RFC 7519 &#167;4.1.3); both must be honoured,
    /// because rejecting the array form would refuse tokens the spec permits.
    /// </summary>
    private static bool AudienceContains(JsonElement claims, string clientId)
    {
        if (!claims.TryGetProperty("aud", out JsonElement aud))
        {
            return false;
        }
        return aud.ValueKind switch
        {
            JsonValueKind.String => aud.GetString() == clientId,
            JsonValueKind.Array => aud.EnumerateArray()
                .Any(item => item.ValueKind == JsonValueKind.String && item.GetString() == clientId),
            _ => false,
        };
    }

    /// <summary>
    /// Whether <c>events</c> carries the back-channel-logout key mapped to a JSON <b>object</b>.
    /// </summary>
    /// <remarks>
    /// The object-ness matters: Back-Channel Logout 1.0 &#167;2.4 specifies a JSON object (normally
    /// empty), and accepting <c>null</c> or a string would let a near-miss token through on a
    /// technicality.
    /// </remarks>
    private static bool HasBackchannelLogoutEvent(JsonElement claims) =>
        claims.TryGetProperty("events", out JsonElement events)
        && events.ValueKind == JsonValueKind.Object
        && events.TryGetProperty(BackchannelLogoutEvent, out JsonElement entry)
        && entry.ValueKind == JsonValueKind.Object;
}
