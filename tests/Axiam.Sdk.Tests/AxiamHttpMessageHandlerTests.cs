using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Rest;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Unit-level coverage for <see cref="AxiamHttpMessageHandler"/>'s cross-cutting REST
/// concerns (CONTRACT.md §3/§5/§9): X-Tenant-Id injection, the host-isolation guard,
/// bearer-from-cookie-jar, CSRF cookie double-submit on state-changing methods, and the
/// reactive single 401→refresh→retry (never a loop, exempt auth paths never refresh).
/// </summary>
[Trait("Category", "Fast")]
public class AxiamHttpMessageHandlerTests
{
    private static readonly Uri BaseUrl = new("https://axiam.test");
    private const string TenantId = "acme";

    private static RefreshGuard Guard(Func<CancellationToken, Task<TokenPair>> del) => new(del);

    private static RefreshGuard SucceedingGuard(Action? onRefresh = null) =>
        Guard(_ =>
        {
            onRefresh?.Invoke();
            return Task.FromResult(new TokenPair(
                Sensitive.Of("refreshed-token"), Sensitive.Of("refreshed-refresh"), DateTimeOffset.UtcNow.AddMinutes(15)));
        });

    private static (HttpClient Client, RecordingHandler Inner) Build(RefreshGuard guard, CookieContainer? cookies = null)
    {
        var inner = new RecordingHandler();
        var handler = new AxiamHttpMessageHandler(cookies ?? new CookieContainer(), BaseUrl, TenantId, guard)
        {
            InnerHandler = inner,
        };
        var client = new HttpClient(handler) { BaseAddress = BaseUrl };
        return (client, inner);
    }

    [Fact]
    public async Task SameOriginRequest_InjectsTenantHeader()
    {
        using RefreshGuard guard = SucceedingGuard();
        (HttpClient client, RecordingHandler inner) = Build(guard);
        inner.Responder = _ => new HttpResponseMessage(HttpStatusCode.OK);

        await client.GetAsync("/api/v1/whatever");

        Assert.Equal(TenantId, inner.LastRequestHeaders!.GetValues("X-Tenant-Id").Single());
    }

    [Fact]
    public async Task ForeignHostRequest_WithholdsTenantAndAuthHeaders()
    {
        var cookies = new CookieContainer();
        cookies.Add(BaseUrl, new Cookie("axiam_access", "tok"));
        using RefreshGuard guard = SucceedingGuard();
        (HttpClient client, RecordingHandler inner) = Build(guard, cookies);
        inner.Responder = _ => new HttpResponseMessage(HttpStatusCode.OK);

        await client.GetAsync("https://evil.example/steal");

        Assert.False(inner.LastRequestHeaders!.Contains("X-Tenant-Id"));
        Assert.False(inner.LastRequestHeaders.Contains("Authorization"));
    }

    [Fact]
    public async Task ForeignHostOAuth2TokenRequest_StillInjectsTenantHeader_ButWithholdsAuthAndCsrf()
    {
        // F-15 / CONTRACT.md §12.1 note 2: X-Tenant-Id is unconditional on /oauth2/*
        // endpoints even when discovery advertises them on a host other than the
        // client's configured base URL (e.g. a gateway/CDN fronting the token endpoint
        // separately). No prior test asserted the header on a /oauth2/token request.
        var cookies = new CookieContainer();
        cookies.Add(BaseUrl, new Cookie("axiam_access", "tok"));
        cookies.Add(BaseUrl, new Cookie("axiam_csrf", "csrf-123"));
        using RefreshGuard guard = SucceedingGuard();
        (HttpClient client, RecordingHandler inner) = Build(guard, cookies);
        inner.Responder = _ => new HttpResponseMessage(HttpStatusCode.OK);

        await client.PostAsync(
            "https://foreign-idp.example/oauth2/token",
            new StringContent("grant_type=refresh_token", Encoding.UTF8, "application/x-www-form-urlencoded"));

        Assert.Equal(TenantId, inner.LastRequestHeaders!.GetValues("X-Tenant-Id").Single());
        // Authorization/CSRF stay same-origin only (3A) — the /oauth2/* carve-out is
        // scoped to X-Tenant-Id alone; neither header is meaningful to /oauth2/* anyway
        // (client authentication there is client_secret_post, never bearer).
        Assert.False(inner.LastRequestHeaders.Contains("Authorization"));
        Assert.False(inner.LastRequestHeaders.Contains("X-CSRF-Token"));
    }

    [Fact]
    public async Task ForeignHostNonOAuth2Request_StillWithholdsTenantHeader()
    {
        // Confirms the F-15 carve-out is scoped to /oauth2/* only: an ordinary
        // foreign-host request whose path merely starts with "oauth2" but is not under
        // /oauth2/ must still withhold the tenant header, exactly like any other
        // foreign-host request.
        using RefreshGuard guard = SucceedingGuard();
        (HttpClient client, RecordingHandler inner) = Build(guard);
        inner.Responder = _ => new HttpResponseMessage(HttpStatusCode.OK);

        await client.GetAsync("https://evil.example/oauth2-lookalike/not-actually-oauth2");

        Assert.False(inner.LastRequestHeaders!.Contains("X-Tenant-Id"));
    }

    [Fact]
    public async Task AccessCookiePresent_InjectsBearerAuthorization()
    {
        var cookies = new CookieContainer();
        cookies.Add(BaseUrl, new Cookie("axiam_access", "jwt-token"));
        using RefreshGuard guard = SucceedingGuard();
        (HttpClient client, RecordingHandler inner) = Build(guard, cookies);
        inner.Responder = _ => new HttpResponseMessage(HttpStatusCode.OK);

        await client.GetAsync("/api/v1/whatever");

        Assert.Equal("Bearer jwt-token", inner.LastRequestHeaders!.GetValues("Authorization").Single());
    }

    [Fact]
    public async Task CsrfCookie_OnStateChangingPost_EchoedAsHeader()
    {
        var cookies = new CookieContainer();
        cookies.Add(BaseUrl, new Cookie("axiam_csrf", "csrf-123"));
        using RefreshGuard guard = SucceedingGuard();
        (HttpClient client, RecordingHandler inner) = Build(guard, cookies);
        inner.Responder = _ => new HttpResponseMessage(HttpStatusCode.OK);

        await client.PostAsync("/api/v1/things", new StringContent("{}", Encoding.UTF8, "application/json"));

        Assert.Equal("csrf-123", inner.LastRequestHeaders!.GetValues("X-CSRF-Token").Single());
    }

    [Fact]
    public async Task CsrfCookie_OnSafeGet_NotEchoed()
    {
        var cookies = new CookieContainer();
        cookies.Add(BaseUrl, new Cookie("axiam_csrf", "csrf-123"));
        using RefreshGuard guard = SucceedingGuard();
        (HttpClient client, RecordingHandler inner) = Build(guard, cookies);
        inner.Responder = _ => new HttpResponseMessage(HttpStatusCode.OK);

        await client.GetAsync("/api/v1/things");

        Assert.False(inner.LastRequestHeaders!.Contains("X-CSRF-Token"));
    }

    [Fact]
    public async Task Unauthorized_OnNonExemptPath_TriggersRefreshAndRetriesOnce_WithNewToken()
    {
        int refreshes = 0;
        using RefreshGuard guard = SucceedingGuard(() => refreshes++);
        (HttpClient client, RecordingHandler inner) = Build(guard);

        int calls = 0;
        inner.Responder = req =>
        {
            calls++;
            if (calls == 1)
            {
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            }

            // Second (retry) attempt must carry the refreshed bearer token.
            Assert.Equal("Bearer refreshed-token", req.Headers.GetValues("Authorization").Single());
            return new HttpResponseMessage(HttpStatusCode.OK);
        };

        HttpResponseMessage response = await client.PostAsync("/api/v1/authz/check", new StringContent("{}"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, calls);
        Assert.Equal(1, refreshes);
    }

    [Fact]
    public async Task Unauthorized_OnExemptAuthPath_DoesNotRefresh()
    {
        int refreshes = 0;
        using RefreshGuard guard = SucceedingGuard(() => refreshes++);
        (HttpClient client, RecordingHandler inner) = Build(guard);
        inner.Responder = _ => new HttpResponseMessage(HttpStatusCode.Unauthorized);

        HttpResponseMessage response = await client.PostAsync("/api/v1/auth/login", new StringContent("{}"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, refreshes);
    }

    [Fact]
    public async Task Unauthorized_WhenRefreshFails_ReturnsOriginal401_NoRetry()
    {
        using RefreshGuard guard = Guard(_ => throw new AuthError("refresh failed"));
        (HttpClient client, RecordingHandler inner) = Build(guard);
        int calls = 0;
        inner.Responder = _ =>
        {
            calls++;
            return new HttpResponseMessage(HttpStatusCode.Unauthorized);
        };

        HttpResponseMessage response = await client.GetAsync("/api/v1/authz/check");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(1, calls); // original attempt only; refresh failed so no retry
    }

    [Fact]
    public async Task Unauthorized_OnRetryItself_DoesNotLoop()
    {
        int refreshes = 0;
        using RefreshGuard guard = SucceedingGuard(() => refreshes++);
        (HttpClient client, RecordingHandler inner) = Build(guard);
        int calls = 0;
        inner.Responder = _ =>
        {
            calls++;
            return new HttpResponseMessage(HttpStatusCode.Unauthorized); // always 401
        };

        HttpResponseMessage response = await client.GetAsync("/api/v1/authz/check");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(2, calls); // original + exactly one retry, never a third
        Assert.Equal(1, refreshes);
    }

    [Fact]
    public async Task CaptureCsrfToken_FromResponseHeader_UsedOnNextStateChangingRequest()
    {
        using RefreshGuard guard = SucceedingGuard();
        (HttpClient client, RecordingHandler inner) = Build(guard);
        int calls = 0;
        inner.Responder = _ =>
        {
            calls++;
            var resp = new HttpResponseMessage(HttpStatusCode.OK);
            if (calls == 1)
            {
                resp.Headers.TryAddWithoutValidation("X-CSRF-Token", "server-csrf");
            }
            return resp;
        };

        await client.GetAsync("/api/v1/first"); // captures the CSRF token from the response
        await client.PostAsync("/api/v1/second", new StringContent("{}"));

        Assert.Equal("server-csrf", inner.LastRequestHeaders!.GetValues("X-CSRF-Token").Single());
    }

    [Fact]
    public void Constructor_NullArguments_Throw()
    {
        using RefreshGuard guard = SucceedingGuard();
        Assert.Throws<ArgumentNullException>(() => new AxiamHttpMessageHandler(null!, BaseUrl, TenantId, guard));
        Assert.Throws<ArgumentNullException>(() => new AxiamHttpMessageHandler(new CookieContainer(), null!, TenantId, guard));
        Assert.Throws<ArgumentNullException>(() => new AxiamHttpMessageHandler(new CookieContainer(), BaseUrl, null!, guard));
        Assert.Throws<ArgumentNullException>(() => new AxiamHttpMessageHandler(new CookieContainer(), BaseUrl, TenantId, null!));
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public Func<HttpRequestMessage, HttpResponseMessage> Responder { get; set; } =
            _ => new HttpResponseMessage(HttpStatusCode.OK);

        public System.Net.Http.Headers.HttpRequestHeaders? LastRequestHeaders { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequestHeaders = request.Headers;
            return Task.FromResult(Responder(request));
        }
    }
}
