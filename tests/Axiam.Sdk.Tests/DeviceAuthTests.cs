using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;6.1 rules 6&#8211;10 (contract 1.51): <c>AuthenticateDeviceAsync()</c>,
/// the mTLS device login.
/// </summary>
[Trait("Category", "Fast")]
public sealed class DeviceAuthTests
{
    private static readonly Uri BaseUrl = new("https://axiam.test");
    private const string TenantGuid = "22222222-2222-2222-2222-222222222222";

    /// <summary>
    /// A syntactically valid PEM pair. Tests that use the fake transport never parse it
    /// (the fake transport is injected in place of the real <see cref="HttpClientHandler"/>
    /// construction, mirroring MtlsEndpointAliasesTests' own helper).
    /// </summary>
    private static readonly byte[] DummyCertPem = Encoding.ASCII.GetBytes(
        "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKZ0000000000MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n-----END CERTIFICATE-----\n");

    private static readonly byte[] DummyKeyPem = Encoding.ASCII.GetBytes(
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n");

    private static AxiamClient Client(RoutingHandler handler, byte[]? certPem, byte[]? keyPem)
    {
        var options = new AxiamClientOptions
        {
            BaseUrl = BaseUrl,
            TenantId = TenantGuid,
            ClientCertificatePem = certPem,
            ClientKeyPem = keyPem,
        };
        return AxiamClient.CreateForTesting(BaseUrl, TenantGuid, options, handler);
    }

    private static HttpResponseMessage JsonOk(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage DeviceTokenResponse(string token = "device-token-abc", int expiresIn = 900) =>
        JsonOk($$"""{"access_token":"{{token}}","token_type":"Bearer","expires_in":{{expiresIn}}}""");

    // ---- §6.1 rule 7: unreachable without a certificate, zero wire calls --------------

    [Fact]
    public async Task AuthenticateDeviceAsync_WithNoClientCertificate_ThrowsAuthError_ZeroWireCalls()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/device", _ => DeviceTokenResponse());
        using AxiamClient client = Client(handler, certPem: null, keyPem: null);

        await Assert.ThrowsAsync<AuthError>(() => client.AuthenticateDeviceAsync());

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task AuthenticateDeviceAsync_ReachesTheWireOnlyWhenACertificateIsConfigured_I4Twin()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/device", _ => DeviceTokenResponse());
        using AxiamClient client = Client(handler, DummyCertPem, DummyKeyPem);

        var deviceResult = await client.AuthenticateDeviceAsync();
        using AxiamClient device = deviceResult.Client;
        DeviceToken token = deviceResult.Token;

        Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/auth/device");
        Assert.Equal("device-token-abc", token.AccessToken.Reveal());
        Assert.Equal("Bearer", token.TokenType);
        Assert.Equal(900, token.ExpiresIn);
    }

    // ---- §6.1 rule 6: no request body, adoption as a bearer credential -----------------

    [Fact]
    public async Task AuthenticateDeviceAsync_SendsNoRequestBody()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/device", _ => DeviceTokenResponse());
        using AxiamClient client = Client(handler, DummyCertPem, DummyKeyPem);

        using AxiamClient device = (await client.AuthenticateDeviceAsync()).Client;

        HttpRequestMessage req = Assert.Single(handler.Requests);
        Assert.Null(req.Content);
    }

    [Fact]
    public async Task TheReturnedHandleSendsTheDeviceTokenAsABearerCredential()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/device", _ => DeviceTokenResponse("secret-device-token"));
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        using AxiamClient client = Client(handler, DummyCertPem, DummyKeyPem);

        using AxiamClient device = (await client.AuthenticateDeviceAsync()).Client;
        await device.Management.Resources.ListAsync();

        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.Equal("Bearer secret-device-token", req.Headers.Authorization?.ToString() is { Length: > 0 }
            ? $"{req.Headers.Authorization!.Scheme} {req.Headers.Authorization!.Parameter}"
            : req.Headers.GetValues("Authorization").Single());
    }

    // ---- §6.1 rules 6/8: never the refresh guard, on the login or on a later 401 -------

    [Fact]
    public async Task ALoginFailure_401_IsAuthError_VerbatimMessage_NoRefreshCall()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/device", _ => new HttpResponseMessage(HttpStatusCode.Unauthorized)
        {
            Content = new StringContent(
                """{"error":"authentication_failed","message":"unknown or untrusted certificate"}""",
                Encoding.UTF8, "application/json"),
        });
        using AxiamClient client = Client(handler, DummyCertPem, DummyKeyPem);

        AuthError ex = await Assert.ThrowsAsync<AuthError>(() => client.AuthenticateDeviceAsync());
        Assert.Contains("unknown or untrusted certificate", ex.Message);
        Assert.DoesNotContain(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/auth/refresh");
    }

    [Fact]
    public async Task ALaterFailure_401_OnTheDeviceToken_IsAuthError_NoRefreshCall()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/device", _ => DeviceTokenResponse());
        handler.Map("/api/v1/resources", _ => new HttpResponseMessage(HttpStatusCode.Unauthorized)
        {
            Content = new StringContent("""{"error":"authentication_failed","message":"token expired"}""", Encoding.UTF8, "application/json"),
        });
        using AxiamClient client = Client(handler, DummyCertPem, DummyKeyPem);
        using AxiamClient device = (await client.AuthenticateDeviceAsync()).Client;

        await Assert.ThrowsAsync<AuthError>(() => device.Management.Resources.ListAsync());
        Assert.DoesNotContain(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/auth/refresh");
    }

    // ---- §16: a 429 is not an authentication failure and is not retried ---------------

    [Fact]
    public async Task ALoginRateLimited_429_IsNetworkErrorNotAuthError_AndIsNotRetried()
    {
        int callCount = 0;
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/device", _ =>
        {
            callCount++;
            return new HttpResponseMessage((HttpStatusCode)429)
            {
                Content = new StringContent("""{"error":"rate_limit_exceeded"}""", Encoding.UTF8, "application/json"),
            };
        });
        using AxiamClient client = Client(handler, DummyCertPem, DummyKeyPem);

        await Assert.ThrowsAsync<NetworkError>(() => client.AuthenticateDeviceAsync());
        Assert.Equal(1, callCount);
    }

    // ---- The gate is reset: a device holds no login result -----------------------------

    [Fact]
    public async Task TheReturnedHandleHasNoActingTenantGateKnowledge_ActingTenantIsUngated()
    {
        using var handler = new RoutingHandler();
        handler.Map("/api/v1/auth/device", _ => DeviceTokenResponse());
        handler.Map("/api/v1/resources", _ => JsonOk("""{"items":[],"total":0}"""));
        using AxiamClient client = Client(handler, DummyCertPem, DummyKeyPem);
        using AxiamClient device = (await client.AuthenticateDeviceAsync()).Client;

        Guid otherTenant = Guid.Parse("44444444-4444-4444-4444-444444444444");
        // Does not throw: no login result is held on the device handle, so §5.2 rule 1's
        // gate has nothing to refuse on — the server would answer.
        using AxiamClient acting = device.ActingTenant(otherTenant);
        await acting.Management.Resources.ListAsync();

        HttpRequestMessage req = Assert.Single(handler.Requests, r => r.RequestUri!.AbsolutePath == "/api/v1/resources");
        Assert.Equal(otherTenant.ToString(), req.Headers.GetValues("X-Axiam-Tenant").Single());
    }

    // ---- Real pipeline: the device handle withholds a stale session cookie -------------
    //
    // The axiam-typescript-sdk lesson (device_auth deviceAuth.test.ts, commit 3e4421c):
    // its HTTP mock intercepted ABOVE the layer where the cookie jar attaches cookies, so
    // "the device token withholds the stale cookie" passed even with the withholding
    // removed. This test uses a REAL HttpListener loopback server and a REAL
    // HttpClientHandler/CookieContainer for both the original client (whose jar is seeded
    // with a stale session cookie) and the returned device handle, and inspects the
    // Cookie header the loopback server actually received — the point below which nothing
    // in this SDK's own code can fake the answer.
    [Fact]
    public async Task TheDeviceHandleNeverSendsTheOriginalSessionsStaleCookie()
    {
        using var listener = new HttpListener();
        string prefix = $"http://127.0.0.1:{GetEphemeralPort()}/";
        listener.Prefixes.Add(prefix);
        listener.Start();

        string? cookieHeaderOnResourcesCall = "not observed";
        var serverTask = Task.Run(async () =>
        {
            for (int i = 0; i < 2; i++)
            {
                HttpListenerContext ctx = await listener.GetContextAsync();
                byte[] body;
                if (ctx.Request.Url!.AbsolutePath == "/api/v1/auth/device")
                {
                    body = Encoding.UTF8.GetBytes(
                        """{"access_token":"device-token-xyz","token_type":"Bearer","expires_in":900}""");
                }
                else
                {
                    // The one request this test cares about: what Cookie header (if any)
                    // reached a REAL server, over the device handle's own transport.
                    cookieHeaderOnResourcesCall = ctx.Request.Headers["Cookie"];
                    body = Encoding.UTF8.GetBytes("""{"items":[],"total":0}""");
                }

                ctx.Response.ContentType = "application/json";
                ctx.Response.ContentLength64 = body.Length;
                await ctx.Response.OutputStream.WriteAsync(body);
                ctx.Response.OutputStream.Close();
            }
        });

        try
        {
            (byte[] certPem, byte[] keyPem) = RealClientCertPemPair();
            using var original = new AxiamClient(
                new Uri(prefix),
                TenantGuid,
                new AxiamClientOptions
                {
                    BaseUrl = new Uri(prefix),
                    TenantId = TenantGuid,
                    ClientCertificatePem = certPem,
                    ClientKeyPem = keyPem,
                });

            // Seed a STALE session cookie directly into the ORIGINAL client's real cookie
            // jar — the exact shape a caller who logged in earlier, then switched to a
            // device credential, would have sitting in memory.
            FieldInfo field = typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
            var container = (CookieContainer)field.GetValue(original)!;
            container.Add(new Uri(prefix), new Cookie("axiam_access", "STALE-SESSION-TOKEN"));

            using AxiamClient device = (await original.AuthenticateDeviceAsync()).Client;

            await device.Management.Resources.ListAsync();
            await serverTask;

            Assert.True(
                string.IsNullOrEmpty(cookieHeaderOnResourcesCall)
                || !cookieHeaderOnResourcesCall.Contains("STALE-SESSION-TOKEN", StringComparison.Ordinal),
                $"the device handle sent the original session's stale cookie: '{cookieHeaderOnResourcesCall}'");
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    // ---- Real pipeline: the device-login POST itself withholds the prior session -------
    //
    // The test above (TheDeviceHandleNeverSendsTheOriginalSessionsStaleCookie) only
    // inspects the SECOND request — the returned device handle's own follow-up call. It
    // never asserts on the device-auth POST's own headers, so it does not catch a leak on
    // that first call. CONTRACT.md §6.1 rules 6-10: a client that already holds a cookie
    // session must send neither that session's `Cookie` header nor the derived
    // `Authorization: Bearer` header on `POST /api/v1/auth/device` itself. Same real
    // loopback/real CookieContainer boundary as the test above — a fake transport above
    // HttpClientHandler's cookie layer would prove nothing here (the axiam-typescript-sdk
    // C-8 lesson).
    [Fact]
    public async Task TheDeviceLoginPostItselfWithholdsThePriorSessionsCookieAndAuthorization()
    {
        using var listener = new HttpListener();
        string prefix = $"http://127.0.0.1:{GetEphemeralPort()}/";
        listener.Prefixes.Add(prefix);
        listener.Start();

        string? cookieHeaderOnDeviceLogin = "not observed";
        string? authHeaderOnDeviceLogin = "not observed";
        string? tenantHeaderOnDeviceLogin = "not observed";
        var serverTask = Task.Run(async () =>
        {
            HttpListenerContext ctx = await listener.GetContextAsync();
            cookieHeaderOnDeviceLogin = ctx.Request.Headers["Cookie"];
            authHeaderOnDeviceLogin = ctx.Request.Headers["Authorization"];
            tenantHeaderOnDeviceLogin = ctx.Request.Headers["X-Tenant-Id"];
            byte[] body = Encoding.UTF8.GetBytes(
                """{"access_token":"device-token-xyz","token_type":"Bearer","expires_in":900}""");
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.OutputStream.Close();
        });

        try
        {
            (byte[] certPem, byte[] keyPem) = RealClientCertPemPair();
            using var original = new AxiamClient(
                new Uri(prefix),
                TenantGuid,
                new AxiamClientOptions
                {
                    BaseUrl = new Uri(prefix),
                    TenantId = TenantGuid,
                    ClientCertificatePem = certPem,
                    ClientKeyPem = keyPem,
                });

            // Seed a STALE session cookie directly into the ORIGINAL client's real cookie
            // jar — the exact shape a caller who logged in earlier, then switched to a
            // device credential, would have sitting in memory.
            FieldInfo field = typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
            var container = (CookieContainer)field.GetValue(original)!;
            container.Add(new Uri(prefix), new Cookie("axiam_access", "STALE-SESSION-TOKEN"));

            using AxiamClient device = (await original.AuthenticateDeviceAsync()).Client;
            await serverTask;

            Assert.True(
                string.IsNullOrEmpty(cookieHeaderOnDeviceLogin),
                $"the device-login POST itself sent the original session's cookie: '{cookieHeaderOnDeviceLogin}'");
            Assert.True(
                string.IsNullOrEmpty(authHeaderOnDeviceLogin),
                $"the device-login POST itself sent an Authorization header: '{authHeaderOnDeviceLogin}'");
            // §5 rule 2: X-Tenant-Id stays unconditional even though the request no longer
            // runs through AxiamHttpMessageHandler (which normally derives it).
            Assert.Equal(TenantGuid, tenantHeaderOnDeviceLogin);
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    // ---- A refused device login leaves the original handle's session exactly as it was --

    [Fact]
    public async Task ARefusedDeviceLogin_401_LeavesTheOriginalSessionsCookieIntact_AndNextRequestStillSendsIt()
    {
        using var listener = new HttpListener();
        string prefix = $"http://127.0.0.1:{GetEphemeralPort()}/";
        listener.Prefixes.Add(prefix);
        listener.Start();

        string? cookieHeaderOnFollowUpCall = "not observed";
        var serverTask = Task.Run(async () =>
        {
            for (int i = 0; i < 2; i++)
            {
                HttpListenerContext ctx = await listener.GetContextAsync();
                if (ctx.Request.Url!.AbsolutePath == "/api/v1/auth/device")
                {
                    byte[] body401 = Encoding.UTF8.GetBytes(
                        """{"error":"authentication_failed","message":"unknown or untrusted certificate"}""");
                    ctx.Response.StatusCode = 401;
                    ctx.Response.ContentType = "application/json";
                    ctx.Response.ContentLength64 = body401.Length;
                    await ctx.Response.OutputStream.WriteAsync(body401);
                    ctx.Response.OutputStream.Close();
                }
                else
                {
                    cookieHeaderOnFollowUpCall = ctx.Request.Headers["Cookie"];
                    byte[] body = Encoding.UTF8.GetBytes("""{"items":[],"total":0}""");
                    ctx.Response.ContentType = "application/json";
                    ctx.Response.ContentLength64 = body.Length;
                    await ctx.Response.OutputStream.WriteAsync(body);
                    ctx.Response.OutputStream.Close();
                }
            }
        });

        try
        {
            (byte[] certPem, byte[] keyPem) = RealClientCertPemPair();
            using var original = new AxiamClient(
                new Uri(prefix),
                TenantGuid,
                new AxiamClientOptions
                {
                    BaseUrl = new Uri(prefix),
                    TenantId = TenantGuid,
                    ClientCertificatePem = certPem,
                    ClientKeyPem = keyPem,
                });

            FieldInfo field = typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
            var container = (CookieContainer)field.GetValue(original)!;
            container.Add(new Uri(prefix), new Cookie("axiam_access", "ORIGINAL-SESSION-TOKEN"));

            await Assert.ThrowsAsync<AuthError>(() => original.AuthenticateDeviceAsync());

            // The jar itself is untouched by the refusal — the same cookie is still there.
            CookieCollection stillThere = container.GetCookies(new Uri(prefix));
            Assert.Contains(stillThere.Cast<Cookie>(), c => c.Name == "axiam_access" && c.Value == "ORIGINAL-SESSION-TOKEN");

            // And the original handle's own transport still sends it on an ordinary request.
            await original.Management.Resources.ListAsync();
            await serverTask;

            Assert.False(string.IsNullOrEmpty(cookieHeaderOnFollowUpCall), "expected the original session's cookie on the follow-up call");
            Assert.Contains("ORIGINAL-SESSION-TOKEN", cookieHeaderOnFollowUpCall);
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    // ---- I4 twin: a client with no prior session is unaffected ------------------------

    [Fact]
    public async Task TheDeviceLoginPostFromAClientWithNoPriorSession_IsUnaffected_I4Twin()
    {
        using var listener = new HttpListener();
        string prefix = $"http://127.0.0.1:{GetEphemeralPort()}/";
        listener.Prefixes.Add(prefix);
        listener.Start();

        string? cookieHeaderOnDeviceLogin = "not observed";
        string? authHeaderOnDeviceLogin = "not observed";
        string? cookieHeaderOnFollowUpCall = "not observed";
        string? authHeaderOnFollowUpCall = "not observed";
        var serverTask = Task.Run(async () =>
        {
            for (int i = 0; i < 2; i++)
            {
                HttpListenerContext ctx = await listener.GetContextAsync();
                if (ctx.Request.Url!.AbsolutePath == "/api/v1/auth/device")
                {
                    cookieHeaderOnDeviceLogin = ctx.Request.Headers["Cookie"];
                    authHeaderOnDeviceLogin = ctx.Request.Headers["Authorization"];
                    byte[] body = Encoding.UTF8.GetBytes(
                        """{"access_token":"device-token-xyz","token_type":"Bearer","expires_in":900}""");
                    ctx.Response.ContentType = "application/json";
                    ctx.Response.ContentLength64 = body.Length;
                    await ctx.Response.OutputStream.WriteAsync(body);
                    ctx.Response.OutputStream.Close();
                }
                else
                {
                    cookieHeaderOnFollowUpCall = ctx.Request.Headers["Cookie"];
                    authHeaderOnFollowUpCall = ctx.Request.Headers["Authorization"];
                    byte[] body = Encoding.UTF8.GetBytes("""{"items":[],"total":0}""");
                    ctx.Response.ContentType = "application/json";
                    ctx.Response.ContentLength64 = body.Length;
                    await ctx.Response.OutputStream.WriteAsync(body);
                    ctx.Response.OutputStream.Close();
                }
            }
        });

        try
        {
            (byte[] certPem, byte[] keyPem) = RealClientCertPemPair();
            using var original = new AxiamClient(
                new Uri(prefix),
                TenantGuid,
                new AxiamClientOptions
                {
                    BaseUrl = new Uri(prefix),
                    TenantId = TenantGuid,
                    ClientCertificatePem = certPem,
                    ClientKeyPem = keyPem,
                });
            // No prior session: the cookie jar starts empty — this is the case that was
            // already right; the fix must not disturb it.

            using AxiamClient device = (await original.AuthenticateDeviceAsync()).Client;
            await device.Management.Resources.ListAsync();
            await serverTask;

            Assert.True(string.IsNullOrEmpty(cookieHeaderOnDeviceLogin));
            Assert.True(string.IsNullOrEmpty(authHeaderOnDeviceLogin));
            Assert.True(string.IsNullOrEmpty(cookieHeaderOnFollowUpCall));
            Assert.Equal("Bearer device-token-xyz", authHeaderOnFollowUpCall);
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    // ---- Send-back: the device-login POST also owes X-Axiam-Tenant when set -----------
    //
    // CONTRACT.md §5.2 rule 1: the acting-tenant header is sent on every REST request
    // when this handle has one set — §5 rule 2's X-Tenant-Id is not a substitute, and
    // routing the login over the anonymous transport (this file's earlier fix) must not
    // silently drop it. `_anonymousHttpClient` is SHARED across every `ActingTenant()`
    // handle built over one client (see AxiamClient.cs's copy-constructor), so the header
    // cannot be a `DefaultRequestHeaders` entry on it the way it is on `_httpClient`; it
    // is applied per-request from the CALLING handle's own `_actingTenant` field instead
    // (`ApplyAnonymousTenantHeaders`). Real loopback, same boundary as the tests above.

    [Fact]
    public async Task TheDeviceLoginPostCarriesXAxiamTenant_WhenConfiguredAtConstruction()
    {
        const string actingTenant = "55555555-5555-5555-5555-555555555555";
        using var listener = new HttpListener();
        string prefix = $"http://127.0.0.1:{GetEphemeralPort()}/";
        listener.Prefixes.Add(prefix);
        listener.Start();

        string? cookieHeaderOnDeviceLogin = "not observed";
        string? authHeaderOnDeviceLogin = "not observed";
        string? actingTenantHeaderOnDeviceLogin = "not observed";
        var serverTask = Task.Run(async () =>
        {
            HttpListenerContext ctx = await listener.GetContextAsync();
            cookieHeaderOnDeviceLogin = ctx.Request.Headers["Cookie"];
            authHeaderOnDeviceLogin = ctx.Request.Headers["Authorization"];
            actingTenantHeaderOnDeviceLogin = ctx.Request.Headers["X-Axiam-Tenant"];
            byte[] body = Encoding.UTF8.GetBytes(
                """{"access_token":"device-token-xyz","token_type":"Bearer","expires_in":900}""");
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.OutputStream.Close();
        });

        try
        {
            (byte[] certPem, byte[] keyPem) = RealClientCertPemPair();
            using var original = new AxiamClient(
                new Uri(prefix),
                TenantGuid,
                new AxiamClientOptions
                {
                    BaseUrl = new Uri(prefix),
                    TenantId = TenantGuid,
                    ClientCertificatePem = certPem,
                    ClientKeyPem = keyPem,
                    ActingTenant = Guid.Parse(actingTenant),
                });

            using AxiamClient device = (await original.AuthenticateDeviceAsync()).Client;
            await serverTask;

            Assert.True(string.IsNullOrEmpty(cookieHeaderOnDeviceLogin));
            Assert.True(string.IsNullOrEmpty(authHeaderOnDeviceLogin));
            Assert.Equal(actingTenant, actingTenantHeaderOnDeviceLogin);
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    [Fact]
    public async Task TheDeviceLoginPostCarriesXAxiamTenant_FromAnActingTenantHandle()
    {
        const string actingTenant = "66666666-6666-6666-6666-666666666666";
        using var listener = new HttpListener();
        string prefix = $"http://127.0.0.1:{GetEphemeralPort()}/";
        listener.Prefixes.Add(prefix);
        listener.Start();

        string? cookieHeaderOnDeviceLogin = "not observed";
        string? authHeaderOnDeviceLogin = "not observed";
        string? actingTenantHeaderOnDeviceLogin = "not observed";
        var serverTask = Task.Run(async () =>
        {
            HttpListenerContext ctx = await listener.GetContextAsync();
            cookieHeaderOnDeviceLogin = ctx.Request.Headers["Cookie"];
            authHeaderOnDeviceLogin = ctx.Request.Headers["Authorization"];
            actingTenantHeaderOnDeviceLogin = ctx.Request.Headers["X-Axiam-Tenant"];
            byte[] body = Encoding.UTF8.GetBytes(
                """{"access_token":"device-token-xyz","token_type":"Bearer","expires_in":900}""");
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.OutputStream.Close();
        });

        try
        {
            (byte[] certPem, byte[] keyPem) = RealClientCertPemPair();
            using var original = new AxiamClient(
                new Uri(prefix),
                TenantGuid,
                new AxiamClientOptions
                {
                    BaseUrl = new Uri(prefix),
                    TenantId = TenantGuid,
                    ClientCertificatePem = certPem,
                    ClientKeyPem = keyPem,
                });
            // No login result held yet: ActingTenant() is ungated (§5.2 rule 1 — "nothing
            // to gate on ... sends the header as asked"), exactly the shape a device-login
            // caller has.
            using AxiamClient acting = original.ActingTenant(Guid.Parse(actingTenant));

            using AxiamClient device = (await acting.AuthenticateDeviceAsync()).Client;
            await serverTask;

            Assert.True(string.IsNullOrEmpty(cookieHeaderOnDeviceLogin));
            Assert.True(string.IsNullOrEmpty(authHeaderOnDeviceLogin));
            Assert.Equal(actingTenant, actingTenantHeaderOnDeviceLogin);
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    [Fact]
    public async Task TheDeviceLoginPostFromAClientWithNoActingTenant_OmitsXAxiamTenant_I4Twin()
    {
        using var listener = new HttpListener();
        string prefix = $"http://127.0.0.1:{GetEphemeralPort()}/";
        listener.Prefixes.Add(prefix);
        listener.Start();

        string? actingTenantHeaderOnDeviceLogin = "not observed";
        var serverTask = Task.Run(async () =>
        {
            HttpListenerContext ctx = await listener.GetContextAsync();
            actingTenantHeaderOnDeviceLogin = ctx.Request.Headers["X-Axiam-Tenant"];
            byte[] body = Encoding.UTF8.GetBytes(
                """{"access_token":"device-token-xyz","token_type":"Bearer","expires_in":900}""");
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = body.Length;
            await ctx.Response.OutputStream.WriteAsync(body);
            ctx.Response.OutputStream.Close();
        });

        try
        {
            (byte[] certPem, byte[] keyPem) = RealClientCertPemPair();
            using var original = new AxiamClient(
                new Uri(prefix),
                TenantGuid,
                new AxiamClientOptions
                {
                    BaseUrl = new Uri(prefix),
                    TenantId = TenantGuid,
                    ClientCertificatePem = certPem,
                    ClientKeyPem = keyPem,
                });
            // No ActingTenant configured or set — the already-correct case, pinned so the
            // fix cannot over-reach into sending the header unconditionally.

            using AxiamClient device = (await original.AuthenticateDeviceAsync()).Client;
            await serverTask;

            Assert.True(string.IsNullOrEmpty(actingTenantHeaderOnDeviceLogin));
        }
        finally
        {
            listener.Stop();
            listener.Close();
        }
    }

    private static int GetEphemeralPort()
    {
        using var socket = new System.Net.Sockets.Socket(
            System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    /// <summary>A real, ephemeral self-signed client identity — never parsed by mTLS over
    /// this test's plain-HTTP loopback server, but genuinely valid PEM so the SDK's own
    /// real <c>AxiamHttpClientFactory.CreatePrimaryHandler</c> path (exercised by this
    /// test, which does not inject a transport override) can load it without error.</summary>
    private static (byte[] CertPem, byte[] KeyPem) RealClientCertPemPair()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Axiam Device Test", ecdsa, HashAlgorithmName.SHA256);
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        byte[] certPem = Encoding.ASCII.GetBytes(cert.ExportCertificatePem());
        byte[] keyPem = Encoding.ASCII.GetBytes(ecdsa.ExportPkcs8PrivateKeyPem());
        return (certPem, keyPem);
    }

    private sealed class RoutingHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, Func<HttpRequestMessage, HttpResponseMessage>> _routes = new();

        public List<HttpRequestMessage> Requests { get; } = new();

        public void Map(string path, Func<HttpRequestMessage, HttpResponseMessage> responder) => _routes[path] = responder;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            string path = request.RequestUri!.AbsolutePath;
            if (_routes.TryGetValue(path, out Func<HttpRequestMessage, HttpResponseMessage>? responder))
            {
                return Task.FromResult(responder(request));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
