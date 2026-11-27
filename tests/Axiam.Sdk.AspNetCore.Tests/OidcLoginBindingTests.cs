using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Axiam.Sdk;
using Axiam.Sdk.AspNetCore.Tests.Fixtures;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Options;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Axiam.Sdk.AspNetCore.Tests;

/// <summary>
/// CONTRACT.md &#167;12.8 (contract 1.68; audit findings C7 and C6) for
/// <see cref="OidcLoginEndpointExtensions.MapAxiamOidcLogin"/>: the callback completes only for
/// the browser that started the login (the <c>__Host-axiam_oidc_bind</c> cookie), and a
/// <c>return_to</c> is followed only when it is a same-origin relative path.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OidcLoginBindingTests
{
    private const string TenantId = "22222222-2222-2222-2222-222222222222";
    private const string ClientId = "test-relying-party";
    private const string CallbackUrl = "https://app.example/login/axiam/callback";
    private const string HostCookie = "__Host-axiam_oidc_bind";
    private const string LoopbackCookie = "axiam_oidc_bind";
    private const string UniformBody = "unknown, expired, or already-used login state";
    private static readonly Uri BaseUrl = new("https://axiam.test");

    // ---- C7: the login response --------------------------------------------------------

    [Fact]
    public async Task Login_SetsTheHostBindingCookie_WithTheContractAttributes()
    {
        using TestApp app = await TestApp.StartAsync();

        HttpResponseMessage login = await app.Client.GetAsync("/login/axiam", HttpCompletionOption.ResponseHeadersRead);

        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
        string setCookie = SingleSetCookie(login, HostCookie);
        string value = CookieValue(setCookie, HostCookie);
        Assert.Equal(43, value.Length); // 32 random bytes, base64url, no padding
        Assert.Matches("^[A-Za-z0-9_-]{43}$", value);
        string lower = setCookie.ToLowerInvariant();
        Assert.Contains("httponly", lower);
        Assert.Contains("secure", lower);
        Assert.Contains("samesite=lax", lower);
        Assert.Contains("path=/", lower);
        Assert.DoesNotContain("domain=", lower);
        int maxAge = int.Parse(System.Text.RegularExpressions.Regex.Match(lower, @"max-age=(\d+)").Groups[1].Value);
        Assert.InRange(maxAge, 1, 600);
    }

    [Fact]
    public async Task Login_StoresOnlyTheSha256DigestOfTheCookieValue()
    {
        using TestApp app = await TestApp.StartAsync();

        HttpResponseMessage login = await app.Client.GetAsync("/login/axiam", HttpCompletionOption.ResponseHeadersRead);
        string value = CookieValue(SingleSetCookie(login, HostCookie), HostCookie);
        OidcStateEntry? entry = await app.Store.ConsumeAsync(StateOf(login));

        Assert.NotNull(entry);
        string expected = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(value))).ToLowerInvariant();
        Assert.Equal(expected, entry!.BindingDigest);
        Assert.NotEqual(value, entry.BindingDigest);
    }

    [Fact]
    public async Task Login_DrawsANewValueEveryTime_AndNeverReusesAPresentedCookie()
    {
        using TestApp app = await TestApp.StartAsync();

        HttpResponseMessage first = await app.Client.GetAsync("/login/axiam", HttpCompletionOption.ResponseHeadersRead);
        string firstValue = CookieValue(SingleSetCookie(first, HostCookie), HostCookie);
        HttpResponseMessage second = await app.GetWithCookieAsync("/login/axiam", HostCookie, firstValue);
        string secondValue = CookieValue(SingleSetCookie(second, HostCookie), HostCookie);

        Assert.NotEqual(firstValue, secondValue);
    }

    [Fact]
    public async Task Login_OnAnHttpLoopbackRedirectUri_UsesTheFallbackName_WithoutSecure()
    {
        using TestApp app = await TestApp.StartAsync(o => o.RedirectUri = "http://localhost:5000/login/axiam/callback");

        HttpResponseMessage login = await app.Client.GetAsync("/login/axiam", HttpCompletionOption.ResponseHeadersRead);

        string setCookie = SingleSetCookie(login, LoopbackCookie);
        string lower = setCookie.ToLowerInvariant();
        Assert.DoesNotContain("secure", lower);
        Assert.Contains("httponly", lower);
        Assert.Contains("samesite=lax", lower);
        Assert.Contains("path=/", lower);
        Assert.DoesNotContain(login.Headers.GetValues("Set-Cookie"), c => c.StartsWith(HostCookie + "=", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("http://app.example/cb")]
    [InlineData("https://localhost/cb")]
    [InlineData("http://localhost.evil.example/cb")]
    public async Task Login_OnAnyOtherRedirectUri_StillUsesTheHostName(string redirectUri)
    {
        using TestApp app = await TestApp.StartAsync(o => o.RedirectUri = redirectUri);

        HttpResponseMessage login = await app.Client.GetAsync("/login/axiam", HttpCompletionOption.ResponseHeadersRead);

        Assert.Contains(HostCookie + "=", SingleSetCookie(login, HostCookie));
        Assert.DoesNotContain(login.Headers.GetValues("Set-Cookie"), c => c.StartsWith(LoopbackCookie + "=", StringComparison.Ordinal));
    }

    // ---- C7: the callback --------------------------------------------------------------

    [Fact]
    public async Task Callback_WithAValidStateAndNoCookie_Is401_NoExchange_NoOnSuccess_AndClearsTheCookie()
    {
        using TestApp app = await TestApp.StartAsync();
        (string state, _) = await app.BeginAsync();

        HttpResponseMessage response = await app.Client.GetAsync($"/login/axiam/callback?state={state}&code=c1");

        await AssertUniform401Async(response);
        Assert.Equal(0, app.Server.TokenRequests);
        Assert.False(app.OnSuccessCalled);
        AssertCleared(response, HostCookie);
    }

    [Fact]
    public async Task Callback_WithAnotherLoginsCookie_Is401_NoExchange_NoOnSuccess()
    {
        using TestApp app = await TestApp.StartAsync();
        (string stateA, _) = await app.BeginAsync();
        (_, string cookieB) = await app.BeginAsync();

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={stateA}&code=c1", HostCookie, cookieB);

        await AssertUniform401Async(response);
        Assert.Equal(0, app.Server.TokenRequests);
        Assert.False(app.OnSuccessCalled);
        AssertCleared(response, HostCookie);
    }

    [Fact]
    public async Task Callback_FromTheBrowserThatStartedTheLogin_Succeeds_OnSuccessGetsTheRequest_AndClearsTheCookie()
    {
        using TestApp app = await TestApp.StartAsync();
        (string state, string cookie) = await app.BeginAsync();

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(app.OnSuccessCalled);
        Assert.Equal("/login/axiam/callback", app.OnSuccessPath);
        Assert.Equal(1, app.Server.TokenRequests);
        AssertCleared(response, HostCookie);
    }

    [Fact]
    public async Task ARefusedCallback_ConsumesTheEntry_SoARetryWithTheRightCookieAlsoFails()
    {
        using TestApp app = await TestApp.StartAsync();
        (string state, string cookie) = await app.BeginAsync();

        HttpResponseMessage refused = await app.Client.GetAsync($"/login/axiam/callback?state={state}&code=c1");
        HttpResponseMessage retry = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        await AssertUniform401Async(retry);
        Assert.Equal(0, app.Server.TokenRequests);
    }

    [Fact]
    public async Task AnEntryWithNoBindingDigest_IsRefused()
    {
        using TestApp app = await TestApp.StartAsync();
        // Stored directly, as 1.67 glue or a caller-supplied store would have left it.
        await app.Store.SaveAsync(new OidcStateEntry("legacy-state", "n", Axiam.Sdk.Core.Sensitive<string>.Wrap("v"), CallbackUrl, null));

        HttpResponseMessage response = await app.GetWithCookieAsync("/login/axiam/callback?state=legacy-state&code=c1", HostCookie, "anything");

        await AssertUniform401Async(response);
        Assert.Equal(0, app.Server.TokenRequests);
        Assert.False(app.OnSuccessCalled);
    }

    [Fact]
    public async Task OnLoopback_TheCallbackReadsOnlyTheFallbackName()
    {
        using TestApp app = await TestApp.StartAsync(o => o.RedirectUri = "http://localhost:5000/login/axiam/callback");
        (string state, string cookie) = await app.BeginAsync(LoopbackCookie);

        // The right value under the wrong (__Host-) name is treated as no cookie.
        HttpResponseMessage wrongName = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);
        await AssertUniform401Async(wrongName);

        (string state2, string cookie2) = await app.BeginAsync(LoopbackCookie);
        HttpResponseMessage rightName = await app.GetWithCookieAsync($"/login/axiam/callback?state={state2}&code=c1", LoopbackCookie, cookie2);
        Assert.Equal(HttpStatusCode.OK, rightName.StatusCode);
        AssertCleared(rightName, LoopbackCookie);
    }

    [Fact]
    public async Task EveryOtherCallbackErrorAlsoClearsTheCookie()
    {
        using TestApp app = await TestApp.StartAsync();

        HttpResponseMessage idpError = await app.Client.GetAsync("/login/axiam/callback?error=access_denied");
        HttpResponseMessage malformed = await app.Client.GetAsync("/login/axiam/callback?state=only-state");

        Assert.Equal(HttpStatusCode.Unauthorized, idpError.StatusCode);
        AssertCleared(idpError, HostCookie);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        AssertCleared(malformed, HostCookie);
    }

    // ---- C6: return_to -----------------------------------------------------------------

    public static IEnumerable<object[]> UnsafeReturnTo() => new[]
    {
        new object[] { "https://evil.example/x" },
        new object[] { "//evil.example/x" },
        new object[] { "/\\evil.example" },
        new object[] { "/a\\b" },
        new object[] { "/a\r" },
        new object[] { "/a\0" },
        new object[] { "/a\u007f" },
        new object[] { "javascript:alert(1)" },
        new object[] { "dashboard" },
    };

    [Theory]
    [MemberData(nameof(UnsafeReturnTo))]
    public async Task Login_DropsAnUnsafeReturnTo(string returnTo)
    {
        using TestApp app = await TestApp.StartAsync();

        HttpResponseMessage login = await app.Client.GetAsync("/login/axiam?return_to=" + Uri.EscapeDataString(returnTo), HttpCompletionOption.ResponseHeadersRead);
        OidcStateEntry? entry = await app.Store.ConsumeAsync(StateOf(login));

        Assert.NotNull(entry);
        Assert.Null(entry!.ReturnTo);
    }

    [Theory]
    [MemberData(nameof(UnsafeReturnTo))]
    public async Task Callback_DoesNotFollowAnUnsafeReturnTo_StoredDirectlyInTheEntry(string returnTo)
    {
        using TestApp app = await TestApp.StartAsync(forceReturnTo: returnTo);
        (string state, string cookie) = await app.BeginAsync();

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        JsonElement body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.True(body.GetProperty("authenticated").GetBoolean());
    }

    [Fact]
    public async Task ASameOriginRelativePath_IsStoredAndFollowed()
    {
        using TestApp app = await TestApp.StartAsync();
        (string state, string cookie) = await app.BeginAsync(returnTo: "/dashboard?tab=1");

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/dashboard?tab=1", response.Headers.Location!.OriginalString);
    }

    // ---- Round 2: GLUE-R1-2 / GLUE-R1-3 / GLUE-R1-4 / CSH-R1-3 / CSH-R1-8 ------------------

    [Theory]
    [InlineData("/caf\u00e9", "/caf%C3%A9")]
    [InlineData("/\u65e5\u672c/\u8a9e?q=\u00fc", "/%E6%97%A5%E6%9C%AC/%E8%AA%9E?q=%C3%BC")]
    [InlineData("/already%20encoded/a%C3%A9", "/already%20encoded/a%C3%A9")]
    public async Task ANonAsciiReturnTo_IsPercentEncoded_SoTheLocationHeaderIsAscii(string returnTo, string expectedLocation)
    {
        using TestApp app = await TestApp.StartAsync();
        (string state, string cookie) = await app.BeginAsync(returnTo: returnTo);

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        string location = response.Headers.Location!.OriginalString;
        Assert.Equal(expectedLocation, location);
        Assert.All(location, c => Assert.InRange(c, (char)0x20, (char)0x7e));
    }

    // ---- Decision 7 (login-glue binding): the adapter writes the percent-encoded form of the destination ----

    private static void AssertLocationIsPureAscii(string location) =>
        Assert.All(location, c => Assert.InRange(c, (char)0x21, (char)0x7e));

    [Theory]
    [InlineData("/a b", "/a%20b")]
    [InlineData("/caf\u00e9", "/caf%C3%A9")]
    [InlineData("/\u20ac", "/%E2%82%AC")]
    [InlineData("/a%20b", "/a%20b")]
    [InlineData("/a%20b c", "/a%20b%20c")]
    [InlineData("/100%", "/100%25")]
    [InlineData("/a%zzb", "/a%25zzb")]
    [InlineData("/%%41", "/%25%41")]
    [InlineData("/a%2", "/a%252")]
    [InlineData("/a\"b<c>d`e{f}", "/a%22b%3Cc%3Ed%60e%7Bf%7D")]
    [InlineData("/ok?x=1&y=2#f", "/ok?x=1&y=2#f")]
    public async Task TheLocationHeader_IsThePercentEncodedForm_PureAscii_AndTheCookieIsCleared(string returnTo, string expectedLocation)
    {
        using TestApp app = await TestApp.StartAsync();
        (string state, string cookie) = await app.BeginAsync(returnTo: returnTo);

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        string location = response.Headers.Location!.OriginalString;
        Assert.Equal(expectedLocation, location);
        AssertLocationIsPureAscii(location);
        AssertCleared(response, HostCookie);
        Assert.True(app.OnSuccessCalled);
    }

    [Fact]
    public async Task ALoneSurrogateInTheDestination_BecomesTheReplacementCharacter_AndDoesNotThrow()
    {
        using TestApp app = await TestApp.StartAsync(forceReturnTo: "/a\ud800b");
        (string state, string cookie) = await app.BeginAsync();

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        string location = response.Headers.Location!.OriginalString;
        Assert.Equal("/a%EF%BF%BDb", location);
        AssertLocationIsPureAscii(location);
        AssertCleared(response, HostCookie);
    }

    [Fact]
    public async Task TwoLoneSurrogates_BecomeTwoReplacementCharacters()
    {
        using TestApp app = await TestApp.StartAsync(forceReturnTo: "/\ud800\ud800");
        (string state, string cookie) = await app.BeginAsync();

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/%EF%BF%BD%EF%BF%BD", response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task ABackslash_AdmittedByAnApplicationPredicate_IsKeptUnencoded()
    {
        using TestApp app = await TestApp.StartAsync(o => o.AllowReturnTo = v => v.StartsWith('/'));
        (string state, string cookie) = await app.BeginAsync(returnTo: "/a\\b");

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/a\\b", response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task ACrLfDestination_AdmittedByAnApplicationPredicate_IsEncoded_AndInjectsNoHeader()
    {
        using TestApp app = await TestApp.StartAsync(o => o.AllowReturnTo = v => v.StartsWith('/'));
        (string state, string cookie) = await app.BeginAsync(returnTo: "/a\r\nSet-Cookie: pwned=1");

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        string location = response.Headers.Location!.OriginalString;
        Assert.Equal("/a%0D%0ASet-Cookie:%20pwned=1", location);
        AssertLocationIsPureAscii(location);
        Assert.DoesNotContain(
            response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? all) ? all : Array.Empty<string>(),
            c => c.StartsWith("pwned=", StringComparison.Ordinal));
        AssertCleared(response, HostCookie);
    }

    [Fact]
    public async Task ANonAsciiSuccessRedirect_IsEncodedToo()
    {
        using TestApp app = await TestApp.StartAsync(o => o.SuccessRedirect = "/succ\u00e8s \u00e9");
        (string state, string cookie) = await app.BeginAsync();

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        string location = response.Headers.Location!.OriginalString;
        Assert.Equal("/succ%C3%A8s%20%C3%A9", location);
        AssertLocationIsPureAscii(location);
        AssertCleared(response, HostCookie);
        Assert.True(app.OnSuccessCalled);
    }

    [Fact]
    public async Task TheBindingCookie_IsEssential_SoTheCookieConsentPolicyDoesNotSuppressIt()
    {
        using TestApp app = await TestApp.StartAsync(beforeRouting: b =>
            b.UseCookiePolicy(new CookiePolicyOptions { CheckConsentNeeded = _ => true }));

        // No consent has been given. The login still sets the binding cookie, and the callback still completes.
        (string state, string cookie) = await app.BeginAsync();
        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(app.OnSuccessCalled);
        AssertCleared(response, HostCookie);
    }

    [Fact]
    public async Task ARefusedCallbackWithAnotherLoginsCookie_ConsumesTheEntry_SoARetryWithTheRightCookieAlsoFails()
    {
        using TestApp app = await TestApp.StartAsync();
        (string stateA, string cookieA) = await app.BeginAsync();
        (_, string cookieB) = await app.BeginAsync();

        HttpResponseMessage refused = await app.GetWithCookieAsync($"/login/axiam/callback?state={stateA}&code=c1", HostCookie, cookieB);
        HttpResponseMessage retry = await app.GetWithCookieAsync($"/login/axiam/callback?state={stateA}&code=c1", HostCookie, cookieA);

        await AssertUniform401Async(refused);
        await AssertUniform401Async(retry);
        Assert.Equal(0, app.Server.TokenRequests);
        Assert.False(app.OnSuccessCalled);
    }

    [Fact]
    public async Task AnExceptionFromOnSuccess_StillAnswersWithTheClearingCookie()
    {
        using TestApp app = await TestApp.StartAsync(o =>
            o.OnSuccessAsync = (_, _, _, _) => throw new InvalidOperationException("the application's hook failed"));
        (string state, string cookie) = await app.BeginAsync();

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        AssertCleared(response, HostCookie);
    }

    [Fact]
    public async Task AnExceptionFromOnSuccess_DoesNotShipTheHeadersTheHookSetBeforeThrowing()
    {
        // CSH-R3-1: a hook that signs the user in and then throws must abort the sign-in. The host used to discard
        // every header on an exception; the callback's own catch must do the same, keeping only the clearing cookie.
        using TestApp app = await TestApp.StartAsync(o =>
            o.OnSuccessAsync = (ctx, _, _, _) =>
            {
                ctx.Response.Cookies.Append("app_session", "x");
                ctx.Response.Headers["X-From-Hook"] = "1";
                throw new InvalidOperationException("the application's rule rejected the user");
            });
        (string state, string cookie) = await app.BeginAsync();

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        AssertCleared(response, HostCookie);
        Assert.DoesNotContain(
            response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? all) ? all : Array.Empty<string>(),
            c => c.StartsWith("app_session=", StringComparison.Ordinal));
        Assert.False(response.Headers.Contains("X-From-Hook"));
    }

    [Fact]
    public async Task AnOperationCanceledExceptionThatIsNotTheClientsAbort_StillAnswers500WithTheClearingCookie()
    {
        // CSH-R5-2: an HttpClient timeout in the hook (TaskCanceledException), or a driver's command timeout, is an
        // OperationCanceledException although the request was not aborted. It must take the same catch as any other
        // exception: the clearing Set-Cookie (§12.8 rule 1d) and the 500, not the host's handler.
        using TestApp app = await TestApp.StartAsync(o =>
            o.OnSuccessAsync = (ctx, _, _, _) =>
            {
                Assert.False(ctx.RequestAborted.IsCancellationRequested);
                ctx.Response.Cookies.Append("app_session", "x");
                throw new TaskCanceledException("the hook's HttpClient timed out");
            });
        (string state, string cookie) = await app.BeginAsync();

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        AssertCleared(response, HostCookie);
        Assert.DoesNotContain(
            response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? all) ? all : Array.Empty<string>(),
            c => c.StartsWith("app_session=", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnOperationCanceledExceptionAfterTheClientAborted_IsLeftToTheHost_NoGlue500Body()
    {
        // Observed from the server side, because once the client has aborted its own side fails whatever the glue
        // does: a middleware around the endpoint records what reached it. If the glue's catch took the exception it
        // would have answered 500 (and the exception would never arrive here); left to the host, it propagates.
        Exception? seenByMiddleware = null;
        int statusAfterNext = 0;
        // The client's request fails as soon as the server aborts, which can be before the middleware below has run
        // its catch; the assertions wait for the server side to finish instead of racing it.
        TaskCompletionSource middlewareDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using TestApp app = await TestApp.StartAsync(
            o => o.OnSuccessAsync = (ctx, _, _, _) =>
            {
                ctx.Abort(); // the client went away: RequestAborted is cancelled
                Assert.True(ctx.RequestAborted.IsCancellationRequested);
                throw new OperationCanceledException(ctx.RequestAborted);
            },
            beforeRouting: builder => builder.Use(async (ctx, next) =>
            {
                try
                {
                    await next();
                    statusAfterNext = ctx.Response.StatusCode;
                }
                catch (Exception ex) when (ctx.Request.Path.StartsWithSegments("/login/axiam/callback"))
                {
                    seenByMiddleware = ex;
                    throw;
                }
                finally
                {
                    if (ctx.Request.Path.StartsWithSegments("/login/axiam/callback"))
                    {
                        middlewareDone.TrySetResult();
                    }
                }
            }));
        (string state, string cookie) = await app.BeginAsync();

        try
        {
            await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);
        }
        catch (Exception ex) when (ex is not Xunit.Sdk.XunitException)
        {
            // The client side fails after an abort; that is not what is under test.
        }

        await middlewareDone.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.IsAssignableFrom<OperationCanceledException>(seenByMiddleware);
        Assert.NotEqual(StatusCodes.Status500InternalServerError, statusAfterNext);
    }

    [Fact]
    public async Task APredicate_WidensTheRule_OnlyForValuesTheDefaultRuleRefuses()
    {
        using TestApp app = await TestApp.StartAsync(o => o.AllowReturnTo = v => v == "https://app.example/x");

        (string state, string cookie) = await app.BeginAsync(returnTo: "https://app.example/x");
        HttpResponseMessage allowed = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);
        Assert.Equal(HttpStatusCode.Found, allowed.StatusCode);
        Assert.Equal("https://app.example/x", allowed.Headers.Location!.OriginalString);

        (string state2, string cookie2) = await app.BeginAsync(returnTo: "https://evil.example/x");
        HttpResponseMessage refused = await app.GetWithCookieAsync($"/login/axiam/callback?state={state2}&code=c1", HostCookie, cookie2);
        Assert.Equal(HttpStatusCode.OK, refused.StatusCode);
        Assert.Null(refused.Headers.Location);
    }

    [Fact]
    public async Task APredicateThatThrows_AcceptsNothing()
    {
        using TestApp app = await TestApp.StartAsync(o => o.AllowReturnTo = _ => throw new InvalidOperationException("boom"));
        (string state, string cookie) = await app.BeginAsync(returnTo: "https://app.example/x");

        HttpResponseMessage response = await app.GetWithCookieAsync($"/login/axiam/callback?state={state}&code=c1", HostCookie, cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    // ---- helpers -----------------------------------------------------------------------

    private static string StateOf(HttpResponseMessage login) => QueryParam(login.Headers.Location!.ToString(), "state");

    private static string QueryParam(string url, string name)
    {
        foreach (string pair in new Uri(url).Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] kv = pair.Split('=', 2);
            if (Uri.UnescapeDataString(kv[0]) == name)
            {
                return kv.Length > 1 ? kv[1] : string.Empty;
            }
        }
        throw new InvalidOperationException($"query parameter '{name}' not found in '{url}'");
    }

    private static string SingleSetCookie(HttpResponseMessage response, string name)
    {
        Assert.True(response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? values), "no Set-Cookie header");
        return Assert.Single(values!, c => c.StartsWith(name + "=", StringComparison.Ordinal));
    }

    private static string CookieValue(string setCookie, string name)
    {
        string first = setCookie.Split(';')[0];
        return first[(name.Length + 1)..];
    }

    private static void AssertCleared(HttpResponseMessage response, string name)
    {
        string setCookie = SingleSetCookie(response, name);
        Assert.Equal(string.Empty, CookieValue(setCookie, name));
        string lower = setCookie.ToLowerInvariant();
        Assert.Contains("max-age=0", lower);
        Assert.Contains("path=/", lower);
    }

    private static async Task AssertUniform401Async(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        JsonElement body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("authentication_failed", body.GetProperty("error").GetString());
        Assert.Equal(UniformBody, body.GetProperty("message").GetString());
    }

    /// <summary>Wraps a store so a test can plant an arbitrary <c>return_to</c> in a saved entry.</summary>
    private sealed class ReturnToOverridingStore : IOidcStateStore
    {
        private readonly MemoryOidcStateStore _inner;
        private readonly string? _override;

        public ReturnToOverridingStore(MemoryOidcStateStore inner, string? returnTo)
        {
            _inner = inner;
            _override = returnTo;
        }

        public Task SaveAsync(OidcStateEntry entry, CancellationToken cancellationToken = default) =>
            _inner.SaveAsync(_override is null ? entry : entry with { ReturnTo = _override }, cancellationToken);

        public Task<OidcStateEntry?> ConsumeAsync(string state, CancellationToken cancellationToken = default) =>
            _inner.ConsumeAsync(state, cancellationToken);
    }

    private sealed class TestApp : IDisposable
    {
        private readonly IHost _host;
        public HttpClient Client { get; }
        public MemoryOidcStateStore Store { get; }
        public FakeOidcServerHandler Server { get; }
        public bool OnSuccessCalled { get; private set; }
        public string? OnSuccessPath { get; private set; }

        private TestApp(IHost host, MemoryOidcStateStore store, FakeOidcServerHandler server)
        {
            _host = host;
            Client = host.GetTestClient();
            Store = store;
            Server = server;
        }

        public static async Task<TestApp> StartAsync(Action<AxiamOidcLoginOptions>? configure = null, string? forceReturnTo = null, Action<IApplicationBuilder>? beforeRouting = null)
        {
            var fixture = new JwksFixture();
            var server = new FakeOidcServerHandler(fixture);
            var store = new MemoryOidcStateStore();
            TestApp? app = null;
            AxiamClient fakeClient = AxiamClient.CreateForTesting(
                BaseUrl, TenantId, new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantId, OidcClientId = ClientId }, server);
            IOidcStateStore effectiveStore = forceReturnTo is null ? store : new ReturnToOverridingStore(store, forceReturnTo);

            IHostBuilder builder = new HostBuilder().ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(fakeClient);
                    services.AddSingleton(effectiveStore);
                    services.AddAxiam(options =>
                    {
                        options.BaseUrl = BaseUrl;
                        options.DefaultTenantId = TenantId;
                    });
                });
                webHost.Configure(appBuilder =>
                {
                    beforeRouting?.Invoke(appBuilder);
                    appBuilder.UseRouting();
                    appBuilder.UseEndpoints(endpoints =>
                    {
                        endpoints.MapAxiamOidcLogin("/login/axiam", "/login/axiam/callback", options =>
                        {
                            options.RedirectUri = CallbackUrl;
                            options.OnSuccessAsync = (context, _, _, _) =>
                            {
                                app!.OnSuccessCalled = true;
                                app.OnSuccessPath = context.Request.Path;
                                return Task.CompletedTask;
                            };
                            configure?.Invoke(options);
                        });
                    });
                });
            });

            IHost host = await builder.StartAsync();
            app = new TestApp(host, store, server);
            return app;
        }

        /// <summary>Runs the login route and returns its <c>state</c> and the binding cookie's value.</summary>
        public async Task<(string State, string Cookie)> BeginAsync(string cookieName = HostCookie, string? returnTo = null)
        {
            string path = returnTo is null ? "/login/axiam" : "/login/axiam?return_to=" + Uri.EscapeDataString(returnTo);
            HttpResponseMessage login = await Client.GetAsync(path, HttpCompletionOption.ResponseHeadersRead);
            string authorizeUrl = login.Headers.Location!.ToString();
            Server.NextIdTokenNonce = QueryParam(authorizeUrl, "nonce");
            string cookie = CookieValue(SingleSetCookie(login, cookieName), cookieName);
            return (QueryParam(authorizeUrl, "state"), cookie);
        }

        public Task<HttpResponseMessage> GetWithCookieAsync(string path, string cookieName, string cookieValue)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, path);
            request.Headers.Add("Cookie", $"{cookieName}={cookieValue}");
            return Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        }

        public void Dispose()
        {
            Client.Dispose();
            _host.Dispose();
        }
    }

    private sealed class FakeOidcServerHandler : HttpMessageHandler
    {
        private readonly JwksFixture _fixture;
        private int _tokenRequests;

        public string NextIdTokenNonce { get; set; } = "unused";
        public int TokenRequests => Volatile.Read(ref _tokenRequests);

        public FakeOidcServerHandler(JwksFixture fixture) => _fixture = fixture;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = request.RequestUri!.AbsolutePath;
            string origin = BaseUrl.ToString().TrimEnd('/');
            if (path == "/.well-known/openid-configuration")
            {
                return Task.FromResult(Json(JsonSerializer.Serialize(new
                {
                    issuer = origin,
                    authorization_endpoint = $"{origin}/oauth2/authorize",
                    token_endpoint = $"{origin}/oauth2/token",
                    userinfo_endpoint = $"{origin}/oauth2/userinfo",
                    jwks_uri = $"{origin}/oauth2/jwks",
                    revocation_endpoint = $"{origin}/oauth2/revoke",
                    introspection_endpoint = $"{origin}/oauth2/introspect",
                    response_types_supported = new[] { "code" },
                    subject_types_supported = new[] { "public" },
                    id_token_signing_alg_values_supported = new[] { "EdDSA" },
                    scopes_supported = new[] { "openid" },
                    token_endpoint_auth_methods_supported = new[] { "client_secret_post" },
                    claims_supported = new[] { "sub" },
                    grant_types_supported = new[] { "authorization_code" },
                })));
            }
            if (path == "/oauth2/jwks")
            {
                return Task.FromResult(Json(_fixture.BuildJwksDocument()));
            }
            if (path == "/oauth2/token")
            {
                Interlocked.Increment(ref _tokenRequests);
                string idToken = _fixture.SignIdToken(new
                {
                    iss = origin,
                    sub = "user-1",
                    aud = ClientId,
                    exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
                    iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    nonce = NextIdTokenNonce,
                });
                return Task.FromResult(Json(JsonSerializer.Serialize(new
                {
                    access_token = "access-token-1",
                    token_type = "Bearer",
                    expires_in = 900,
                    refresh_token = "refresh-token-1",
                    id_token = idToken,
                })));
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static HttpResponseMessage Json(string json) =>
            new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }
}
