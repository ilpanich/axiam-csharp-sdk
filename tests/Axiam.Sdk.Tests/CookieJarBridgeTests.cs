using System.Net;
using Axiam.Sdk.Rest;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Unit coverage for <see cref="CookieJarBridge"/>'s copy logic in isolation.
/// </summary>
/// <remarks>
/// This is the one part of the CONTRACT.md &#167;24.1 <c>setup/register/*</c> adoption path
/// (contract 1.45) that a fake, non-<see cref="HttpClientHandler"/> test transport cannot
/// exercise end to end — see <c>AxiamClientAuthFlowTests</c>' remarks on why a real
/// Set-Cookie round trip is never modeled by <c>RoutingHandler</c>. Testing the copy
/// directly, against two plain <see cref="CookieContainer"/>s, covers the actual risk in
/// that glue code without needing a real socket.
/// </remarks>
[Trait("Category", "Fast")]
public sealed class CookieJarBridgeTests
{
    private static readonly Uri BaseUri = new("https://axiam.test");

    [Fact]
    public void CopiesEveryCookieForTheOrigin()
    {
        var from = new CookieContainer();
        from.Add(BaseUri, new Cookie("axiam_access", "access-jwt"));
        from.Add(BaseUri, new Cookie("axiam_refresh", "refresh-opaque"));
        from.Add(BaseUri, new Cookie("axiam_csrf", "csrf-value"));

        var to = new CookieContainer();

        CookieJarBridge.Copy(from, to, BaseUri);

        CookieCollection copied = to.GetCookies(BaseUri);
        Assert.Equal(3, copied.Count);
        Assert.Equal("access-jwt", copied["axiam_access"]!.Value);
        Assert.Equal("refresh-opaque", copied["axiam_refresh"]!.Value);
        Assert.Equal("csrf-value", copied["axiam_csrf"]!.Value);
    }

    [Fact]
    public void AnEmptySourceJarCopiesNothingAndDoesNotThrow()
    {
        var from = new CookieContainer();
        var to = new CookieContainer();
        to.Add(BaseUri, new Cookie("pre_existing", "still-here"));

        CookieJarBridge.Copy(from, to, BaseUri);

        CookieCollection result = to.GetCookies(BaseUri);
        Assert.Single(result);
        Assert.Equal("still-here", result["pre_existing"]!.Value);
    }

    [Fact]
    public void CopyingIntoAJarThatAlreadyHasTheSameCookieOverwritesTheValue()
    {
        var from = new CookieContainer();
        from.Add(BaseUri, new Cookie("axiam_access", "new-value"));

        var to = new CookieContainer();
        to.Add(BaseUri, new Cookie("axiam_access", "stale-value"));

        CookieJarBridge.Copy(from, to, BaseUri);

        Assert.Equal("new-value", to.GetCookies(BaseUri)["axiam_access"]!.Value);
    }

    [Fact]
    public void NullArgumentsAreRejected()
    {
        var jar = new CookieContainer();
        Assert.Throws<ArgumentNullException>(() => CookieJarBridge.Copy(null!, jar, BaseUri));
        Assert.Throws<ArgumentNullException>(() => CookieJarBridge.Copy(jar, null!, BaseUri));
        Assert.Throws<ArgumentNullException>(() => CookieJarBridge.Copy(jar, jar, null!));
    }
}
