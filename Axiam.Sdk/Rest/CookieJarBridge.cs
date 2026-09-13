using System.Net;

namespace Axiam.Sdk.Rest;

/// <summary>
/// Moves cookies collected in one <see cref="CookieContainer"/> into another, both scoped
/// to the same origin.
/// </summary>
/// <remarks>
/// Backs the CONTRACT.md &#167;24.1 <c>setup/register/*</c> pair (contract 1.45):
/// <c>WebauthnSetupRegisterStartAsync</c>/<c>WebauthnSetupRegisterFinishAsync</c> run over
/// a dedicated, session-credential-free transport so no existing session cookie or
/// <c>Authorization</c> header is ever attached to them — but a successful <c>finish</c>
/// still sets a brand-new session the caller must end up with, so its Set-Cookie triple
/// (captured in that dedicated transport's own, otherwise-empty jar) is copied here into
/// the shared jar every other call on the client reads from. Kept as its own type — rather
/// than inlined where it is called — so the copy itself (the one part of that flow a fake,
/// non-<see cref="HttpClientHandler"/> test transport can never exercise end to end) has
/// something to unit test directly, independent of any transport.
/// </remarks>
internal static class CookieJarBridge
{
    /// <summary>
    /// Copies every cookie <paramref name="from"/> holds for <paramref name="baseUri"/>
    /// into <paramref name="to"/>.
    /// </summary>
    /// <param name="from">The jar to read from.</param>
    /// <param name="to">The jar to add into.</param>
    /// <param name="baseUri">The origin both jars are scoped to.</param>
    public static void Copy(CookieContainer from, CookieContainer to, Uri baseUri)
    {
        ArgumentNullException.ThrowIfNull(from);
        ArgumentNullException.ThrowIfNull(to);
        ArgumentNullException.ThrowIfNull(baseUri);

        foreach (Cookie cookie in from.GetCookies(baseUri))
        {
            to.Add(baseUri, cookie);
        }
    }
}
