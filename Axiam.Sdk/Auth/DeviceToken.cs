using Axiam.Sdk.Core;

namespace Axiam.Sdk.Auth;

/// <summary>
/// The result of <c>AxiamClient.AuthenticateDeviceAsync</c> — the &#167;6.1 mTLS device
/// login, <c>POST /api/v1/auth/device</c> (CONTRACT.md &#167;6.1 rule 6, contract 1.51).
/// </summary>
/// <remarks>
/// <para>
/// There is no refresh token: <see cref="ExpiresIn"/> is the whole lifetime of the
/// credential, and a device re-authenticates by calling
/// <c>AuthenticateDeviceAsync</c> again, which costs one TLS handshake — cheaper than the
/// server-side state a refresh token would need. This is a server decision (D-6 of the
/// dogfooding remediation plan), not an SDK omission.
/// </para>
/// <para>
/// <see cref="AccessToken"/> is certificate-bound (CONTRACT.md &#167;10.1 rule 9, &#167;6.1
/// rule 9): it carries <c>cnf.x5t#S256</c> naming the certificate this client presented,
/// and is usable only on a connection presenting that same certificate. The handle
/// <c>AuthenticateDeviceAsync</c> returns already satisfies that — it is built over the
/// SAME client-certificate identity this client was constructed with.
/// </para>
/// </remarks>
/// <param name="AccessToken">
/// The device's bearer credential. <see cref="Sensitive{T}"/> (&#167;7): never appears in
/// <see cref="object.ToString"/>, JSON serialization or a log call.
/// </param>
/// <param name="TokenType">Always <c>"Bearer"</c> — including for this certificate-bound
/// token. CONTRACT.md &#167;1.1.1 rule 5: an SDK MUST decide boundness from <c>cnf</c>
/// alone, never from this field.</param>
/// <param name="ExpiresIn">The access token's lifetime in seconds (server default 900).</param>
public sealed record DeviceToken(
    Sensitive<string> AccessToken,
    string TokenType,
    int ExpiresIn);
