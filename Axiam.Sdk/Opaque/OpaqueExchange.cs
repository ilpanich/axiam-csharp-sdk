namespace Axiam.Sdk.Opaque;

using Axiam.Sdk.Core;

/// <summary>
/// One in-flight OPAQUE exchange, owning a native state handle.
/// </summary>
/// <remarks>
/// <para>
/// The handle is <b>single-use</b>: the library consumes it in <c>Finish</c> whether that
/// succeeds or fails. This class takes it out of a one-shot slot, so a second <c>Finish</c>
/// raises a .NET exception rather than handing a dangling pointer across the ABI.
/// </para>
/// <para>
/// <see cref="IDisposable"/> and a finalizer, in that order of preference: <c>using</c>
/// releases an abandoned exchange deterministically, and the finalizer catches a caller who
/// started a login and never completed it. Both go through the same one-shot slot, so neither
/// can double-free.
/// </para>
/// </remarks>
public abstract class OpaqueExchange : IDisposable
{
    private readonly bool _registration;
    private nint _handle;

    private protected OpaqueExchange(IOpaqueNative lib, nint handle, string firstMessage, bool registration)
    {
        Library = lib;
        _handle = handle;
        FirstMessage = firstMessage;
        _registration = registration;
    }

    /// <summary>The loaded library, shared with subclasses for their <c>Finish</c>.</summary>
    private protected IOpaqueNative Library { get; }

    /// <summary>
    /// The first protocol message, hex — <c>RegistrationRequest</c> or <c>KE1</c>.
    /// </summary>
    private protected string FirstMessage { get; }

    /// <summary>Spends the handle, or refuses if it is already spent.</summary>
    private protected nint Consume()
    {
        nint taken = Interlocked.Exchange(ref _handle, nint.Zero);
        return taken == nint.Zero
            ? throw NetworkError.FromMessage("OPAQUE: this exchange has already been completed")
            : taken;
    }

    /// <summary>
    /// Releases the exchange if it was never finished. Idempotent, and a no-op once
    /// <c>Finish</c> has spent the handle.
    /// </summary>
    public void Dispose()
    {
        Release();
        GC.SuppressFinalize(this);
    }

    /// <summary>Releases an exchange the caller abandoned without disposing it.</summary>
    ~OpaqueExchange() => Release();

    private void Release()
    {
        nint abandoned = Interlocked.Exchange(ref _handle, nint.Zero);
        if (abandoned == nint.Zero)
        {
            return;
        }

        if (_registration)
        {
            Library.RegistrationFree(abandoned);
        }
        else
        {
            Library.LoginFree(abandoned);
        }
    }
}

/// <summary>One in-flight enrolment (CONTRACT.md &#167;23).</summary>
public sealed class RegistrationExchange : OpaqueExchange
{
    internal RegistrationExchange(IOpaqueNative lib, nint handle, string request)
        : base(lib, handle, request, registration: true)
    {
    }

    /// <summary>The hex <c>RegistrationRequest</c> to send to <c>register/start</c>.</summary>
    public string Request => FirstMessage;

    /// <summary>
    /// Seals the envelope under the server's oblivious PRF, returning the hex
    /// <c>RegistrationRecord</c>.
    /// </summary>
    /// <param name="password">
    /// The plaintext being enrolled; every copy this SDK makes is cleared, but not the
    /// caller's.
    /// </param>
    /// <param name="registrationResponse">The server's hex <c>RegistrationResponse</c>.</param>
    /// <param name="ksf">The key-stretching function the server named.</param>
    /// <returns>The record to attach to the request that sets the password.</returns>
    /// <exception cref="NetworkError">
    /// The exchange is already spent, the key-stretching function is one this SDK cannot ask
    /// for, or the library refuses the response.
    /// </exception>
    public string Finish(char[] password, string registrationResponse, KsfParams ksf)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(ksf);

        // The key-stretching handle is built BEFORE the state is spent, and the
        // order is load-bearing. Build() refuses an unrecognised function or an
        // out-of-band cost, and if the state had already been taken out of its
        // one-shot slot by then it could never be freed -- a leaked Rust
        // allocation per refused attempt, which is once per login against a
        // misconfigured tenant. Built first, a refusal leaves the exchange
        // intact: Dispose() and the finalizer still release it, and a caller
        // who fixes the parameters can retry.
        nint ksfHandle = ksf.Build(Library);
        byte[] encoded = OpaqueProtocol.NulTerminatedUtf8(password);
        try
        {
            nint state = Consume();
            nint record = Library.RegistrationFinish(
                state, encoded, OpaqueProtocol.NulTerminatedAscii(registrationResponse), ksfHandle);

            return record == nint.Zero
                ? throw NetworkError.FromMessage(
                    "OPAQUE: " + OpaqueProtocol.LastError(Library, "the envelope could not be sealed"))
                : OpaqueProtocol.Take(Library, record);
        }
        finally
        {
            Library.KsfFree(ksfHandle);
            Array.Clear(encoded);
        }
    }
}

/// <summary>One in-flight login (CONTRACT.md &#167;23).</summary>
public sealed class LoginExchange : OpaqueExchange
{
    internal LoginExchange(IOpaqueNative lib, nint handle, string ke1)
        : base(lib, handle, ke1, registration: false)
    {
    }

    /// <summary>The hex <c>KE1</c> to send to <c>login/start</c>.</summary>
    public string Ke1 => FirstMessage;

    /// <summary>Opens the envelope, producing <c>KE3</c>.</summary>
    /// <remarks>
    /// <para>
    /// A failure here is the <b>whole</b> of the client's authentication check, and covers both
    /// halves of the mutual authentication: the envelope only opens under the right password,
    /// and <c>KE2</c>'s MAC only verifies if the server actually holds the record. Nothing may
    /// be sent afterwards (&#167;23.4 rule 7).
    /// </para>
    /// <para>
    /// That case is an <see cref="AuthError"/>, unlike every other null return in this
    /// namespace. The distinction is the point: a wrong password, an account that does not
    /// exist and a server that does not hold the record are indistinguishable by design and are
    /// all authentication failures, whereas a key-stretching function this build cannot perform
    /// is a configuration problem, and reporting it as "invalid password" would send an
    /// operator looking in the wrong place.
    /// </para>
    /// </remarks>
    /// <param name="password">
    /// The account password; every copy this SDK makes is cleared, but not the caller's.
    /// </param>
    /// <param name="ke2">The server's hex <c>KE2</c>.</param>
    /// <param name="ksf">The key-stretching function the server named.</param>
    /// <returns>The hex <c>KE3</c> to send to <c>login/finish</c>.</returns>
    /// <exception cref="AuthError">
    /// The envelope did not open, or <c>KE2</c> did not verify.
    /// </exception>
    /// <exception cref="NetworkError">
    /// The exchange is already spent, or the key-stretching function is one this SDK cannot ask
    /// for.
    /// </exception>
    public string Finish(char[] password, string ke2, KsfParams ksf)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(ksf);

        // The key-stretching handle is built BEFORE the state is spent, and the
        // order is load-bearing. Build() refuses an unrecognised function or an
        // out-of-band cost, and if the state had already been taken out of its
        // one-shot slot by then it could never be freed -- a leaked Rust
        // allocation per refused attempt, which is once per login against a
        // misconfigured tenant. Built first, a refusal leaves the exchange
        // intact: Dispose() and the finalizer still release it, and a caller
        // who fixes the parameters can retry.
        nint ksfHandle = ksf.Build(Library);
        byte[] encoded = OpaqueProtocol.NulTerminatedUtf8(password);
        try
        {
            nint state = Consume();
            nint ke3 = Library.LoginFinish(
                state, encoded, OpaqueProtocol.NulTerminatedAscii(ke2), ksfHandle);

            return ke3 == nint.Zero
                ? throw new AuthError(
                    "invalid credentials: " +
                    OpaqueProtocol.LastError(Library, "the OPAQUE envelope did not open"))
                : OpaqueProtocol.Take(Library, ke3);
        }
        finally
        {
            Library.KsfFree(ksfHandle);
            Array.Clear(encoded);
        }
    }
}
