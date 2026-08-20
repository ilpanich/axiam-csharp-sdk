namespace Axiam.Sdk.Opaque;

using System.Runtime.InteropServices;
using System.Text;
using Axiam.Sdk.Core;

/// <summary>
/// Entry points into <c>libaxiam_opaque_ffi</c> (CONTRACT.md &#167;23).
/// </summary>
/// <remarks>
/// There is no cryptography in this class, or anywhere in this namespace. That is deliberate
/// and is what &#167;23.1 requires: OPAQUE needs an oblivious PRF, <c>hash_to_curve</c>,
/// <c>expand_message_xmd</c>, an envelope construction and a three-message AKE, and eleven
/// independent implementations of that is eleven chances to be subtly and silently wrong. The
/// SRP-6a this replaces was arithmetic every language can express, which is why
/// <c>Axiam.Sdk.Srp</c> existed.
/// </remarks>
public static class OpaqueProtocol
{
    /// <summary>Whether this installation can perform OPAQUE (&#167;23.2).</summary>
    /// <remarks>
    /// Reports rather than throwing, and is genuinely able to answer <c>false</c>: the shared
    /// library is a per-platform release asset rather than a NuGet package. Ask before a login
    /// rather than discovering the gap mid-exchange.
    /// </remarks>
    /// <returns><c>true</c> when the library is present and says it can.</returns>
    public static bool Available()
    {
        IOpaqueNative? lib = OpaqueLibrary.Load();
        return lib is not null && lib.Available() != 0;
    }

    /// <summary>Blinds <paramref name="password"/> to open an enrolment.</summary>
    /// <param name="password">
    /// The plaintext being enrolled; every copy this SDK makes is cleared, but not the
    /// caller's.
    /// </param>
    /// <returns>
    /// An exchange whose <see cref="RegistrationExchange.Request"/> goes to
    /// <c>register/start</c>.
    /// </returns>
    /// <exception cref="NetworkError">The library is unavailable or refuses.</exception>
    public static RegistrationExchange StartRegistration(char[] password)
    {
        ArgumentNullException.ThrowIfNull(password);

        IOpaqueNative lib = OpaqueLibrary.Require();
        byte[] encoded = NulTerminatedUtf8(password);
        try
        {
            nint handle = lib.RegistrationStart(encoded, out nint request);
            return handle == nint.Zero
                ? throw NetworkError.FromMessage(
                    "OPAQUE: " + LastError(lib, "registration could not be started"))
                : new RegistrationExchange(lib, handle, Take(lib, request));
        }
        finally
        {
            Array.Clear(encoded);
        }
    }

    /// <summary>Blinds <paramref name="password"/> to open a login.</summary>
    /// <param name="password">
    /// The account password; every copy this SDK makes is cleared, but not the caller's.
    /// </param>
    /// <returns>An exchange whose <see cref="LoginExchange.Ke1"/> goes to <c>login/start</c>.</returns>
    /// <exception cref="NetworkError">The library is unavailable or refuses.</exception>
    public static LoginExchange StartLogin(char[] password)
    {
        ArgumentNullException.ThrowIfNull(password);

        IOpaqueNative lib = OpaqueLibrary.Require();
        byte[] encoded = NulTerminatedUtf8(password);
        try
        {
            nint handle = lib.LoginStart(encoded, out nint ke1);
            return handle == nint.Zero
                ? throw NetworkError.FromMessage(
                    "OPAQUE: " + LastError(lib, "login could not be started"))
                : new LoginExchange(lib, handle, Take(lib, ke1));
        }
        finally
        {
            Array.Clear(encoded);
        }
    }

    /// <summary>Takes ownership of a returned string, freeing the Rust allocation.</summary>
    /// <remarks>
    /// Called on every path that receives one, including the error paths: a binding that frees
    /// only on success leaks once per failed login, which is the login rate an installation
    /// under attack sees.
    /// </remarks>
    internal static string Take(IOpaqueNative lib, nint ptr)
    {
        if (ptr == nint.Zero)
        {
            throw NetworkError.FromMessage(
                "OPAQUE: " + LastError(lib, "the library returned no value"));
        }

        try
        {
            return Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
        }
        finally
        {
            lib.StringFree(ptr);
        }
    }

    /// <summary>The library's description of the last failure, or <paramref name="fallback"/>.</summary>
    /// <remarks>
    /// The returned pointer is borrowed — library-owned, not freed here. A failure with nothing
    /// behind it is a library bug, but a caller still deserves a sentence rather than an empty
    /// one.
    /// </remarks>
    internal static string LastError(IOpaqueNative lib, string fallback)
    {
        nint raw = lib.LastError();
        if (raw == nint.Zero)
        {
            return fallback;
        }

        string message = Marshal.PtrToStringUTF8(raw) ?? string.Empty;
        return string.IsNullOrEmpty(message) ? fallback : message;
    }

    /// <summary>
    /// Encodes a password as NUL-terminated UTF-8, without an intermediate <c>string</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// UTF-8 explicitly rather than through default string marshalling: a password that encoded
    /// differently under a different platform default would derive a randomized password no
    /// AXIAM server agrees with, and would surface as a wrong password on that machine only.
    /// </para>
    /// <para>
    /// No <c>string</c> because a <c>string</c> is immutable and cannot be cleared. The caller
    /// clears the returned array.
    /// </para>
    /// </remarks>
    internal static byte[] NulTerminatedUtf8(char[] password)
    {
        int length = Encoding.UTF8.GetByteCount(password);
        byte[] output = new byte[length + 1];
        Encoding.UTF8.GetBytes(password, 0, password.Length, output, 0);
        return output;
    }

    /// <summary>Encodes a hex protocol message as a NUL-terminated byte array.</summary>
    /// <remarks>
    /// Separate from <see cref="NulTerminatedUtf8"/> because these are not secrets and need no
    /// clearing — and because passing them through the same helper would suggest they do.
    /// </remarks>
    internal static byte[] NulTerminatedAscii(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);

        byte[] raw = Encoding.UTF8.GetBytes(hex);
        byte[] output = new byte[raw.Length + 1];
        raw.CopyTo(output, 0);
        return output;
    }
}
