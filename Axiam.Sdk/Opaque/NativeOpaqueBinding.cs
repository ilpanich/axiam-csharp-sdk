using System.Reflection;
using System.Runtime.InteropServices;

namespace Axiam.Sdk.Opaque;

/// <summary>
/// The real P/Invoke binding to <c>libaxiam_opaque_ffi</c>.
/// </summary>
/// <remarks>
/// <para>
/// <c>[DllImport]</c> rather than <c>[LibraryImport]</c>. The source generator behind
/// <c>LibraryImport</c> emits <c>fixed</c> blocks, which would oblige the whole assembly to
/// set <c>AllowUnsafeBlocks</c>. Widening what every file in this SDK is permitted to do, for
/// one binding of twelve entry points, is a worse trade than an analyzer suggestion.
/// </para>
/// <para>
/// The library is resolved through <see cref="NativeLibrary.SetDllImportResolver"/> so
/// <c>AXIAM_OPAQUE_LIBRARY</c> can point at a file the default probing would not find — the
/// normal case for a container image that ships it alongside the application rather than
/// installing it system-wide.
/// </para>
/// </remarks>
internal sealed class NativeOpaqueBinding : IOpaqueNative
{
    /// <summary>The base name .NET expands per platform.</summary>
    private const string LibraryName = "axiam_opaque_ffi";

    static NativeOpaqueBinding()
    {
        NativeLibrary.SetDllImportResolver(
            Assembly.GetExecutingAssembly(),
            static (name, assembly, searchPath) =>
            {
                if (name != LibraryName)
                {
                    return nint.Zero;
                }

                string? over = OpaqueLibrary.PathOverride();
                if (!string.IsNullOrWhiteSpace(over) && NativeLibrary.TryLoad(over, out nint handle))
                {
                    return handle;
                }

                // Zero hands the request back to the default resolver rather than
                // failing here — an override that does not load must not stop a
                // correctly installed system library from being found.
                return nint.Zero;
            });
    }

    /// <inheritdoc/>
    public void StringFree(nint ptr) => axiam_opaque_string_free(ptr);

    /// <inheritdoc/>
    public nint LastError() => axiam_opaque_last_error();

    /// <inheritdoc/>
    public int Available() => axiam_opaque_available();

    /// <inheritdoc/>
    public nint KsfArgon2id(uint memoryKib, uint iterations, uint parallelism) =>
        axiam_opaque_ksf_argon2id(memoryKib, iterations, parallelism);

    /// <inheritdoc/>
    public nint KsfScrypt(byte logN, uint r, uint p) => axiam_opaque_ksf_scrypt(logN, r, p);

    /// <inheritdoc/>
    public void KsfFree(nint ptr) => axiam_opaque_ksf_free(ptr);

    /// <inheritdoc/>
    public nint RegistrationStart(byte[] password, out nint outRequest) =>
        axiam_opaque_registration_start(password, out outRequest);

    /// <inheritdoc/>
    public nint RegistrationFinish(nint state, byte[] password, byte[] registrationResponse, nint ksf) =>
        axiam_opaque_registration_finish(state, password, registrationResponse, ksf, nint.Zero);

    /// <inheritdoc/>
    public void RegistrationFree(nint ptr) => axiam_opaque_registration_free(ptr);

    /// <inheritdoc/>
    public nint LoginStart(byte[] password, out nint outKe1) =>
        axiam_opaque_login_start(password, out outKe1);

    /// <inheritdoc/>
    public nint LoginFinish(nint state, byte[] password, byte[] ke2, nint ksf) =>
        axiam_opaque_login_finish(state, password, ke2, ksf, nint.Zero, nint.Zero);

    /// <inheritdoc/>
    public void LoginFree(nint ptr) => axiam_opaque_login_free(ptr);

    // ------------------------------------------------------------------
    // The ABI. Every out-parameter that opaque.h declares `char **` and this
    // SDK does not use is passed as nint.Zero rather than omitted -- the C
    // signature is fixed, and "may be NULL" is a value, not an overload.
    // ------------------------------------------------------------------

    [DllImport(LibraryName)]
    private static extern void axiam_opaque_string_free(nint ptr);

    [DllImport(LibraryName)]
    private static extern nint axiam_opaque_last_error();

    [DllImport(LibraryName)]
    private static extern int axiam_opaque_available();

    [DllImport(LibraryName)]
    private static extern nint axiam_opaque_ksf_argon2id(uint memoryKib, uint iterations, uint parallelism);

    [DllImport(LibraryName)]
    private static extern nint axiam_opaque_ksf_scrypt(byte logN, uint r, uint p);

    [DllImport(LibraryName)]
    private static extern void axiam_opaque_ksf_free(nint ptr);

    [DllImport(LibraryName)]
    private static extern nint axiam_opaque_registration_start(byte[] password, out nint outRequest);

    [DllImport(LibraryName)]
    private static extern nint axiam_opaque_registration_finish(
        nint state,
        byte[] password,
        byte[] registrationResponse,
        nint ksf,
        nint outExportKey);

    [DllImport(LibraryName)]
    private static extern void axiam_opaque_registration_free(nint ptr);

    [DllImport(LibraryName)]
    private static extern nint axiam_opaque_login_start(byte[] password, out nint outKe1);

    [DllImport(LibraryName)]
    private static extern nint axiam_opaque_login_finish(
        nint state,
        byte[] password,
        byte[] ke2,
        nint ksf,
        nint outSessionKey,
        nint outExportKey);

    [DllImport(LibraryName)]
    private static extern void axiam_opaque_login_free(nint ptr);
}
