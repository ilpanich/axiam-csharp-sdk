using Axiam.Sdk.Core;

namespace Axiam.Sdk.Opaque;

/// <summary>
/// Loads <c>libaxiam_opaque_ffi</c> once per process, memoizing failure as well as success.
/// </summary>
/// <remarks>
/// <para>
/// The library is a Rust <c>cdylib</c> published as a per-platform asset of the AXIAM release,
/// not a NuGet package — there is no cross-language registry to put it on. A consumer whose
/// tenant does not use OPAQUE should not be made to carry a native artifact, so its absence is
/// normal and <see cref="OpaqueProtocol.Available"/> reports <c>false</c> rather than throwing. An
/// application can then choose the password path up front instead of discovering the gap
/// mid-login.
/// </para>
/// <para>
/// Memoizing the failure matters as much as memoizing the success: retrying the load on every
/// login is a per-request filesystem walk for a file that is not going to appear.
/// </para>
/// </remarks>
internal static class OpaqueLibrary
{
    /// <summary>Overrides the search: an absolute path to the shared library.</summary>
    internal const string PathEnvironmentVariable = "AXIAM_OPAQUE_LIBRARY";

    private static readonly object Gate = new();

    private static IOpaqueNative? _library;
    private static bool _attempted;

    /// <summary>The override path, or <c>null</c>. Read by the DllImport resolver.</summary>
    internal static string? PathOverride() =>
        Environment.GetEnvironmentVariable(PathEnvironmentVariable);

    /// <summary>The library, or <c>null</c> when it is not present.</summary>
    internal static IOpaqueNative? Load()
    {
        lock (Gate)
        {
            if (_attempted)
            {
                return _library;
            }

            _attempted = true;
            _library = Probe();
            return _library;
        }
    }

    /// <summary>
    /// Loads and then actually calls into the library.
    /// </summary>
    /// <remarks>
    /// The call is the point. A .NET P/Invoke does not resolve until first use, so a binding
    /// that only constructed the object would report "present" and then throw at login. It also
    /// catches the name-collision case — some other library of the same name on the search path
    /// loads fine and is missing our symbols, which is an
    /// <see cref="EntryPointNotFoundException"/> and must be treated as absent rather than
    /// called into.
    /// </remarks>
    private static IOpaqueNative? Probe()
    {
        try
        {
            var binding = new NativeOpaqueBinding();
            _ = binding.Available();
            return binding;
        }
        catch (DllNotFoundException)
        {
            return null;
        }
        catch (EntryPointNotFoundException)
        {
            return null;
        }
        catch (BadImageFormatException)
        {
            // A library for the wrong architecture. Present, unusable, and not
            // something to keep retrying.
            return null;
        }
    }

    /// <summary>The library, or a refusal naming the artifact.</summary>
    /// <remarks>
    /// Never an <see cref="AuthError"/>: absent is a deployment fact, and reporting it as a
    /// credential failure would send a user off to reset a password that works.
    /// </remarks>
    internal static IOpaqueNative Require() =>
        Load() ?? throw NetworkError.FromMessage(
            "OPAQUE is not available: the shared library `libaxiam_opaque_ffi` could not be " +
            "loaded. Download the asset for your platform from the axiam release page, then " +
            "put it where the runtime probes for native libraries or set " +
            PathEnvironmentVariable + " to its full path.");

    /// <summary>Installs a binding, bypassing the loader. Test-only.</summary>
    internal static void SetForTests(IOpaqueNative? stub)
    {
        lock (Gate)
        {
            _library = stub;
            _attempted = true;
        }
    }

    /// <summary>Forgets the memoized load. Test-only.</summary>
    internal static void ResetForTests()
    {
        lock (Gate)
        {
            _library = null;
            _attempted = false;
        }
    }
}
