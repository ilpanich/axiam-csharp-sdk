using System.Runtime.InteropServices;
using System.Text;
using Axiam.Sdk.Opaque;

namespace Axiam.Sdk.Tests.Fixtures;

/// <summary>
/// An in-process stand-in for <c>libaxiam_opaque_ffi</c>.
/// </summary>
/// <remarks>
/// <para>
/// CONTRACT.md &#167;23.1 forbids this SDK from implementing OPAQUE, so there is no
/// cryptography to test. What there is — and what this fake exists to exercise — is the ABI's
/// <i>contract</i>: every returned string is heap-allocated and must be freed exactly once with
/// <c>StringFree</c>; a state handle is CONSUMED by its <c>Finish</c>, success or failure; a
/// zero return means failure, described by <c>LastError</c>.
/// </para>
/// <para>
/// Requiring the real shared library would give a suite that runs only where a per-platform
/// release asset happens to be installed — and it would be testing <c>opaque-ke</c> rather than
/// this binding. Cross-implementation agreement is verified upstream by the conformance
/// vectors.
/// </para>
/// <para>
/// The pointers are real unmanaged allocations, so the binding's <c>Marshal.PtrToStringUTF8</c>
/// and its free discipline are exercised for what they are rather than mocked away. Every value
/// it returns is hex, as the real ABI's are: a fake that handed back raw bytes would let a
/// binding bug survive.
/// </para>
/// </remarks>
internal sealed class FakeOpaqueNative : IOpaqueNative, IDisposable
{
    private readonly HashSet<nint> _allocations = [];
    private readonly Dictionary<nint, string> _states = [];
    private readonly HashSet<string> _failing = [];
    private readonly Dictionary<string, string> _failMessages = [];

    private nint _nextHandle = 0x1000;
    private nint _lastErrorBuffer = nint.Zero;
    private string _lastError = string.Empty;

    /// <summary>Pointers passed to <c>StringFree</c>, in order.</summary>
    /// <remarks>A leak never appears here; a double free appears twice.</remarks>
    public List<nint> Freed { get; } = [];

    /// <summary>Key-stretching handles built and not yet released.</summary>
    /// <remarks>Must be zero after any <c>Finish</c>.</remarks>
    public int KsfAlive { get; private set; }

    /// <summary>What <c>Available</c> answers.</summary>
    public int AvailableValue { get; set; } = 1;

    /// <summary>State handles neither consumed nor released.</summary>
    public int StatesAlive => _states.Count;

    /// <summary>Allocations handed out and never freed.</summary>
    public int AllocationsAlive => _allocations.Count;

    /// <summary>Makes an entry point return zero instead of working.</summary>
    public void Fail(string entryPoint) => _failing.Add(entryPoint);

    /// <summary>Overrides what <c>LastError</c> reports for a failing entry point.</summary>
    /// <remarks>
    /// An empty string models a library that failed without saying why — a bug, but one the
    /// binding still has to produce a sentence for.
    /// </remarks>
    public void FailMessage(string entryPoint, string message) => _failMessages[entryPoint] = message;

    /// <summary>Decodes one of this fake's hex payloads.</summary>
    public static string Decode(string hex) => Encoding.UTF8.GetString(Convert.FromHexString(hex));

    // -- helpers -------------------------------------------------------

    private nint AllocateHex(string payload)
    {
        string hex = Convert.ToHexString(Encoding.UTF8.GetBytes(payload)).ToLowerInvariant();
        nint ptr = Marshal.StringToCoTaskMemUTF8(hex);
        _allocations.Add(ptr);
        return ptr;
    }

    private static string Read(byte[] nulTerminated)
    {
        int length = nulTerminated.Length;
        while (length > 0 && nulTerminated[length - 1] == 0)
        {
            length--;
        }

        return Encoding.UTF8.GetString(nulTerminated, 0, length);
    }

    private nint NewState(string kind)
    {
        _nextHandle += 0x10;
        _states[_nextHandle] = kind;
        return _nextHandle;
    }

    private void ConsumeState(nint handle, string kind)
    {
        if (!_states.Remove(handle, out string? actual) || actual != kind)
        {
            throw new InvalidOperationException(
                $"handle 0x{handle:x} was not a live {kind} (was {actual ?? "absent"})");
        }
    }

    private bool Failed(string entryPoint, string message)
    {
        if (!_failing.Contains(entryPoint))
        {
            return false;
        }

        _lastError = _failMessages.TryGetValue(entryPoint, out string? custom) ? custom : message;
        return true;
    }

    // -- the ABI -------------------------------------------------------

    /// <inheritdoc/>
    public void StringFree(nint ptr)
    {
        if (!_allocations.Remove(ptr))
        {
            throw new InvalidOperationException(
                $"free of 0x{ptr:x}, which this library never allocated (or already freed)");
        }

        Freed.Add(ptr);
        Marshal.FreeCoTaskMem(ptr);
    }

    /// <inheritdoc/>
    public nint LastError()
    {
        if (_lastError.Length == 0)
        {
            return nint.Zero;
        }

        // Borrowed, not freed by the caller -- so it is held here rather than
        // registered as an allocation, and released when this fake is disposed.
        if (_lastErrorBuffer != nint.Zero)
        {
            Marshal.FreeCoTaskMem(_lastErrorBuffer);
        }

        _lastErrorBuffer = Marshal.StringToCoTaskMemUTF8(_lastError);
        return _lastErrorBuffer;
    }

    /// <inheritdoc/>
    public int Available() => AvailableValue;

    /// <inheritdoc/>
    public nint KsfArgon2id(uint memoryKib, uint iterations, uint parallelism)
    {
        if (Failed("ksf_argon2id", "argon2id parameters rejected"))
        {
            return nint.Zero;
        }

        KsfAlive++;
        return (nint)(0xA0000 + memoryKib + iterations + parallelism);
    }

    /// <inheritdoc/>
    public nint KsfScrypt(byte logN, uint r, uint p)
    {
        if (Failed("ksf_scrypt", "scrypt parameters rejected"))
        {
            return nint.Zero;
        }

        KsfAlive++;
        return (nint)(0xB0000 + logN + r + p);
    }

    /// <inheritdoc/>
    public void KsfFree(nint ptr)
    {
        if (ptr == nint.Zero)
        {
            throw new InvalidOperationException("free of a null ksf handle");
        }

        KsfAlive--;
    }

    /// <inheritdoc/>
    public nint RegistrationStart(byte[] password, out nint outRequest)
    {
        if (Failed("registration_start", "registration could not be started"))
        {
            outRequest = nint.Zero;
            return nint.Zero;
        }

        outRequest = AllocateHex("req:" + Read(password));
        return NewState("registration");
    }

    /// <inheritdoc/>
    public nint RegistrationFinish(nint state, byte[] password, byte[] registrationResponse, nint ksf)
    {
        ConsumeState(state, "registration");
        if (Failed("registration_finish", "the envelope could not be sealed"))
        {
            return nint.Zero;
        }

        return AllocateHex(
            $"record:{Read(password)}:{Read(registrationResponse)}:{ksf:x}");
    }

    /// <inheritdoc/>
    public void RegistrationFree(nint ptr) => ConsumeState(ptr, "registration");

    /// <inheritdoc/>
    public nint LoginStart(byte[] password, out nint outKe1)
    {
        if (Failed("login_start", "login could not be started"))
        {
            outKe1 = nint.Zero;
            return nint.Zero;
        }

        outKe1 = AllocateHex("ke1:" + Read(password));
        return NewState("login");
    }

    /// <inheritdoc/>
    public nint LoginFinish(nint state, byte[] password, byte[] ke2, nint ksf)
    {
        ConsumeState(state, "login");
        if (Failed("login_finish", "the envelope did not open"))
        {
            return nint.Zero;
        }

        return AllocateHex($"ke3:{Read(password)}:{Read(ke2)}:{ksf:x}");
    }

    /// <inheritdoc/>
    public void LoginFree(nint ptr) => ConsumeState(ptr, "login");

    /// <summary>Releases anything the test left behind, so the suite itself does not leak.</summary>
    public void Dispose()
    {
        foreach (nint ptr in _allocations)
        {
            Marshal.FreeCoTaskMem(ptr);
        }

        _allocations.Clear();

        if (_lastErrorBuffer != nint.Zero)
        {
            Marshal.FreeCoTaskMem(_lastErrorBuffer);
            _lastErrorBuffer = nint.Zero;
        }
    }
}
