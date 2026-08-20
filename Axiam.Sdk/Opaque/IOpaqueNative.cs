namespace Axiam.Sdk.Opaque;

/// <summary>
/// The <c>libaxiam_opaque_ffi</c> C ABI, exactly as <c>include/axiam/opaque.h</c> declares it.
/// </summary>
/// <remarks>
/// <para>
/// An interface in front of the P/Invoke declarations rather than the declarations themselves,
/// for one reason: it is what a test can implement. The contract this ABI carries is about
/// <i>ownership</i> — who frees a returned string, when a state handle is spent, what a null
/// pointer means. Those are the rules a binding gets wrong, and they can be exercised
/// exhaustively against a stand-in without the real shared library present.
/// </para>
/// <para>
/// Strings cross as NUL-terminated UTF-8 <c>byte[]</c>, never as <c>string</c>. .NET's default
/// string marshalling on this platform is not guaranteed to be UTF-8, and a password that
/// round-tripped differently would produce a randomized password no AXIAM server agrees with —
/// surfacing as a wrong password on that machine only. The conformance vectors require UTF-8.
/// </para>
/// </remarks>
internal interface IOpaqueNative
{
    /// <summary>Releases a string this library returned. Rust allocated it; Rust frees it.</summary>
    void StringFree(nint ptr);

    /// <summary>
    /// Describes the last failure. The pointer is borrowed — library-owned, never freed here.
    /// </summary>
    nint LastError();

    /// <summary>Nonzero when this build can perform OPAQUE.</summary>
    int Available();

    /// <summary>Builds an Argon2id handle, or returns zero when the parameters are refused.</summary>
    nint KsfArgon2id(uint memoryKib, uint iterations, uint parallelism);

    /// <summary>Builds a scrypt handle, or returns zero when the parameters are refused.</summary>
    nint KsfScrypt(byte logN, uint r, uint p);

    /// <summary>Releases a key-stretching handle.</summary>
    void KsfFree(nint ptr);

    /// <summary>
    /// Begins an enrolment, writing the hex <c>RegistrationRequest</c> to
    /// <paramref name="outRequest"/>.
    /// </summary>
    nint RegistrationStart(byte[] password, out nint outRequest);

    /// <summary>
    /// Completes an enrolment, <b>consuming</b> <paramref name="state"/> whether it succeeds or
    /// fails. Returns the hex <c>RegistrationRecord</c>, or zero.
    /// </summary>
    nint RegistrationFinish(nint state, byte[] password, byte[] registrationResponse, nint ksf);

    /// <summary>Releases enrolment state that was never finished.</summary>
    void RegistrationFree(nint ptr);

    /// <summary>Begins a login, writing the hex <c>KE1</c> to <paramref name="outKe1"/>.</summary>
    nint LoginStart(byte[] password, out nint outKe1);

    /// <summary>
    /// Completes a login, <b>consuming</b> <paramref name="state"/>. Returns the hex
    /// <c>KE3</c>, or zero.
    /// </summary>
    /// <remarks>
    /// A zero return is the whole of the client's authentication check, and it covers both
    /// halves of the mutual authentication: the envelope only opens under the right password,
    /// and <c>KE2</c>'s MAC only verifies if the server actually holds the record. Per
    /// CONTRACT.md &#167;23.4 rule 7 nothing may be sent to <c>login/finish</c> after it.
    /// </remarks>
    nint LoginFinish(nint state, byte[] password, byte[] ke2, nint ksf);

    /// <summary>Releases login state that was never finished.</summary>
    void LoginFree(nint ptr);
}
