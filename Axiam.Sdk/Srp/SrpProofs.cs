namespace Axiam.Sdk.Srp;

/// <summary>The two proofs an SRP exchange produces (CONTRACT.md &#167;23.2).</summary>
/// <remarks>
/// <see cref="ClientProof"/> goes on the verify request. <see cref="ExpectedServerProof"/>
/// stays here and is compared against the response's <c>server_proof</c>: that comparison is
/// the half of SRP that authenticates the <i>server</i>, and &#167;23.3 rule 6 makes it
/// mandatory.
/// </remarks>
/// <param name="ClientProof"><c>M1</c>, lowercase hex.</param>
/// <param name="ExpectedServerProof">The <c>M2</c> the server must return.</param>
public sealed record SrpProofs(string ClientProof, string ExpectedServerProof);
