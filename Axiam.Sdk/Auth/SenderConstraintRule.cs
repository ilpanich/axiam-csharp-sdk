using System.Security.Cryptography;
using System.Text;

namespace Axiam.Sdk.Auth;

/// <summary>
/// CONTRACT.md &#167;10.1 rule 9's ten-case table, extracted to ONE implementation shared
/// by every entry point that has to apply it — <see cref="JwksVerifier.VerifyTokenBinding"/>
/// (local JSON claims) and <see cref="Grpc.TokenGrpcClient"/> (gRPC <c>CnfClaim</c>
/// messages) both delegate here rather than each re-deriving the same table from a
/// differently-shaped source. CONTRACT.md &#167;10.3 rule 1 requires exactly this: "local
/// verification and gRPC validation share one implementation... so the two cannot
/// disagree about whether a token is a bearer token."
/// </summary>
internal static class SenderConstraintRule
{
    /// <summary>
    /// The shared core. <paramref name="cnfPresent"/> distinguishes "no <c>cnf</c> claim
    /// at all" (an ordinary bearer token, accepted unconditionally — the table's top row)
    /// from "a <c>cnf</c> claim is present", whatever its members hold —
    /// <paramref name="x5tS256"/>/<paramref name="jkt"/> empty or null there is
    /// CONTRACT.md &#167;10.3 rule 3's "an empty <c>CnfClaim</c> MUST be refused, not read
    /// as unbound" (proto3 cannot express "absent string", so an empty one is the wire
    /// spelling of &#167;10.1 rule 9's "names neither" row).
    /// </summary>
    internal static bool Verify(bool cnfPresent, string? x5tS256, string? jkt, PresentedProofs proofs)
    {
        if (!cnfPresent)
        {
            return true; // an ordinary bearer token
        }

        string? expectedCert = string.IsNullOrEmpty(x5tS256) ? null : x5tS256;
        string? expectedJkt = string.IsNullOrEmpty(jkt) ? null : jkt;

        if (expectedCert is null && expectedJkt is null)
        {
            // Present but names neither method this entry point can check (including
            // both empty) — an unverifiable constraint, never "unconstrained".
            return false;
        }

        // Each arm that applies must pass. Two independent checks rather than a switch
        // on the pair, precisely so "both named" needs no case of its own — it is simply
        // where both run (a conjunction, not a disjunction — CONTRACT.md §10.1 rule 9
        // detail 2).
        if (expectedCert is not null)
        {
            if (string.IsNullOrEmpty(proofs.CertificateThumbprint) ||
                !CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expectedCert),
                    Encoding.ASCII.GetBytes(proofs.CertificateThumbprint)))
            {
                return false;
            }
        }

        if (expectedJkt is not null)
        {
            if (string.IsNullOrEmpty(proofs.DpopThumbprint) ||
                !CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expectedJkt),
                    Encoding.ASCII.GetBytes(proofs.DpopThumbprint)))
            {
                return false;
            }
        }

        return true;
    }
}
