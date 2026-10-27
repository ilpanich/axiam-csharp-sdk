using System.Collections.Generic;

namespace Axiam.Sdk;

/// <summary>
/// The target frameworks this SDK is built and tested against.
/// </summary>
/// <remarks>
/// <para>
/// NuGet already enforces the lower bound at restore time — the package ships a
/// <c>lib/</c> folder per target framework and refuses to install into a project
/// targeting anything older. What it does not tell you is the *upper* end: a
/// package with a <c>lib/net10.0</c> folder installs happily into a
/// <c>net11.0</c> project and runs there under roll-forward, whether or not
/// anybody ever built or tested it on that runtime.
/// </para>
/// <para>
/// These values name both ends, so a deployment preflight or a startup assertion
/// can report which of them the running process is actually on. See
/// <c>examples/VersionCompatibility</c>.
/// </para>
/// <para>
/// <c>VersionPolicyTests</c> asserts these against the
/// <c>&lt;TargetFramework&gt;</c> (or <c>&lt;TargetFrameworks&gt;</c>) in <c>Axiam.Sdk.csproj</c> and against the CI
/// workflow, so they cannot drift from what is actually built.
/// </para>
/// </remarks>
public static class SupportedFrameworks
{
    /// <summary>
    /// The oldest target framework the SDK is built against.
    /// </summary>
    /// <remarks>
    /// .NET 10 is an LTS release, supported through November 2028. It became the
    /// floor when the <c>net8.0</c> leg was dropped ahead of .NET 8's end of
    /// support on 10 November 2026. <c>VersionPolicyTests</c> fails the build on
    /// the day the floor lapses rather than leaving it to be noticed.
    /// </remarks>
    public const string Floor = "net10.0";

    /// <summary>
    /// The newest target framework the SDK is built and tested against.
    /// </summary>
    /// <remarks>
    /// .NET 10 is an LTS release, supported through November 2028.
    /// </remarks>
    public const string Newest = "net10.0";

    /// <summary>
    /// Every target framework the package ships a <c>lib/</c> folder for, oldest first.
    /// </summary>
    /// <remarks>
    /// While <see cref="Floor"/> and <see cref="Newest"/> name the same framework
    /// the package ships a single <c>lib/</c> folder, and this lists it once.
    /// </remarks>
    public static IReadOnlyList<string> All { get; } =
        Floor == Newest ? new[] { Floor } : new[] { Floor, Newest };
}
