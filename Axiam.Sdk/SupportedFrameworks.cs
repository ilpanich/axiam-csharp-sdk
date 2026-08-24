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
/// package with a <c>lib/net8.0</c> folder installs happily into a
/// <c>net10.0</c> project and runs there under roll-forward, whether or not
/// anybody ever built or tested it on that runtime.
/// </para>
/// <para>
/// These values name both ends, so a deployment preflight or a startup assertion
/// can report which of them the running process is actually on. See
/// <c>examples/VersionCompatibility</c>.
/// </para>
/// <para>
/// <c>VersionPolicyTests</c> asserts these against the
/// <c>&lt;TargetFrameworks&gt;</c> in <c>Axiam.Sdk.csproj</c> and against the CI
/// workflow, so they cannot drift from what is actually built.
/// </para>
/// </remarks>
public static class SupportedFrameworks
{
    /// <summary>
    /// The oldest target framework the SDK is built against.
    /// </summary>
    /// <remarks>
    /// .NET 8 reaches end of support on 10 November 2026. When it does, this
    /// moves to <c>net10.0</c> and the <c>net8.0</c> leg is dropped from
    /// <c>&lt;TargetFrameworks&gt;</c>; <c>VersionPolicyTests</c> fails the build
    /// on that date rather than leaving it to be noticed.
    /// </remarks>
    public const string Floor = "net8.0";

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
    public static IReadOnlyList<string> All { get; } = new[] { Floor, Newest };
}
