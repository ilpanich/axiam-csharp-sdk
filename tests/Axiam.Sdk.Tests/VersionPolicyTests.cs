using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Language-version support policy — the target frameworks this SDK claims,
/// builds, and runs on.
/// </summary>
/// <remarks>
/// <para>
/// "Which .NET does this SDK support?" is declared in several places that
/// nothing compares: <c>&lt;TargetFrameworks&gt;</c> in each <c>.csproj</c> (what
/// NuGet enforces at restore time), the SDK versions installed by the CI
/// workflows (what is actually compiled), <c>docfx.json</c> (which framework the
/// published API reference is extracted from), and
/// <see cref="SupportedFrameworks"/> (the only one a consumer can read at run
/// time).
/// </para>
/// <para>
/// Before this suite existed every project targeted <c>net8.0</c> alone — a
/// framework that reaches <b>end of support on 10 November 2026</b>. Nothing in
/// the build said so, and nothing would have: a <c>lib/net8.0</c> package
/// installs into a <c>net10.0</c> project and runs there under roll-forward,
/// so the gap is invisible from both sides until the security updates stop.
/// </para>
/// <para>
/// The policy pinned here is floor + newest. In .NET that is expressed by
/// multi-targeting rather than by a CI matrix: one build produces both
/// <c>lib/</c> folders, and <c>dotnet test</c> runs the whole suite once per
/// target framework — including this class, on each of them.
/// </para>
/// </remarks>
[Trait("Category", "Fast")]
public sealed class VersionPolicyTests
{
    /// <summary>
    /// End-of-support dates for the .NET releases this policy can reason about,
    /// from https://dotnet.microsoft.com/platform/support/policy/dotnet-core.
    /// </summary>
    /// <remarks>
    /// A hardcoded table needs occasional maintenance, but the alternative — a
    /// comparison against a number somebody typed once — silently stops meaning
    /// anything on the day that release goes out of support, which is exactly
    /// the failure this whole class exists to prevent.
    /// </remarks>
    private static readonly IReadOnlyDictionary<string, DateTime> EndOfSupport =
        new Dictionary<string, DateTime>(StringComparer.Ordinal)
        {
            ["net6.0"] = new DateTime(2024, 11, 12, 0, 0, 0, DateTimeKind.Utc),
            ["net7.0"] = new DateTime(2024, 5, 14, 0, 0, 0, DateTimeKind.Utc),
            ["net8.0"] = new DateTime(2026, 11, 10, 0, 0, 0, DateTimeKind.Utc),
            ["net9.0"] = new DateTime(2026, 11, 10, 0, 0, 0, DateTimeKind.Utc),
            ["net10.0"] = new DateTime(2028, 11, 14, 0, 0, 0, DateTimeKind.Utc),
        };

    /// <summary>
    /// Projects whose <c>&lt;TargetFrameworks&gt;</c> must list exactly the
    /// supported set: the two published packages, both test projects, and every
    /// example. An example that stops building on one end of the range is a
    /// consumability regression on that end.
    /// </summary>
    private static IEnumerable<string> AllProjectFiles(string root)
    {
        yield return Path.Combine(root, "Axiam.Sdk", "Axiam.Sdk.csproj");
        yield return Path.Combine(root, "Axiam.Sdk.AspNetCore", "Axiam.Sdk.AspNetCore.csproj");

        foreach (string dir in new[] { "tests", "examples" })
        {
            string path = Path.Combine(root, dir);
            if (!Directory.Exists(path))
            {
                continue;
            }

            foreach (string project in Directory.EnumerateFiles(path, "*.csproj", SearchOption.AllDirectories))
            {
                yield return project;
            }
        }
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Axiam.Sdk.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException(
            "could not locate the repository root (Axiam.Sdk.sln not found in any ancestor of the test assembly)");
    }

    private static IReadOnlyList<string> TargetFrameworksOf(string csprojPath)
    {
        string text = File.ReadAllText(csprojPath);

        Match multi = Regex.Match(text, @"<TargetFrameworks>([^<]*)</TargetFrameworks>");
        if (multi.Success)
        {
            return multi.Groups[1].Value
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        Match single = Regex.Match(text, @"<TargetFramework>([^<]*)</TargetFramework>");
        Assert.True(
            single.Success,
            $"{Path.GetFileName(csprojPath)} declares neither <TargetFramework> nor <TargetFrameworks>");

        return new[] { single.Groups[1].Value.Trim() };
    }

    /// <summary>
    /// Every project in the repository targets exactly the supported set.
    /// </summary>
    /// <remarks>
    /// This is the assertion that keeps examples honest. A published package can
    /// multi-target correctly while the examples still pin the old framework, at
    /// which point nothing proves the SDK is usable from an application on the
    /// newest runtime — which is the claim examples exist to make.
    /// </remarks>
    [Fact]
    public void EveryProjectTargetsExactlyTheSupportedFrameworks()
    {
        string root = FindRepoRoot();
        var expected = SupportedFrameworks.All.ToArray();
        var offenders = new List<string>();

        foreach (string project in AllProjectFiles(root))
        {
            Assert.True(File.Exists(project), $"expected project to exist: {project}");

            string[] actual = TargetFrameworksOf(project).ToArray();
            if (!actual.SequenceEqual(expected))
            {
                offenders.Add(
                    $"{Path.GetRelativePath(root, project)}: [{string.Join(", ", actual)}]");
            }
        }

        Assert.True(
            offenders.Count == 0,
            $"expected every project to target [{string.Join(", ", expected)}], but:{Environment.NewLine}"
            + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// The floor is a .NET release that still receives security updates.
    /// </summary>
    /// <remarks>
    /// This fails on the day the floor goes out of support, not whenever
    /// somebody next thinks to look. .NET 8 reaches end of support on
    /// 10 November 2026 — so this test turns red on 11 November 2026 and the
    /// fix is to drop the <c>net8.0</c> leg.
    /// </remarks>
    [Fact]
    public void FloorStillReceivesSecurityUpdates()
    {
        Assert.True(
            EndOfSupport.ContainsKey(SupportedFrameworks.Floor),
            $"{SupportedFrameworks.Floor} has no end-of-support date in this test's table. "
            + "Add it from https://dotnet.microsoft.com/platform/support/policy/dotnet-core "
            + "rather than removing the check.");

        DateTime eol = EndOfSupport[SupportedFrameworks.Floor];
        Assert.True(
            eol > DateTime.UtcNow,
            $"the declared floor, {SupportedFrameworks.Floor}, reached end of support on "
            + $"{eol:yyyy-MM-dd} and no longer receives security updates. Drop it from "
            + "<TargetFrameworks> in every project and raise SupportedFrameworks.Floor.");
    }

    /// <summary>
    /// The newest target framework outlives the floor — otherwise "newest" is not.
    /// </summary>
    [Fact]
    public void NewestOutlivesTheFloor()
    {
        Assert.True(EndOfSupport.ContainsKey(SupportedFrameworks.Newest));
        Assert.True(
            EndOfSupport[SupportedFrameworks.Newest] > EndOfSupport[SupportedFrameworks.Floor],
            $"{SupportedFrameworks.Newest} does not outlive {SupportedFrameworks.Floor}");
    }

    /// <summary>
    /// CI installs an SDK for every target framework the projects declare.
    /// </summary>
    /// <remarks>
    /// Multi-targeting fails at build time without the matching targeting pack,
    /// so a missing SDK entry is loud rather than silent — but it is loud in a
    /// way that reads as an unrelated MSBuild error (NETSDK1045). Naming the
    /// real cause here saves that diagnosis.
    /// </remarks>
    [Theory]
    [InlineData(".github/workflows/sdk-ci-csharp.yml")]
    [InlineData(".github/workflows/coverage.yml")]
    [InlineData(".github/workflows/docs-publish.yml")]
    public void CiInstallsAnSdkForEveryTargetFramework(string workflowPath)
    {
        string root = FindRepoRoot();
        string full = Path.Combine(root, workflowPath);
        Assert.True(File.Exists(full), $"expected workflow to exist: {full}");

        string yaml = File.ReadAllText(full);

        foreach (string tfm in SupportedFrameworks.All)
        {
            // "net8.0" -> "8.0.x", the setup-dotnet channel form.
            string channel = tfm.Replace("net", string.Empty, StringComparison.Ordinal) + ".x";
            Assert.True(
                yaml.Contains(channel, StringComparison.Ordinal),
                $"{workflowPath} never installs a {channel} SDK, but the projects target {tfm}");
        }
    }

    /// <summary>
    /// The published API reference is extracted from a supported framework.
    /// </summary>
    [Fact]
    public void DocfxExtractsASupportedTargetFramework()
    {
        string root = FindRepoRoot();
        string docfx = File.ReadAllText(Path.Combine(root, "docfx.json"));

        Match match = Regex.Match(docfx, @"""TargetFramework""\s*:\s*""([^""]+)""");
        Assert.True(match.Success, "docfx.json declares no TargetFramework for metadata extraction");

        Assert.Contains(match.Groups[1].Value, SupportedFrameworks.All);
    }

    /// <summary>
    /// The framework this test assembly was compiled for is one the SDK claims.
    /// </summary>
    /// <remarks>
    /// <c>dotnet test</c> runs the suite once per target framework, so this
    /// executes on each leg and closes the loop from the running side: whichever
    /// framework the build produced, <see cref="SupportedFrameworks"/> lists it.
    /// </remarks>
    [Fact]
    public void RunningTargetFrameworkIsDeclaredSupported()
    {
#if NET8_0
        const string running = "net8.0";
#elif NET10_0
        const string running = "net10.0";
#else
        const string running = "unknown";
#endif
        Assert.Contains(running, SupportedFrameworks.All);
    }
}
