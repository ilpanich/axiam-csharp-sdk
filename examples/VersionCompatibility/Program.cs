// VersionCompatibility — reports the running .NET runtime against the target
// frameworks this SDK is built and tested against.
//
// NuGet enforces the lower bound at restore time: the package ships a lib/ folder
// per target framework and refuses to install into a project targeting anything
// older. It says nothing about the upper end, and that silence is the interesting
// case — a lib/net8.0 assembly installs happily into a net10.0 project and runs
// there under roll-forward, whether or not anyone ever built or tested it on that
// runtime. "It restored, so it is supported" does not follow.
//
// This example reads Axiam.Sdk.SupportedFrameworks rather than hardcoding
// versions, so it stays correct across SDK upgrades.
//
// Run: dotnet run --project examples/VersionCompatibility
//      dotnet run --project examples/VersionCompatibility -f net10.0

using System;
using System.Linq;
using System.Runtime.InteropServices;
using Axiam.Sdk;

// The target framework THIS example was compiled for. Determined at compile
// time, because that is the question that matters: which lib/ folder of the SDK
// did the build actually bind against?
#if NET8_0
const string compiledFor = "net8.0";
#elif NET10_0
const string compiledFor = "net10.0";
#else
const string compiledFor = "unknown";
#endif

Console.WriteLine($"compiled against:  {compiledFor}");
Console.WriteLine($"running runtime:   {RuntimeInformation.FrameworkDescription}");
Console.WriteLine($"SDK floor:         {SupportedFrameworks.Floor}");
Console.WriteLine($"SDK newest:        {SupportedFrameworks.Newest}");
Console.WriteLine($"SDK ships lib/:    {string.Join(", ", SupportedFrameworks.All)}");

if (!SupportedFrameworks.All.Contains(compiledFor))
{
    // Reaching here means the app bound to a lib/ folder the SDK no longer
    // claims — a stale package restored from a local NuGet cache, most likely.
    Console.Error.WriteLine(
        $"UNSUPPORTED: this application was compiled against {compiledFor}, which "
        + "this SDK does not ship a lib/ folder for.");
    return 1;
}

// Environment.Version reports the runtime that is actually executing, which is
// not necessarily the one the assembly was compiled for: .NET rolls forward, so
// a net8.0 assembly commonly runs on a .NET 10 host.
int runningMajor = Environment.Version.Major;
int compiledMajor = int.Parse(compiledFor.Replace("net", string.Empty).Split('.')[0]);

if (runningMajor > compiledMajor)
{
    Console.WriteLine(
        $"ROLL-FORWARD: compiled for {compiledFor} but running on .NET {runningMajor}. "
        + "Supported — the SDK ships a lib/ folder for that runtime too, and CI "
        + "builds and tests it. Rebuilding against it avoids the roll-forward.");
}
else
{
    Console.WriteLine($"SUPPORTED: {compiledFor} is a framework this SDK builds and tests.");
}

if (compiledFor == SupportedFrameworks.Floor)
{
    // Worth saying out loud rather than leaving to a release note: the floor is
    // the leg that gets dropped first.
    Console.WriteLine(
        $"NOTE: {SupportedFrameworks.Floor} is the oldest framework this SDK "
        + "supports and will be dropped when it goes out of support. Consider "
        + $"retargeting to {SupportedFrameworks.Newest}.");
}

return 0;
