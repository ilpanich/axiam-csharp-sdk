using System.Reflection;
using System.Runtime.CompilerServices;
using System.Xml.Linq;
using Axiam.Sdk.Management;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// R-28 / CS-06 (CONTRACT.md &#167;27.4 rule 5, &#167;29.2): the generated documentation says
/// what the types do. Read from the compiled XML documentation, so a generator template that
/// drifts from the types fails here rather than in a reader's code.
/// </summary>
public sealed class GeneratedDocsTests
{
    private const string ModelsPrefix = "Axiam.Sdk.Management.Models.";

    private static readonly Assembly Sdk = typeof(AxiamClient).Assembly;

    private static readonly Lazy<Dictionary<string, string>> Docs = new(() =>
        XDocument.Load(Path.Combine(AppContext.BaseDirectory, "Axiam.Sdk.xml"))
            .Descendants("member")
            .ToDictionary(m => (string)m.Attribute("name")!, m => string.Join(" ", m.Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))));

    private static IEnumerable<(Type Type, string Doc)> ModelDocs() =>
        Docs.Value.Where(d => d.Key.StartsWith("T:" + ModelsPrefix, StringComparison.Ordinal))
            .Select(d => (Sdk.GetType(d.Key[2..]), d.Value))
            .Where(d => d.Item1 is not null)
            .Select(d => (d.Item1!, d.Value));

    private static bool IsRequired(PropertyInfo p) => p.GetCustomAttribute<RequiredMemberAttribute>() is not null;

    private static PropertyInfo[] Members(Type t) =>
        t.GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(p => p.Name != "EqualityContract").ToArray();

    /// <summary>A model that says every property is required has no optional property.</summary>
    [Fact]
    public void EveryPropertyIsRequiredOnlyWhereItIs()
    {
        List<(Type Type, string Doc)> claimed = ModelDocs()
            .Where(d => d.Doc.Contains("Every property is required", StringComparison.Ordinal)).ToList();
        Assert.All(claimed, d => Assert.All(Members(d.Type), p => Assert.True(
            IsRequired(p), $"{d.Type.Name} says every property is required, but {p.Name} is optional")));

        string saml = Docs.Value["T:" + ModelsPrefix + "SamlServiceProviderInput"];
        Assert.DoesNotContain("Every property is required", saml, StringComparison.Ordinal);
    }

    /// <summary>
    /// A model documented as a SPARSE body ("what you leave unset is left unchanged") is the
    /// body of an operation documented as a sparse update — never a parse request.
    /// </summary>
    [Fact]
    public void ASparseBodyIsTheBodyOfASparseUpdate()
    {
        HashSet<string> sparseUpdateBodies = Docs.Value
            .Where(d => d.Key.StartsWith("M:Axiam.Sdk.Management.", StringComparison.Ordinal) &&
                        d.Value.Contains("A SPARSE update", StringComparison.Ordinal))
            .SelectMany(d => d.Key.Split('(', ',', ')'))
            .Where(p => p.StartsWith(ModelsPrefix, StringComparison.Ordinal))
            .ToHashSet(StringComparer.Ordinal);
        Assert.NotEmpty(sparseUpdateBodies);

        List<(Type Type, string Doc)> claimed = ModelDocs()
            .Where(d => d.Doc.Contains("SPARSE body", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(claimed);
        Assert.All(claimed, d => Assert.True(
            sparseUpdateBodies.Contains(d.Type.FullName!),
            $"{d.Type.Name} is documented as a SPARSE body but is no sparse update's body"));

        string parse = Docs.Value["T:" + ModelsPrefix + "ParseSamlSpMetadata"];
        Assert.DoesNotContain("left unchanged", parse, StringComparison.Ordinal);
    }

    /// <summary>
    /// A replacement whose body has optional members does not claim "every field of the body
    /// is written": an unset member is omitted from the wire (&#167;27.4 rule 5).
    /// </summary>
    [Fact]
    public void AReplacementDoesNotClaimEveryFieldIsWritten()
    {
        var replacements = Docs.Value
            .Where(d => d.Key.StartsWith("M:Axiam.Sdk.Management.", StringComparison.Ordinal) &&
                        d.Value.Contains("A REPLACEMENT", StringComparison.Ordinal))
            .ToList();
        Assert.NotEmpty(replacements);
        foreach ((string member, string doc) in replacements)
        {
            Type? body = member.Split('(', ',', ')')
                .Where(p => p.StartsWith(ModelsPrefix, StringComparison.Ordinal))
                .Select(p => Sdk.GetType(p))
                .FirstOrDefault(t => t is not null);
            if (body is not null && Members(body).Any(p => !IsRequired(p)))
            {
                Assert.False(
                    doc.Contains("every field of the body is written", StringComparison.Ordinal),
                    $"{member}: says every field is written, but {body.Name} has optional members");
            }
        }
    }

    /// <summary>The README's read-modify-write comment claims no secret for SAML, whose type has none.</summary>
    [Fact]
    public void TheReadmeSamlReadModifyWriteMentionsNoSecret()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "README.md")))
        {
            dir = dir.Parent;
        }

        string[] lines = File.ReadAllLines(Path.Combine(dir!.FullName, "README.md"));
        int read = Array.FindIndex(lines, l => l.Contains("await client.Saml.GetServiceProviderAsync(", StringComparison.Ordinal));
        Assert.True(read > 0, "the README's SAML read-modify-write example is missing");
        int comment = read - 1;
        while (comment >= 0 && lines[comment].TrimStart().StartsWith("//", StringComparison.Ordinal))
        {
            Assert.DoesNotContain("secret", lines[comment], StringComparison.OrdinalIgnoreCase);
            comment--;
        }

        Assert.Null(typeof(Axiam.Sdk.Management.Models.SamlServiceProviderInput).GetProperties()
            .FirstOrDefault(p => p.Name.Contains("Secret", StringComparison.Ordinal)));
    }
}
