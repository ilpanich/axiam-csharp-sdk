using System.Text.Json;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// CONTRACT.md &#167;27.13 (contract 1.51): the two generated-DTO shapes C-1's EXECUTED
/// block (item 2) flagged as generator traps, pinned here with real
/// <see cref="System.Text.Json.JsonSerializer"/> round-trips rather than trusted by
/// inspection. Both were wrong in the reference generator before this port's fix; §27.13
/// item 3 asks every SDK to check them.
/// </summary>
[Trait("Category", "Fast")]
public sealed class Contract151ModelsTests
{
    // ---- SubjectAltName: {"dns": …} / {"ip": …}, never {} -----------------

    [Fact]
    public void ADnsSubjectAltNameSerializesAsDnsNeverAsAnEmptyObject()
    {
        SubjectAltName san = SubjectAltName.Dns("api.lakeside.internal");
        string json = JsonSerializer.Serialize(san);
        Assert.Equal("{\"dns\":\"api.lakeside.internal\"}", json);
        Assert.NotEqual("{}", json);
    }

    [Fact]
    public void AnIpSubjectAltNameSerializesAsIpNeverAsAnEmptyObject()
    {
        SubjectAltName san = SubjectAltName.Ip("10.0.0.5");
        string json = JsonSerializer.Serialize(san);
        Assert.Equal("{\"ip\":\"10.0.0.5\"}", json);
        Assert.NotEqual("{}", json);
    }

    [Fact]
    public void ASubjectAltNameListRoundTripsThroughCreateCertificateRequest()
    {
        var request = new CreateCertificateRequest
        {
            IssuerCaId = Guid.NewGuid(),
            Subject = "svc-1",
            CertType = CertificateType.Server,
            KeyAlgorithm = KeyAlgorithm.Ed25519,
            ValidityDays = 90,
            SubjectAltNames = new List<SubjectAltName>
            {
                SubjectAltName.Dns("api.lakeside.internal"),
                SubjectAltName.Ip("10.0.0.5"),
            },
        };

        string json = JsonSerializer.Serialize(request, ManagementJson.Wire);
        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement sans = doc.RootElement.GetProperty("subject_alt_names");
        Assert.Equal(2, sans.GetArrayLength());
        Assert.Equal("api.lakeside.internal", sans[0].GetProperty("dns").GetString());
        Assert.Equal("10.0.0.5", sans[1].GetProperty("ip").GetString());
        // Neither entry serialized as an empty object -- the defect this test exists to
        // catch produces exactly `{}` for every arm.
        Assert.NotEqual(0, sans[0].EnumerateObject().Count());
        Assert.NotEqual(0, sans[1].EnumerateObject().Count());

        CreateCertificateRequest? decoded = JsonSerializer.Deserialize<CreateCertificateRequest>(json, ManagementJson.Wire);
        Assert.NotNull(decoded);
        Assert.Equal(2, decoded!.SubjectAltNames!.Count);
        Assert.IsType<SubjectAltName.DnsArm>(decoded.SubjectAltNames[0]);
        Assert.IsType<SubjectAltName.IpArm>(decoded.SubjectAltNames[1]);
        Assert.Equal("api.lakeside.internal", ((SubjectAltName.DnsArm)decoded.SubjectAltNames[0]).Value);
        Assert.Equal("10.0.0.5", ((SubjectAltName.IpArm)decoded.SubjectAltNames[1]).Value);
    }

    [Fact]
    public void ASubjectAltNameNamingNeitherKeyIsRefused()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<SubjectAltName>("{\"uri\":\"x\"}"));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<SubjectAltName>("{}"));
    }

    // ---- inherit: absent on a role-side listing decodes as true, never false --------

    private static UserResponse SampleUser() => new()
    {
        Id = Guid.NewGuid(),
        Username = "alice",
        Email = "alice@example.com",
        EmailVerified = true,
        FailedLoginAttempts = 0,
        IsLocked = false,
        MfaEnabled = false,
        Status = UserStatus.Active,
        TenantId = Guid.NewGuid(),
        CreatedAt = DateTimeOffset.UtcNow,
        UpdatedAt = DateTimeOffset.UtcNow,
        Metadata = JsonDocument.Parse("{}").RootElement,
    };

    private static Role SampleRole() => new()
    {
        Id = Guid.NewGuid(),
        Name = "editor",
        Description = "",
        IsGlobal = false,
        TenantId = Guid.NewGuid(),
        CreatedAt = DateTimeOffset.UtcNow,
        UpdatedAt = DateTimeOffset.UtcNow,
    };

    /// <summary>
    /// Builds a wire object for <paramref name="innerKey"/> = <paramref name="inner"/>
    /// with NO <c>inherit</c> key at all -- the shape every pre-1.51 server's role-side
    /// listing sent, since the field did not exist yet.
    /// </summary>
    private static string WireWithoutInherit(string innerKey, object inner)
    {
        string innerJson = JsonSerializer.Serialize(inner, ManagementJson.Wire);
        return $$"""{"{{innerKey}}": {{innerJson}} }""";
    }

    [Fact]
    public void ARoleUserAssignmentWithNoInheritFieldOnTheWireDecodesTrue()
    {
        // A pre-1.51 server -- the shape every deployed row had before the field
        // existed. §27.13 S-10 rule 3: MUST read absent as true, MUST NOT read it as
        // false, and (the generator defect this pins) MUST NOT throw either.
        string wire = WireWithoutInherit("user", SampleUser());

        RoleUserAssignment? decoded = JsonSerializer.Deserialize<RoleUserAssignment>(wire, ManagementJson.Wire);
        Assert.NotNull(decoded);
        Assert.True(decoded!.Inherit);
    }

    [Fact]
    public void ARoleUserAssignmentWithInheritFalseOnTheWireDecodesFalse()
    {
        UserResponse user = SampleUser();
        var assignment = new { inherit = false, user };
        string wire = JsonSerializer.Serialize(assignment, ManagementJson.Wire);

        RoleUserAssignment? decoded = JsonSerializer.Deserialize<RoleUserAssignment>(wire, ManagementJson.Wire);
        Assert.NotNull(decoded);
        Assert.False(decoded!.Inherit);
    }

    [Fact]
    public void ARoleAssignmentSubjectSideListingWithNoInheritFieldDecodesTrue()
    {
        string wire = WireWithoutInherit("role", SampleRole());

        RoleAssignment? decoded = JsonSerializer.Deserialize<RoleAssignment>(wire, ManagementJson.Wire);
        Assert.NotNull(decoded);
        Assert.True(decoded!.Inherit);
    }

    [Fact]
    public void AnAssignRoleToUserRequestOmitsInheritWhenTrueAndSendsItWhenFalse()
    {
        // §27.6.1 rule 2 / §27.13 S-10 rule 1: an inheritable assignment's body stays
        // byte-for-byte a pre-1.51 body -- `inherit` MUST NOT be sent explicitly as true.
        var inheritable = new AssignRoleToUserRequest { UserId = Guid.NewGuid() };
        string inheritableJson = JsonSerializer.Serialize(inheritable, ManagementJson.Wire);
        Assert.DoesNotContain("inherit", inheritableJson);

        var scoped = new AssignRoleToUserRequest
        {
            UserId = Guid.NewGuid(),
            ResourceId = Guid.NewGuid(),
            Inherit = false,
        };
        string scopedJson = JsonSerializer.Serialize(scoped, ManagementJson.Wire);
        Assert.Contains("\"inherit\":false", scopedJson);
    }
}
