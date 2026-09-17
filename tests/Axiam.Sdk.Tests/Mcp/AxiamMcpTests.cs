using Axiam.Sdk.Management;
using Axiam.Sdk.Mcp;
using Xunit;

namespace Axiam.Sdk.Tests.Mcp;

/// <summary>
/// CONTRACT.md &#167;28.9 required tests 1 and 2 &#8212; the two that are
/// framework-independent: document shape and its validation negatives
/// (<see cref="AxiamMcp.ProtectedResourceMetadata"/>), and challenge quoting and its
/// refusals (<see cref="AxiamMcp.BearerChallenge"/>). Both run against &#167;28.9's own
/// fixture, reused verbatim so a divergence from another SDK's port shows up as a
/// different expected value rather than a different test.
/// </summary>
[Trait("Category", "Fast")]
public sealed class AxiamMcpTests
{
    // ------------------------------------------------------------------
    // §28.9's fixture, verbatim.
    // ------------------------------------------------------------------
    private const string Resource = "https://mcp.example.com/mcp";
    private static readonly string[] AuthorizationServers = { "https://axiam.example.com" };
    private static readonly string[] ScopesSupported = { "mcp:read", "mcp:tools" };
    private const string ResourceDocumentation = "https://mcp.example.com/docs";
    private const string MetadataPath = "/.well-known/oauth-protected-resource/mcp";
    private const string MetadataUrl = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";

    private static ProtectedResourceMetadataOptions Fixture() => new()
    {
        Resource = Resource,
        AuthorizationServers = AuthorizationServers,
        ScopesSupported = ScopesSupported,
        ResourceDocumentation = ResourceDocumentation,
    };

    // ------------------------------------------------------------------
    // Test 1a: document shape (the positive).
    // ------------------------------------------------------------------

    [Fact]
    public void ProtectedResourceMetadata_Fixture_ProducesTheExactDocumentAndDerivedValues()
    {
        ProtectedResourceMetadata metadata = AxiamMcp.ProtectedResourceMetadata(Fixture());

        Assert.Equal(Resource, metadata.Document.Resource);
        Assert.Equal(AuthorizationServers, metadata.Document.AuthorizationServers);
        Assert.Equal(ScopesSupported, metadata.Document.ScopesSupported);
        Assert.Equal(new[] { "header" }, metadata.Document.BearerMethodsSupported);
        Assert.Equal(ResourceDocumentation, metadata.Document.ResourceDocumentation);
        Assert.Equal(MetadataPath, metadata.MetadataPath);
        Assert.Equal(MetadataUrl, metadata.MetadataUrl);
    }

    // ------------------------------------------------------------------
    // Test 1b: §28.3's five metadata_path derivations.
    // ------------------------------------------------------------------

    [Theory]
    [InlineData("https://mcp.example.com", "/.well-known/oauth-protected-resource")]
    [InlineData("https://mcp.example.com/", "/.well-known/oauth-protected-resource")]
    [InlineData("https://mcp.example.com/mcp", "/.well-known/oauth-protected-resource/mcp")]
    [InlineData("https://mcp.example.com/mcp/", "/.well-known/oauth-protected-resource/mcp/")]
    [InlineData("https://mcp.example.com/a/b", "/.well-known/oauth-protected-resource/a/b")]
    public void MetadataPath_IsDerivedFromTheResource_PerTheFiveWorkedExamples(string resource, string expectedPath)
    {
        ProtectedResourceMetadata metadata = AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = resource,
            AuthorizationServers = AuthorizationServers,
            ScopesSupported = ScopesSupported,
        });

        Assert.Equal(expectedPath, metadata.MetadataPath);
        Assert.Equal(new Uri(resource).GetLeftPart(UriPartial.Authority) + expectedPath, metadata.MetadataUrl);
    }

    // ------------------------------------------------------------------
    // Test 1c: validation negatives — each a ValidationError, no route (nothing to
    // register, since this is the pure operation the route derives from).
    // ------------------------------------------------------------------

    [Fact]
    public void RelativeResource_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = "/mcp",
            AuthorizationServers = AuthorizationServers,
            ScopesSupported = ScopesSupported,
        }));
    }

    [Fact]
    public void ResourceWithFragment_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = "https://mcp.example.com/mcp#frag",
            AuthorizationServers = AuthorizationServers,
            ScopesSupported = ScopesSupported,
        }));
    }

    [Fact]
    public void ResourceWithQuery_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = "https://mcp.example.com/mcp?x=1",
            AuthorizationServers = AuthorizationServers,
            ScopesSupported = ScopesSupported,
        }));
    }

    [Fact]
    public void HttpResource_OnANonLoopbackHost_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = "http://mcp.example.com/mcp",
            AuthorizationServers = AuthorizationServers,
            ScopesSupported = ScopesSupported,
        }));
    }

    [Fact]
    public void HttpResource_On127001_IsAccepted()
    {
        ProtectedResourceMetadata metadata = AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = "http://127.0.0.1/mcp",
            AuthorizationServers = AuthorizationServers,
            ScopesSupported = ScopesSupported,
        });

        Assert.Equal("http://127.0.0.1/.well-known/oauth-protected-resource/mcp", metadata.MetadataUrl);
    }

    [Fact]
    public void EmptyAuthorizationServers_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = Resource,
            AuthorizationServers = Array.Empty<string>(),
            ScopesSupported = ScopesSupported,
        }));
    }

    [Fact]
    public void AuthorizationServersEntry_WithAQuery_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = Resource,
            AuthorizationServers = new[] { "https://axiam.example.com?tenant_id=acme" },
            ScopesSupported = ScopesSupported,
        }));
    }

    [Fact]
    public void AuthorizationServersEntry_WithAFragment_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = Resource,
            AuthorizationServers = new[] { "https://axiam.example.com#x" },
            ScopesSupported = ScopesSupported,
        }));
    }

    [Fact]
    public void DuplicateAuthorizationServersEntry_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = Resource,
            AuthorizationServers = new[] { "https://axiam.example.com", "https://axiam.example.com" },
            ScopesSupported = ScopesSupported,
        }));
    }

    [Fact]
    public void DuplicateScope_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = Resource,
            AuthorizationServers = AuthorizationServers,
            ScopesSupported = new[] { "mcp:read", "mcp:read" },
        }));
    }

    [Theory]
    [InlineData("query")]
    [InlineData("header,body")]
    public void BearerMethodsSupported_OtherThanExactlyHeader_IsRefused(string encoded)
    {
        string[] methods = encoded.Split(',');
        Assert.Throws<ValidationError>(() => AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = Resource,
            AuthorizationServers = AuthorizationServers,
            ScopesSupported = ScopesSupported,
            BearerMethodsSupported = methods,
        }));
    }

    [Fact]
    public void EmptyScopesSupported_IsAccepted_AndOmitsTheMember()
    {
        ProtectedResourceMetadata metadata = AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = Resource,
            AuthorizationServers = AuthorizationServers,
            ScopesSupported = Array.Empty<string>(),
        });

        Assert.Null(metadata.Document.ScopesSupported);
        Assert.DoesNotContain("scopes_supported", System.Text.Json.JsonSerializer.Serialize(metadata.Document));
    }

    [Fact]
    public void AbsentResourceDocumentation_OmitsTheMember_RatherThanEmittingNull()
    {
        ProtectedResourceMetadata metadata = AxiamMcp.ProtectedResourceMetadata(new ProtectedResourceMetadataOptions
        {
            Resource = Resource,
            AuthorizationServers = AuthorizationServers,
            ScopesSupported = ScopesSupported,
        });

        Assert.Null(metadata.Document.ResourceDocumentation);
        // Serialized JSON must not contain the key at all — a `null` value is exactly
        // what §28.2 rule 7 forbids.
        string json = System.Text.Json.JsonSerializer.Serialize(metadata.Document);
        Assert.DoesNotContain("resource_documentation", json);
    }

    // ------------------------------------------------------------------
    // Test 2a: the four §28.4 challenge vectors, exact strings.
    // ------------------------------------------------------------------

    [Fact]
    public void Vector1_NoCredentialPresented()
    {
        string challenge = AxiamMcp.BearerChallenge(new BearerChallengeOptions { ResourceMetadataUrl = MetadataUrl });

        Assert.Equal($"Bearer resource_metadata=\"{MetadataUrl}\"", challenge);
    }

    [Fact]
    public void Vector2_CredentialPresentedAndRejected()
    {
        string challenge = AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = MetadataUrl,
            Error = AxiamBearerChallengeError.InvalidToken,
        });

        Assert.Equal($"Bearer error=\"invalid_token\", resource_metadata=\"{MetadataUrl}\"", challenge);
    }

    [Fact]
    public void Vector3_ScopeFailure403()
    {
        string challenge = AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = MetadataUrl,
            Error = AxiamBearerChallengeError.InsufficientScope,
            Scope = "mcp:tools",
        });

        Assert.Equal($"Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"{MetadataUrl}\"", challenge);
    }

    [Fact]
    public void Vector4_AllFourParameters()
    {
        string challenge = AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = MetadataUrl,
            Error = AxiamBearerChallengeError.InvalidRequest,
            ErrorDescription = "The access token is malformed",
            Scope = "mcp:read mcp:tools",
        });

        Assert.Equal(
            $"Bearer error=\"invalid_request\", error_description=\"The access token is malformed\", scope=\"mcp:read mcp:tools\", resource_metadata=\"{MetadataUrl}\"",
            challenge);
    }

    // ------------------------------------------------------------------
    // Test 2b: the refusals — each a ValidationError, asserting no escaping occurred
    // (the exception is raised rather than a challenge containing `\"`).
    // ------------------------------------------------------------------

    [Fact]
    public void ErrorOfInvalidGrant_IsRefused()
    {
        var ex = Assert.Throws<ValidationError>(() => AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = MetadataUrl,
            Error = "invalid_grant",
        }));
        Assert.DoesNotContain("invalid_grant\\", ex.Message);
    }

    [Fact]
    public void ErrorDescription_ContainingAQuote_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = MetadataUrl,
            ErrorDescription = "bad \"token\"",
        }));
    }

    [Fact]
    public void ErrorDescription_ContainingABackslash_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = MetadataUrl,
            ErrorDescription = "bad\\token",
        }));
    }

    [Fact]
    public void ErrorDescription_ContainingANewline_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = MetadataUrl,
            ErrorDescription = "bad\ntoken",
        }));
    }

    [Fact]
    public void ErrorDescription_ContainingNonAscii_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = MetadataUrl,
            ErrorDescription = "bad töken",
        }));
    }

    [Fact]
    public void Scope_WithALeadingSpace_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = MetadataUrl,
            Scope = " mcp:read",
        }));
    }

    [Fact]
    public void Scope_WithADoubledSpace_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = MetadataUrl,
            Scope = "mcp:read  mcp:tools",
        }));
    }

    [Fact]
    public void Scope_Empty_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = MetadataUrl,
            Scope = string.Empty,
        }));
    }

    [Fact]
    public void ResourceMetadata_ContainingASpace_IsRefused()
    {
        Assert.Throws<ValidationError>(() => AxiamMcp.BearerChallenge(new BearerChallengeOptions
        {
            ResourceMetadataUrl = "https://mcp.example.com/a b",
        }));
    }
}
