using Axiam.Sdk.Management.Models;

namespace Axiam.Sdk.Management
{
    /// <summary>
    /// Local checks a generated &#167;27 operation runs before any I/O (the generator's
    /// <c>PRECHECKS</c> table). Nothing here performs I/O.
    /// </summary>
    internal static class ManagementChecks
    {
        /// <summary>
        /// CONTRACT.md &#167;29.2: <see cref="ParseSamlSpMetadata"/> carries <b>exactly one</b>
        /// of <c>metadata_xml</c> and <c>metadata_url</c>. Both or neither is a local
        /// <see cref="ValidationError"/>, raised before any request — never a request the
        /// server refuses.
        /// </summary>
        /// <param name="body">The request body.</param>
        /// <exception cref="ValidationError">Both members, or neither, are set.</exception>
        internal static void ParseSpMetadataExactlyOne(ParseSamlSpMetadata body)
        {
            ArgumentNullException.ThrowIfNull(body);
            bool hasXml = body.MetadataXml is not null;
            bool hasUrl = body.MetadataUrl is not null;
            if (hasXml == hasUrl)
            {
                string why = hasXml
                    ? "set exactly one of metadata_xml and metadata_url, not both (CONTRACT.md §29.2)"
                    : "set exactly one of metadata_xml and metadata_url (CONTRACT.md §29.2)";
                throw new ValidationError(
                    $"saml.parse_sp_metadata: {why}; no request was sent",
                    new[] { new FieldError(hasXml ? "metadata_xml" : "metadata_url", why) });
            }
        }
    }

    /// <summary>
    /// The read-modify-write form CONTRACT.md &#167;27.4 rule 5 recommends for a
    /// <c>replace</c> update: a read result turned back into the replacement body, every
    /// member carried over, so changing one member and sending it back preserves the rest.
    /// </summary>
    /// <remarks>
    /// No conversion carries a secret: the read types have none (&#167;29.5, &#167;30.2,
    /// &#167;31.2, &#167;32.5), so <see cref="SetDirectoryConfig.BindSecret"/>,
    /// <see cref="SsfStreamInput.AuthorizationHeader"/> and
    /// <see cref="ScimTargetInput.Credential"/> come back <b>absent</b> — which, on the update
    /// that follows, means "keep the stored one" (subject to the connection-move rules each
    /// section states). Set one with a <c>with</c>-expression when the write moves the
    /// connection.
    /// </remarks>
    public static class ManagementReplacements
    {
        /// <summary>A <see cref="SamlServiceProvider"/> as the body that replaces it with itself.</summary>
        /// <param name="sp">The service provider as read.</param>
        /// <returns>The replacement body, every member carried over.</returns>
        public static SamlServiceProviderInput ToInput(this SamlServiceProvider sp)
        {
            ArgumentNullException.ThrowIfNull(sp);
            return new SamlServiceProviderInput
            {
                AcsUrls = sp.AcsUrls,
                AllowIdpInitiated = sp.AllowIdpInitiated,
                AllowedGroups = sp.AllowedGroups,
                AttributeMappings = sp.AttributeMappings,
                DisplayName = sp.DisplayName,
                Enabled = sp.Enabled,
                EncryptAssertions = sp.EncryptAssertions,
                EntityId = sp.EntityId,
                NameIdFormat = sp.NameIdFormat,
                SignResponses = sp.SignResponses,
                SloBinding = sp.SloBinding,
                SloUrl = sp.SloUrl,
                SpEncryptionCertPem = sp.SpEncryptionCertPem,
                SpSigningCertPem = sp.SpSigningCertPem,
                WantAuthnRequestsSigned = sp.WantAuthnRequestsSigned,
            };
        }

        /// <summary>
        /// An <see cref="SsfStream"/> as the body that replaces it with itself;
        /// <c>authorization_header</c> absent (keeps the stored one).
        /// </summary>
        /// <param name="stream">The stream as read.</param>
        /// <returns>The replacement body.</returns>
        public static SsfStreamInput ToInput(this SsfStream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);
            return new SsfStreamInput
            {
                Audience = stream.Audience,
                DeliveryMethod = stream.DeliveryMethod,
                Description = stream.Description,
                EndpointUrl = stream.EndpointUrl,
                EventsAllowed = stream.EventsAllowed,
                EventsRequested = stream.EventsRequested,
                ReceiverClientId = stream.ReceiverClientId,
                Status = stream.Status,
                StatusReason = stream.StatusReason,
                SubjectFormat = stream.SubjectFormat,
            };
        }

        /// <summary>
        /// A <see cref="ScimTargetResponse"/> as the body that replaces it with itself;
        /// <c>credential</c> absent (keeps the stored one), and <c>expected_updated_at</c> the
        /// <c>updated_at</c> it was read with, so the update is refused <c>409</c> if another
        /// administrator wrote the target in between (CONTRACT.md &#167;31.3 rule 4).
        /// </summary>
        /// <remarks>
        /// The version is the server's own string when the target came from this SDK's
        /// <c>ScimTargets</c> calls, because the server compares it for equality at nanosecond
        /// precision and <see cref="DateTimeOffset"/> keeps 100 ns. For a target built any other
        /// way it is <see cref="ScimTargetResponse.UpdatedAt"/> in the round-trip format. Set
        /// <see cref="ScimTargetInput.ExpectedUpdatedAt"/> to <c>null</c> with a
        /// <c>with</c>-expression for a last-writer-wins replacement.
        /// </remarks>
        /// <param name="target">The target as read.</param>
        /// <returns>The replacement body.</returns>
        public static ScimTargetInput ToInput(this ScimTargetResponse target)
        {
            ArgumentNullException.ThrowIfNull(target);
            return new ScimTargetInput
            {
                Auth = target.Auth,
                BaseUrl = target.BaseUrl,
                Deprovision = target.Deprovision,
                Enabled = target.Enabled,
                ExpectedUpdatedAt = target.UpdatedAtAsRead
                    ?? target.UpdatedAt.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                Name = target.Name,
                PushGroups = target.PushGroups,
                Scope = target.Scope,
                UserNameFrom = target.UserNameFrom,
            };
        }

        /// <summary>
        /// A <see cref="DirectoryConfig"/> as the <c>directory.set</c> body that replaces it
        /// with itself; <c>bind_secret</c> absent (keeps the stored one).
        /// </summary>
        /// <param name="config">The configuration as read.</param>
        /// <returns>The replacement body.</returns>
        public static SetDirectoryConfig ToInput(this DirectoryConfig config)
        {
            ArgumentNullException.ThrowIfNull(config);
            return new SetDirectoryConfig
            {
                BaseDn = config.BaseDn,
                BindDn = config.BindDn,
                Enabled = config.Enabled,
                GroupBaseDn = config.GroupBaseDn,
                GroupFilter = config.GroupFilter,
                GroupMappings = config.GroupMappings,
                GroupMemberAttribute = config.GroupMemberAttribute,
                GroupNestingDepth = config.GroupNestingDepth,
                JitProvisioning = config.JitProvisioning,
                Kind = config.Kind,
                StartTls = config.StartTls,
                SyncIntervalSecs = config.SyncIntervalSecs,
                TrustAnchorsPem = config.TrustAnchorsPem,
                Url = config.Url,
                UserAttributeMap = config.UserAttributeMap,
                UserFilter = config.UserFilter,
            };
        }
    }
}

namespace Axiam.Sdk.Management.Models
{
    /// <summary>
    /// A read model that keeps a member's wire string next to its parsed value; the decoder
    /// (<c>ManagementSupport.Decode</c>) hands it the string.
    /// </summary>
    internal interface IKeepsWireVersion
    {
        /// <summary>The wire member whose string is kept.</summary>
        string WireMember { get; }

        /// <summary>This value with <paramref name="asRead"/> kept.</summary>
        /// <param name="asRead">The member's string, exactly as the server sent it.</param>
        /// <returns>A copy carrying it.</returns>
        object WithWireVersion(string asRead);
    }

    /// <content>
    /// <c>updated_at</c> exactly as the server sent it, for the <c>expected_updated_at</c> of
    /// the read-modify-write form (CONTRACT.md &#167;31.3 rule 4).
    /// </content>
    public sealed partial record ScimTargetResponse : IKeepsWireVersion
    {
        /// <summary>
        /// <c>updated_at</c> as the server sent it, nanoseconds and all; <c>null</c> for a
        /// target this SDK did not decode itself.
        /// </summary>
        [System.Text.Json.Serialization.JsonIgnore]
        internal string? UpdatedAtAsRead { get; init; }

        string IKeepsWireVersion.WireMember => "updated_at";

        object IKeepsWireVersion.WithWireVersion(string asRead) => this with { UpdatedAtAsRead = asRead };
    }

    /// <content>
    /// The two ways to build a valid <c>saml.parse_sp_metadata</c> body (CONTRACT.md
    /// &#167;29.2: exactly one member).
    /// </content>
    public sealed partial record ParseSamlSpMetadata
    {
        /// <summary>
        /// A request for the server to fetch the SP's metadata from <paramref name="url"/>
        /// (<c>https</c> only, through its SSRF guard).
        /// </summary>
        /// <param name="url">The metadata URL.</param>
        /// <returns>A body carrying <c>metadata_url</c> only.</returns>
        public static ParseSamlSpMetadata FromUrl(string url)
        {
            ArgumentNullException.ThrowIfNull(url);
            return new ParseSamlSpMetadata { MetadataUrl = url };
        }

        /// <summary>A request carrying the SP's metadata document itself (at most 512 KiB).</summary>
        /// <param name="xml">The metadata document.</param>
        /// <returns>A body carrying <c>metadata_xml</c> only.</returns>
        public static ParseSamlSpMetadata FromXml(string xml)
        {
            ArgumentNullException.ThrowIfNull(xml);
            return new ParseSamlSpMetadata { MetadataXml = xml };
        }
    }
}
