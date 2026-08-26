using System.Text.Json;
using System.Text.Json.Serialization;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Management;

/// <summary>
/// Reads a &#167;27 secret off the wire into a <see cref="Sensitive{T}"/>, and writes it
/// back <b>redacted</b> (CONTRACT.md &#167;27.5).
/// </summary>
/// <remarks>
/// The SDK's default <c>SensitiveJsonConverter</c> throws on read, because before
/// &#167;27 no response body ever carried a secret the caller was meant to keep. &#167;27
/// changes that: a generated private key, a fresh client secret and a SCIM provisioning
/// token are each returned by exactly one call and never again, so they have to survive
/// deserialization. Writing still redacts, so re-serializing a response model for a log
/// line renders <c>"[SENSITIVE]"</c> — matching <see cref="Sensitive{T}.ToString"/>, so
/// the two renderings cannot disagree.
/// </remarks>
internal sealed class ManagementSensitiveReadConverter : JsonConverter<Sensitive<string>>
{
    /// <inheritdoc />
    public override Sensitive<string> Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => Sensitive.Of(reader.GetString() ?? string.Empty);

    /// <inheritdoc />
    public override void Write(
        Utf8JsonWriter writer, Sensitive<string> value, JsonSerializerOptions options)
        => writer.WriteStringValue("[SENSITIVE]");
}

/// <summary>
/// Writes a &#167;27 secret out <b>in the clear</b> — the one place a
/// <see cref="Sensitive{T}"/> is allowed to reach a socket (CONTRACT.md &#167;27.5,
/// &#167;7 rule 4).
/// </summary>
/// <remarks>
/// <para>
/// Registered on exactly one <see cref="JsonSerializerOptions"/>,
/// <see cref="ManagementJson.Wire"/>. Keeping it to a single registration is what makes
/// "a &#167;27 secret goes on the wire here" one greppable place instead of fourteen
/// request types with a hand-written wire twin.
/// </para>
/// <para>
/// This works because <c>System.Text.Json</c> resolves a converter registered in
/// <see cref="JsonSerializerOptions.Converters"/> <em>ahead of</em> a
/// <see cref="JsonConverterAttribute"/> on the target type. That precedence is the
/// opposite of Jackson's, where a class-level annotation beats a module-registered
/// serializer — the sibling Java SDK hit exactly that trap and needed a mixin. A test
/// pins the behaviour here rather than trusting the documented order.
/// </para>
/// </remarks>
internal sealed class ManagementSensitiveWriteConverter : JsonConverter<Sensitive<string>>
{
    /// <inheritdoc />
    public override Sensitive<string> Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => Sensitive.Of(reader.GetString() ?? string.Empty);

    /// <inheritdoc />
    public override void Write(
        Utf8JsonWriter writer, Sensitive<string> value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.Expose());
}

/// <summary>
/// The two <see cref="JsonSerializerOptions"/> the &#167;27 surface uses, and nothing
/// else does.
/// </summary>
internal static class ManagementJson
{
    /// <summary>
    /// Reads &#167;27 responses. Secrets deserialize into <see cref="Sensitive{T}"/>,
    /// and re-serializing one renders <c>"[SENSITIVE]"</c>.
    /// </summary>
    internal static readonly JsonSerializerOptions Reader = Build(exposeSecrets: false);

    /// <summary>
    /// The ONE writer that serializes a <see cref="Sensitive{T}"/> in the clear.
    /// </summary>
    /// <remarks>
    /// <see cref="JsonIgnoreCondition.WhenWritingNull"/> is what gives CONTRACT.md
    /// &#167;27.4 rule 5 its teeth: a sparse body's components all default to
    /// <c>null</c>, so a property the caller never named is absent from the JSON
    /// entirely rather than sent as <c>null</c> — which the server reads as "clear this
    /// field". A replacement body has no nullable components, so every one of its
    /// fields is written.
    /// </remarks>
    internal static readonly JsonSerializerOptions Wire = Build(exposeSecrets: true);

    private static JsonSerializerOptions Build(bool exposeSecrets)
    {
        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNameCaseInsensitive = false,
        };
        if (exposeSecrets)
        {
            options.Converters.Add(new ManagementSensitiveWriteConverter());
        }
        else
        {
            options.Converters.Add(new ManagementSensitiveReadConverter());
        }

        return options;
    }
}
