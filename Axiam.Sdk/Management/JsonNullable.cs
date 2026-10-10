using System.Text.Json;
using System.Text.Json.Serialization;

namespace Axiam.Sdk.Management;

/// <summary>
/// A value that can be an explicit JSON <c>null</c> as well as a value — the third state a
/// &#167;27 body needs where <c>null</c> on the wire means something different from absence
/// (CONTRACT.md &#167;27.4 rule 5, "null is not absent").
/// </summary>
/// <typeparam name="T">The value's type.</typeparam>
/// <remarks>
/// <para>
/// A property typed <c>JsonNullable&lt;T&gt;?</c> has three states:
/// </para>
/// <list type="bullet">
///   <item><c>null</c> (the property was never set) — <b>absent</b>: omitted from a request
///   body, and what a response that did not carry the member decodes to;</item>
///   <item><see cref="Null"/> — an explicit JSON <c>null</c>: sent as <c>null</c> (on
///   <c>directory.update</c> and <c>federation.update_config</c> that <b>clears</b> the stored
///   value), and what a response that
///   carried <c>null</c> decodes to;</item>
///   <item><see cref="Of"/> (or an implicit conversion from <typeparamref name="T"/>) — a
///   value.</item>
/// </list>
/// <para>
/// Only these members of the surface use it, by name (the generator's
/// <c>EXPLICIT_NULL_FIELDS</c>): <c>UpdateDirectoryConfig.GroupBaseDn</c> and
/// <c>.GroupFilter</c> (&#167;30.2: an explicit <c>null</c> clears); the ten nullable members of
/// <c>UpdateFederationConfigRequest</c> — <c>MetadataUrl</c>, <c>IdpSigningCertPem</c>,
/// <c>IdpMetadataSigningCertPem</c>, <c>ProviderSlug</c>, <c>AuthorizationEndpoint</c>,
/// <c>TokenEndpoint</c>, <c>UserinfoEndpoint</c>, <c>AppleTeamId</c>, <c>AppleKeyId</c> and
/// <c>ButtonIcon</c> (&#167;27.15 note 8: an explicit <c>null</c> clears); and
/// <c>SamlIdpInfo.ActiveCredentialId</c> and <c>.NextCredentialId</c> (&#167;29.8 test 8: a
/// <c>null</c> slot is kept apart from an absent member). Every other nullable member keeps
/// the surface's ordinary "null means absent" reading.
/// </para>
/// <para>
/// An implicit conversion from a <c>null</c> reference (a <c>string?</c> variable holding
/// <c>null</c>, say) yields <see cref="Null"/>: a value was assigned, and it was null. Leave the
/// property unset to send nothing.
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonNullableConverterFactory))]
public sealed class JsonNullable<T> : IEquatable<JsonNullable<T>>
{
    private readonly T? _value;

    private JsonNullable(bool isNull, T? value)
    {
        IsNull = isNull;
        _value = value;
    }

    /// <summary>The explicit JSON <c>null</c>.</summary>
    public static JsonNullable<T> Null { get; } = new(true, default);

    /// <summary>Whether this is the explicit JSON <c>null</c>.</summary>
    public bool IsNull { get; }

    /// <summary>The value, or <c>default</c> when <see cref="IsNull"/>.</summary>
    public T? Value => _value;

    /// <summary>A present value; a <c>null</c> reference becomes <see cref="Null"/>.</summary>
    /// <param name="value">The value.</param>
    /// <returns>The wrapped value.</returns>
    public static JsonNullable<T> Of(T? value) => value is null ? Null : new JsonNullable<T>(false, value);

    /// <summary>Wraps <paramref name="value"/>; see <see cref="Of"/>.</summary>
    /// <param name="value">The value.</param>
    public static implicit operator JsonNullable<T>(T? value) => Of(value);

    /// <inheritdoc />
    public bool Equals(JsonNullable<T>? other) =>
        other is not null && IsNull == other.IsNull && EqualityComparer<T?>.Default.Equals(_value, other._value);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as JsonNullable<T>);

    /// <inheritdoc />
    public override int GetHashCode() => IsNull ? 0 : EqualityComparer<T?>.Default.GetHashCode(_value!);

    /// <summary><c>null</c> for the explicit null, otherwise the value's own rendering.</summary>
    /// <returns>The rendering.</returns>
    public override string ToString() => IsNull ? "null" : _value?.ToString() ?? "null";
}

/// <summary>Builds the converter for a closed <see cref="JsonNullable{T}"/>.</summary>
public sealed class JsonNullableConverterFactory : JsonConverterFactory
{
    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert.IsGenericType && typeToConvert.GetGenericTypeDefinition() == typeof(JsonNullable<>);

    /// <inheritdoc />
    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options) =>
        (JsonConverter)Activator.CreateInstance(
            typeof(JsonNullableConverter<>).MakeGenericType(typeToConvert.GetGenericArguments()[0]))!;
}

/// <summary>
/// Reads JSON <c>null</c> as <see cref="JsonNullable{T}.Null"/> (never as an absent value) and
/// writes <see cref="JsonNullable{T}.Null"/> as JSON <c>null</c>.
/// </summary>
/// <typeparam name="T">The value's type.</typeparam>
public sealed class JsonNullableConverter<T> : JsonConverter<JsonNullable<T>>
{
    /// <summary>Called for a JSON <c>null</c> too, which is the point.</summary>
    public override bool HandleNull => true;

    /// <inheritdoc />
    public override JsonNullable<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => reader.TokenType == JsonTokenType.Null
            ? JsonNullable<T>.Null
            : JsonNullable<T>.Of(JsonSerializer.Deserialize<T>(ref reader, options));

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, JsonNullable<T>? value, JsonSerializerOptions options)
    {
        if (value is null || value.IsNull)
        {
            writer.WriteNullValue();
            return;
        }

        JsonSerializer.Serialize(writer, value.Value, options);
    }
}
