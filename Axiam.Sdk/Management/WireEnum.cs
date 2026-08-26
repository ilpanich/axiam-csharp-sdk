using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Management;

/// <summary>
/// The spelling an enum member has on the wire, when it differs from the C# name.
/// </summary>
/// <remarks>
/// <c>System.Text.Json</c> grew <c>JsonStringEnumMemberNameAttribute</c> in .NET 9, but
/// this SDK still targets <c>net8.0</c> as its floor — using it would raise the floor
/// for every consumer to buy nothing a four-line attribute does not already give. This
/// is that attribute, read by <see cref="WireEnumConverter{TEnum}"/>.
/// </remarks>
/// <param name="value">The exact string the server sends and expects.</param>
[AttributeUsage(AttributeTargets.Field)]
public sealed class WireNameAttribute(string value) : Attribute
{
    /// <summary>The exact string the server sends and expects.</summary>
    public string Value { get; } = value;
}

/// <summary>
/// Converts an enum to and from the wire spellings its members carry via
/// <see cref="WireNameAttribute"/>.
/// </summary>
/// <typeparam name="TEnum">The enum being converted.</typeparam>
/// <remarks>
/// An unknown value throws rather than silently mapping to the zero member. A server
/// that grew a new status is a fact the caller needs to see: quietly reading
/// <c>"suspended"</c> as whatever happens to be declared first would turn a new state
/// into a wrong one, and on this surface those states gate access.
/// </remarks>
public sealed class WireEnumConverter<TEnum> : JsonConverter<TEnum>
    where TEnum : struct, Enum
{
    private static readonly Dictionary<string, TEnum> FromWire = BuildFromWire();
    private static readonly Dictionary<TEnum, string> ToWire = BuildToWire();

    /// <inheritdoc />
    public override TEnum Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? raw = reader.GetString();
        if (raw is not null && FromWire.TryGetValue(raw, out TEnum value))
        {
            return value;
        }

        throw NetworkError.FromMessage(
            $"the server sent '{raw}' for {typeof(TEnum).Name}, which this SDK does not know. " +
            $"Known values: {string.Join(", ", FromWire.Keys)}. A newer server may have added " +
            "one; upgrading the SDK is the fix, and guessing would turn a new state into a " +
            "wrong one.");
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, TEnum value, JsonSerializerOptions options)
        => writer.WriteStringValue(ToWire.TryGetValue(value, out string? wire) ? wire : value.ToString());

    private static Dictionary<string, TEnum> BuildFromWire()
    {
        var map = new Dictionary<string, TEnum>(StringComparer.Ordinal);
        foreach ((string wire, TEnum value) in Members())
        {
            map[wire] = value;
        }

        return map;
    }

    private static Dictionary<TEnum, string> BuildToWire()
    {
        var map = new Dictionary<TEnum, string>();
        foreach ((string wire, TEnum value) in Members())
        {
            map[value] = wire;
        }

        return map;
    }

    private static IEnumerable<(string Wire, TEnum Value)> Members()
    {
        foreach (FieldInfo field in typeof(TEnum).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            var value = (TEnum)field.GetValue(null)!;
            string wire = field.GetCustomAttribute<WireNameAttribute>()?.Value ?? field.Name;
            yield return (wire, value);
        }
    }
}
