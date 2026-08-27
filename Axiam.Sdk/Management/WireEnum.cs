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
/// <para>
/// An unknown value decodes to the enum's <c>Unknown</c> member rather than throwing
/// (CONTRACT.md &#167;27.11 rule 1). Throwing fails the <b>whole</b> response, so one
/// field of one record the caller did not ask about would take down an entire page —
/// including the records it did ask for.
/// </para>
/// <para>
/// It never silently maps to the <i>zero</i> member, which is the trap this used to
/// avoid by throwing: reading <c>"suspended"</c> as whatever happens to be declared
/// first would turn a new state into a wrong one, and on this surface those states gate
/// access. <c>Unknown</c> is a state of its own, and its wire spelling is the empty
/// string — which no server value is, so carrying an unrecognised value back into an
/// update is refused by the server rather than written as a spelling it never used.
/// </para>
/// <para>
/// An enum with no <c>Unknown</c> member still throws, so this cannot quietly change
/// behaviour for a hand-written enum that never opted in.
/// </para>
/// </remarks>
public sealed class WireEnumConverter<TEnum> : JsonConverter<TEnum>
    where TEnum : struct, Enum
{
    private static readonly Dictionary<string, TEnum> FromWire = BuildFromWire();
    private static readonly Dictionary<TEnum, string> ToWire = BuildToWire();
    private static readonly TEnum? UnknownMember = FindUnknown();

    /// <inheritdoc />
    public override TEnum Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? raw = reader.GetString();
        if (raw is not null && FromWire.TryGetValue(raw, out TEnum value))
        {
            return value;
        }

        // §27.11 rule 1: decode, do not fail the response this arrived in.
        if (UnknownMember is { } unknown)
        {
            return unknown;
        }

        throw NetworkError.FromMessage(
            $"the server sent '{raw}' for {typeof(TEnum).Name}, which this SDK does not know. " +
            $"Known values: {string.Join(", ", FromWire.Keys)}. A newer server may have added " +
            "one; upgrading the SDK is the fix, and guessing would turn a new state into a " +
            "wrong one.");
    }

    /// <summary>The enum's <c>Unknown</c> member, when it declares one.</summary>
    private static TEnum? FindUnknown()
        => Enum.TryParse("Unknown", out TEnum unknown) ? unknown : null;

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
