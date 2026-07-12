using System.Threading.Tasks;
using Axiam.Sdk.Amqp;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Proves <see cref="AxiamAmqpConsumer.DisposeAsync"/> is a safe no-op when no
/// connection/channel was ever opened (never <see cref="StartAsync"/>-ed), so disposing a
/// freshly-constructed consumer neither throws nor requires a live broker.
/// </summary>
[Trait("Category", "Fast")]
public class AmqpConsumerDisposeTests
{
    [Fact]
    public async Task DisposeAsync_WithoutStart_DoesNotThrow()
    {
        var consumer = new AxiamAmqpConsumer();
        await consumer.DisposeAsync();
    }

    [Fact]
    public async Task DisposeAsync_IsIdempotent()
    {
        var consumer = new AxiamAmqpConsumer();
        await consumer.DisposeAsync();
        await consumer.DisposeAsync();
    }

    [Fact]
    public void Consumer_ExposesContractDefaults()
    {
        Assert.Equal((ushort)10, AxiamAmqpConsumer.DefaultPrefetchCount);
        Assert.Equal(System.TimeSpan.FromSeconds(5), AxiamAmqpConsumer.DefaultNetworkRecoveryInterval);
    }
}
