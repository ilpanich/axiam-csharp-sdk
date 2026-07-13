using System.Net;
using System.Net.Http;
using Axiam.Sdk.Core;
using Grpc.Core;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Fills out the CONTRACT.md §2 status-to-error table for <see cref="ErrorMapper"/> across
/// every branch the transports depend on: HTTP 401/403/409/other, the status-only
/// <c>FromHttpStatus</c> overload, and the gRPC status table (Unauthenticated /
/// PermissionDenied / everything-else).
/// </summary>
[Trait("Category", "Fast")]
public class ErrorMapperMappingTests
{
    [Fact]
    public void FromHttpResponse_401_MapsToAuthError()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        Exception error = ErrorMapper.FromHttpResponse(response, "ctx");
        var auth = Assert.IsType<AuthError>(error);
        Assert.Equal("ctx", auth.Message);
    }

    [Fact]
    public void FromHttpResponse_409_MapsToAuthzError()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.Conflict) { Content = new StringContent("") };
        Exception error = ErrorMapper.FromHttpResponse(response, "conflict");
        Assert.IsType<AuthzError>(error);
    }

    [Fact]
    public void FromHttpResponse_500_MapsToNetworkError()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.InternalServerError);
        Exception error = ErrorMapper.FromHttpResponse(response, "boom");
        Assert.IsType<NetworkError>(error);
    }

    [Fact]
    public void FromHttpResponse_429_MapsToNetworkError()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        Assert.IsType<NetworkError>(ErrorMapper.FromHttpResponse(response, "rate limited"));
    }

    [Fact]
    public void FromHttpResponse_NullResponse_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => ErrorMapper.FromHttpResponse(null!, "ctx"));
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, typeof(AuthError))]
    [InlineData(HttpStatusCode.Forbidden, typeof(AuthzError))]
    [InlineData(HttpStatusCode.Conflict, typeof(AuthzError))]
    [InlineData(HttpStatusCode.BadRequest, typeof(NetworkError))]
    [InlineData(HttpStatusCode.InternalServerError, typeof(NetworkError))]
    public void FromHttpStatus_MapsPerTable(HttpStatusCode status, Type expected)
    {
        Exception error = ErrorMapper.FromHttpStatus(status, "ctx");
        Assert.IsType(expected, error);
    }

    [Fact]
    public void FromGrpcStatus_Unauthenticated_MapsToAuthError()
    {
        Assert.IsType<AuthError>(ErrorMapper.FromGrpcStatus(StatusCode.Unauthenticated, "expired"));
    }

    [Fact]
    public void FromGrpcStatus_PermissionDenied_MapsToAuthzError()
    {
        Assert.IsType<AuthzError>(ErrorMapper.FromGrpcStatus(StatusCode.PermissionDenied, "denied"));
    }

    [Theory]
    [InlineData(StatusCode.Unavailable)]
    [InlineData(StatusCode.DeadlineExceeded)]
    [InlineData(StatusCode.Internal)]
    [InlineData(StatusCode.ResourceExhausted)]
    public void FromGrpcStatus_TransportCodes_MapToNetworkError(StatusCode code)
    {
        Exception error = ErrorMapper.FromGrpcStatus(code, "transient");
        var network = Assert.IsType<NetworkError>(error);
        Assert.NotNull(network.InnerException);
    }
}
