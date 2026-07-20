using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using MagicControl.Shared.Mesh;

namespace MagicControl.Client;

public sealed class DiscoveringMagicControlMeshEndpointResolver(
    MagicControlClientOptions options,
    IMagicControlClientStateStore stateStore) : IMagicControlMeshEndpointResolver
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async ValueTask<IReadOnlyList<Uri>> ResolveAsync(
        CancellationToken cancellationToken = default)
    {
        var endpoints = new Dictionary<string, Uri>(StringComparer.OrdinalIgnoreCase);

        foreach (var endpoint in options.MeshEndpointSeeds)
        {
            Add(endpoint);
        }

        var state = await stateStore.LoadAsync(cancellationToken);
        foreach (var endpoint in state.MeshEndpoints)
        {
            Add(endpoint);
        }

        if (options.EnableAutomaticDiscovery)
        {
            foreach (var endpoint in await DiscoverLanAsync(cancellationToken))
            {
                Add(endpoint);
            }
        }

        return endpoints.Values.ToArray();

        void Add(Uri endpoint)
        {
            if (options.IsEndpointAllowed(endpoint))
            {
                endpoints.TryAdd(endpoint.AbsoluteUri.TrimEnd('/'), endpoint);
            }
        }
    }

    private async ValueTask<IReadOnlyList<Uri>> DiscoverLanAsync(
        CancellationToken cancellationToken)
    {
        var results = new Dictionary<string, Uri>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var multicast = IPAddress.Parse(options.DiscoveryMulticastAddress);
            using var client = new UdpClient(AddressFamily.InterNetwork);
            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            client.Client.Bind(new IPEndPoint(IPAddress.Any, 0));

            var query = JsonSerializer.SerializeToUtf8Bytes(
                new DiscoveryDatagram(
                    MagicControlNodeProtocol.DiscoveryProtocolVersion,
                    "query",
                    options.GroupId,
                    null),
                JsonOptions);
            await client.SendAsync(
                query,
                new IPEndPoint(multicast, options.DiscoveryPort),
                cancellationToken);

            var deadline = DateTimeOffset.UtcNow.Add(options.DiscoveryTimeout);
            while (DateTimeOffset.UtcNow < deadline)
            {
                var remaining = deadline - DateTimeOffset.UtcNow;
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(remaining);

                UdpReceiveResult received;
                try
                {
                    received = await client.ReceiveAsync(timeout.Token);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                DiscoveryDatagram? datagram;
                try
                {
                    datagram = JsonSerializer.Deserialize<DiscoveryDatagram>(
                        received.Buffer,
                        JsonOptions);
                }
                catch (JsonException)
                {
                    continue;
                }

                if (datagram?.Version != MagicControlNodeProtocol.DiscoveryProtocolVersion
                    || !string.Equals(datagram.Kind, "advertisement", StringComparison.OrdinalIgnoreCase)
                    || datagram.Advertisement is not { } advertisement
                    || advertisement.IssuedUtc.AddSeconds(advertisement.TimeToLiveSeconds) < DateTimeOffset.UtcNow
                    || !options.IsEndpointAllowed(advertisement.Endpoint))
                {
                    continue;
                }

                results.TryAdd(
                    advertisement.Endpoint.AbsoluteUri.TrimEnd('/'),
                    advertisement.Endpoint);
            }
        }
        catch (Exception exception) when (
            exception is SocketException or FormatException or InvalidOperationException)
        {
            // Discovery is opportunistic. Explicit seeds and last-known-good endpoints remain usable.
        }

        return results.Values.ToArray();
    }

    private sealed record DiscoveryDatagram(
        int Version,
        string Kind,
        Guid? GroupId,
        MagicControlMeshAdvertisement? Advertisement);
}
