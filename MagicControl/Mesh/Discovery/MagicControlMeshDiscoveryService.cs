using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using MagicControl.Client;
using MagicControl.Shared.Mesh;
using MagicSettings;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Options;

namespace MagicControl.Mesh;

public sealed class MagicControlMeshDiscoveryService(
    IOptionsMonitor<MagicControlMeshSettings> settings,
    IMagicNodeAuthenticator authenticator,
    MagicControlManifestCache manifests,
    IServer server,
    ILogger<MagicControlMeshDiscoveryService> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!settings.CurrentValue.EnableLanDiscovery)
        {
            return;
        }

        UdpClient? receiver = null;
        try
        {
            var current = settings.CurrentValue;
            var multicast = IPAddress.Parse(current.DiscoveryMulticastAddress);
            receiver = new UdpClient(AddressFamily.InterNetwork);
            receiver.Client.SetSocketOption(
                SocketOptionLevel.Socket,
                SocketOptionName.ReuseAddress,
                true);
            receiver.Client.Bind(new IPEndPoint(IPAddress.Any, current.DiscoveryPort));
            receiver.JoinMulticastGroup(multicast);

            using var sender = new UdpClient(AddressFamily.InterNetwork);
            var nextAnnouncement = DateTimeOffset.MinValue;
            while (!stoppingToken.IsCancellationRequested)
            {
                if (DateTimeOffset.UtcNow >= nextAnnouncement)
                {
                    var advertisement = await CreateAdvertisementAsync(stoppingToken);
                    if (advertisement is not null)
                    {
                        var bytes = Serialize("advertisement", null, advertisement);
                        await sender.SendAsync(
                            bytes,
                            new IPEndPoint(multicast, current.DiscoveryPort),
                            stoppingToken);
                    }

                    nextAnnouncement = DateTimeOffset.UtcNow.AddSeconds(
                        Math.Max(3, current.DiscoveryAdvertisementTtlSeconds / 2));
                }

                using var receiveTimeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                receiveTimeout.CancelAfter(TimeSpan.FromSeconds(1));
                try
                {
                    var received = await receiver.ReceiveAsync(receiveTimeout.Token);
                    var datagram = Deserialize(received.Buffer);
                    if (datagram?.Version != MagicControlNodeProtocol.DiscoveryProtocolVersion
                        || !string.Equals(datagram.Kind, "query", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var advertisement = await CreateAdvertisementAsync(stoppingToken);
                    if (advertisement is null)
                    {
                        continue;
                    }

                    await sender.SendAsync(
                        Serialize("advertisement", datagram.GroupId, advertisement),
                        received.RemoteEndPoint,
                        stoppingToken);
                }
                catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
                {
                    // Periodic wake-up for multicast advertisements.
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (
            exception is SocketException or FormatException or InvalidOperationException)
        {
            logger.LogWarning(
                exception,
                "MagicControl Mesh LAN discovery is unavailable. Explicit endpoint seeds remain usable.");
        }
        finally
        {
            receiver?.Dispose();
        }
    }

    public Uri? ResolveAdvertisedEndpoint()
    {
        var configured = settings.CurrentValue.AdvertisedEndpoint;
        if (!string.IsNullOrWhiteSpace(configured)
            && Uri.TryCreate(configured, UriKind.Absolute, out var explicitEndpoint))
        {
            return explicitEndpoint;
        }

        var addresses = server.Features.Get<IServerAddressesFeature>()?.Addresses;
        var bound = addresses?
            .Select(value => Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri : null)
            .Where(uri => uri is not null)
            .Cast<Uri>()
            .OrderByDescending(uri => uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            .FirstOrDefault();
        if (bound is null)
        {
            return null;
        }

        if (!IsWildcardHost(bound.Host) && !bound.IsLoopback)
        {
            return bound;
        }

        var lanAddress = GetLanAddress();
        if (lanAddress is null)
        {
            return bound.IsLoopback ? bound : null;
        }

        var builder = new UriBuilder(bound)
        {
            Host = lanAddress.ToString()
        };
        return builder.Uri;
    }

    private async ValueTask<MagicControlMeshAdvertisement?> CreateAdvertisementAsync(
        CancellationToken cancellationToken)
    {
        var endpoint = ResolveAdvertisedEndpoint();
        if (endpoint is null)
        {
            return null;
        }

        var identity = await authenticator.GetCurrentIdentityAsync(cancellationToken);
        var authorityKeyId = manifests.GetAll()
            .Select(state => state.Envelope.AuthorityKeyId)
            .FirstOrDefault();
        return new MagicControlMeshAdvertisement(
            DeriveGatewayId(authorityKeyId ?? identity.Fingerprint),
            identity.NodeId,
            endpoint,
            authorityKeyId,
            DateTimeOffset.UtcNow,
            Math.Max(5, settings.CurrentValue.DiscoveryAdvertisementTtlSeconds));
    }

    private static byte[] Serialize(
        string kind,
        Guid? groupId,
        MagicControlMeshAdvertisement advertisement)
        => JsonSerializer.SerializeToUtf8Bytes(
            new DiscoveryDatagram(
                MagicControlNodeProtocol.DiscoveryProtocolVersion,
                kind,
                groupId,
                advertisement),
            JsonOptions);

    private static DiscoveryDatagram? Deserialize(byte[] bytes)
    {
        try
        {
            return JsonSerializer.Deserialize<DiscoveryDatagram>(bytes, JsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static Guid DeriveGatewayId(string value)
    {
        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value));
        return new Guid(hash.AsSpan(0, 16));
    }

    private static IPAddress? GetLanAddress()
        => NetworkInterface.GetAllNetworkInterfaces()
            .Where(network => network.OperationalStatus == OperationalStatus.Up
                              && network.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(network => network.GetIPProperties().UnicastAddresses)
            .Select(address => address.Address)
            .Where(address => address.AddressFamily == AddressFamily.InterNetwork
                              && !IPAddress.IsLoopback(address))
            .OrderByDescending(IsPrivate)
            .FirstOrDefault();

    private static bool IsPrivate(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return bytes[0] == 10
               || bytes[0] == 127
               || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
               || (bytes[0] == 192 && bytes[1] == 168);
    }

    private static bool IsWildcardHost(string host)
        => host is "0.0.0.0" or "::" or "[::]" or "*" or "+";

    private sealed record DiscoveryDatagram(
        int Version,
        string Kind,
        Guid? GroupId,
        MagicControlMeshAdvertisement? Advertisement);
}
