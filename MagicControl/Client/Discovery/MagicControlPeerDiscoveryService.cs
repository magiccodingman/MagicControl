using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using MagicControl.Shared.Mesh;
using MagicSettings;
using MagicSettings.Share;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MagicControl.Client;

public sealed class MagicControlPeerDiscoveryService(
    MagicControlClientOptions options,
    MagicControlPeerDirectory directory,
    IMagicControlPeerDirectoryStore store,
    IServiceProvider serviceProvider,
    ILogger<MagicControlPeerDiscoveryService> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private long _sequence = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.EnableDirectPeerDiscovery)
        {
            return;
        }

        var authenticator = serviceProvider.GetService<IMagicNodeAuthenticator>();
        MagicNodeIdentityDescriptor? ownIdentity = null;
        if (authenticator is not null)
        {
            ownIdentity = await authenticator.GetCurrentIdentityAsync(stoppingToken);
        }
        else
        {
            logger.LogInformation(
                "MagicControl direct peer discovery will listen for applications but cannot advertise this application because no IMagicNodeAuthenticator is registered.");
        }

        await LoadCachedPeersAsync(ownIdentity, stoppingToken);

        UdpClient? receiver = null;
        var dirty = false;
        try
        {
            var multicast = IPAddress.Parse(options.PeerDiscoveryMulticastAddress);
            var multicastEndpoint = new IPEndPoint(multicast, options.PeerDiscoveryPort);

            receiver = new UdpClient(AddressFamily.InterNetwork)
            {
                ExclusiveAddressUse = false,
                MulticastLoopback = true
            };
            receiver.Client.SetSocketOption(
                SocketOptionLevel.Socket,
                SocketOptionName.ReuseAddress,
                true);
            receiver.Client.Bind(new IPEndPoint(IPAddress.Any, options.PeerDiscoveryPort));
            receiver.JoinMulticastGroup(multicast);

            using var sender = new UdpClient(AddressFamily.InterNetwork)
            {
                MulticastLoopback = true
            };

            var nextQueryUtc = DateTimeOffset.MinValue;
            var nextAdvertisementUtc = DateTimeOffset.MinValue;
            var nextPersistUtc = DateTimeOffset.UtcNow.AddMinutes(1);

            while (!stoppingToken.IsCancellationRequested)
            {
                var now = DateTimeOffset.UtcNow;
                if (now >= nextQueryUtc)
                {
                    await SendAsync(
                        sender,
                        multicastEndpoint,
                        new PeerDiscoveryDatagram(
                            MagicControlNodeProtocol.PeerDiscoveryProtocolVersion,
                            "query",
                            options.GroupId,
                            null,
                            null),
                        stoppingToken);
                    nextQueryUtc = now.Add(options.PeerDiscoveryQueryInterval);
                }

                if (authenticator is not null
                    && options.AdvertisedEndpoints.Count > 0
                    && now >= nextAdvertisementUtc)
                {
                    var envelope = await CreateAdvertisementAsync(authenticator, stoppingToken);
                    ownIdentity = envelope.Advertisement.Identity;
                    await SendAsync(
                        sender,
                        multicastEndpoint,
                        new PeerDiscoveryDatagram(
                            MagicControlNodeProtocol.PeerDiscoveryProtocolVersion,
                            "advertisement",
                            options.GroupId,
                            options.ApplicationName,
                            envelope),
                        stoppingToken);
                    nextAdvertisementUtc = now.Add(TimeSpan.FromTicks(
                        Math.Max(
                            TimeSpan.FromSeconds(2).Ticks,
                            options.PeerAdvertisementTtl.Ticks / 2)));
                }

                if (dirty && now >= nextPersistUtc)
                {
                    await store.SaveAsync(directory.Snapshot(), stoppingToken);
                    dirty = false;
                    nextPersistUtc = now.AddMinutes(1);
                }

                using var receiveTimeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                receiveTimeout.CancelAfter(TimeSpan.FromMilliseconds(500));
                try
                {
                    var received = await receiver.ReceiveAsync(receiveTimeout.Token);
                    var datagram = Deserialize(received.Buffer);
                    if (datagram?.Version != MagicControlNodeProtocol.PeerDiscoveryProtocolVersion
                        || datagram.GroupId != options.GroupId)
                    {
                        continue;
                    }

                    if (string.Equals(datagram.Kind, "query", StringComparison.OrdinalIgnoreCase))
                    {
                        if (authenticator is null
                            || options.AdvertisedEndpoints.Count == 0
                            || (!string.IsNullOrWhiteSpace(datagram.ApplicationName)
                                && !string.Equals(
                                    datagram.ApplicationName,
                                    options.ApplicationName,
                                    StringComparison.OrdinalIgnoreCase)))
                        {
                            continue;
                        }

                        var envelope = await CreateAdvertisementAsync(authenticator, stoppingToken);
                        ownIdentity = envelope.Advertisement.Identity;
                        await SendAsync(
                            sender,
                            multicastEndpoint,
                            new PeerDiscoveryDatagram(
                                MagicControlNodeProtocol.PeerDiscoveryProtocolVersion,
                                "advertisement",
                                options.GroupId,
                                options.ApplicationName,
                                envelope),
                            stoppingToken);
                        continue;
                    }

                    if (!string.Equals(datagram.Kind, "advertisement", StringComparison.OrdinalIgnoreCase)
                        || datagram.Advertisement is null)
                    {
                        continue;
                    }

                    var advertisement = datagram.Advertisement.Advertisement;
                    if (ownIdentity is not null
                        && advertisement.Identity.NodeId == ownIdentity.NodeId
                        && advertisement.Identity.CredentialId == ownIdentity.CredentialId)
                    {
                        continue;
                    }

                    var validation = MagicControlPeerAdvertisementSecurity.Validate(
                        datagram.Advertisement,
                        options,
                        DateTimeOffset.UtcNow,
                        enforceCurrentLifetime: true);
                    if (!validation.IsValid)
                    {
                        logger.LogDebug(
                            "Ignored an invalid MagicControl peer advertisement: {Reason}",
                            validation.Error);
                        continue;
                    }

                    if (directory.Accept(
                            datagram.Advertisement,
                            DateTimeOffset.UtcNow))
                    {
                        dirty = true;
                    }
                }
                catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
                {
                    // Periodic wake-up for advertisements, queries, and persistence.
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
                "MagicControl direct peer discovery is unavailable. Signed directories and explicit routes remain usable.");
        }
        finally
        {
            receiver?.Dispose();
            if (dirty)
            {
                try
                {
                    await store.SaveAsync(directory.Snapshot(), CancellationToken.None);
                }
                catch (Exception exception) when (exception is IOException or CryptographicException)
                {
                    logger.LogWarning(exception, "MagicControl could not persist the direct peer cache.");
                }
            }
        }
    }

    private async ValueTask LoadCachedPeersAsync(
        MagicNodeIdentityDescriptor? ownIdentity,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var observation in await store.LoadAsync(cancellationToken))
        {
            var advertisement = observation.Advertisement;
            if (observation.LastSeenUtc.Add(options.PeerCacheDuration) < now
                || (ownIdentity is not null
                    && advertisement.Identity.NodeId == ownIdentity.NodeId
                    && advertisement.Identity.CredentialId == ownIdentity.CredentialId))
            {
                continue;
            }

            var validation = MagicControlPeerAdvertisementSecurity.Validate(
                observation.Envelope,
                options,
                now,
                enforceCurrentLifetime: false);
            if (validation.IsValid)
            {
                directory.Accept(
                    observation.Envelope,
                    observation.LastSeenUtc,
                    loadedFromDisk: true);
            }
        }
    }

    private async ValueTask<SignedMagicControlPeerAdvertisement> CreateAdvertisementAsync(
        IMagicNodeAuthenticator authenticator,
        CancellationToken cancellationToken)
    {
        var identity = await authenticator.GetCurrentIdentityAsync(cancellationToken);
        var issuedUtc = DateTimeOffset.UtcNow;
        var ttlSeconds = checked((int)Math.Ceiling(options.PeerAdvertisementTtl.TotalSeconds));
        var advertisement = new MagicControlPeerAdvertisement(
            MagicControlNodeProtocol.PeerDiscoveryProtocolVersion,
            options.GroupId,
            options.ApplicationName,
            options.DisplayName!,
            options.InstanceName,
            options.InstanceRole,
            options.SiteName,
            options.Version,
            identity,
            options.AdvertisedEndpoints.ToArray(),
            Interlocked.Increment(ref _sequence),
            issuedUtc,
            ttlSeconds);
        var proof = await authenticator.CreateProofAsync(
            new MagicAuthenticationRequest(
                MagicControlNodeProtocol.PeerDiscoveryAudience,
                "ANNOUNCE",
                MagicControlPeerAdvertisementSecurity.Target(advertisement),
                MagicControlPeerAdvertisementSecurity.ComputeBodySha256(advertisement),
                TimeSpan.FromSeconds(Math.Min(300, ttlSeconds + 30))),
            cancellationToken);
        return new SignedMagicControlPeerAdvertisement(advertisement, proof);
    }

    private static async ValueTask SendAsync(
        UdpClient client,
        IPEndPoint endpoint,
        PeerDiscoveryDatagram datagram,
        CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(datagram, JsonOptions);
        if (payload.Length > 60_000)
        {
            throw new InvalidOperationException(
                "The MagicControl peer advertisement is too large for UDP discovery.");
        }

        await client.SendAsync(payload, endpoint, cancellationToken);
    }

    private static PeerDiscoveryDatagram? Deserialize(byte[] payload)
    {
        try
        {
            return JsonSerializer.Deserialize<PeerDiscoveryDatagram>(payload, JsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private sealed record PeerDiscoveryDatagram(
        int Version,
        string Kind,
        Guid GroupId,
        string? ApplicationName,
        SignedMagicControlPeerAdvertisement? Advertisement);
}
