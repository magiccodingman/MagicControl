using MagicControl.Shared.Mesh;

namespace MagicControl.Client;

public enum MagicControlStartupMode
{
    CachedFirst = 1,
    PreferConnected = 2,
    PreferMesh = PreferConnected,
    RequireApprovedState = 3,
    RequireMesh = RequireApprovedState
}

public enum MagicControlRouteSelectionMode
{
    Automatic = 1,
    First = 2,
    RoundRobin = 3
}

public sealed class MagicControlClientOptions
{
    public Guid GroupId { get; set; }
    public string ApplicationName { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string InstanceName { get; set; } = Environment.MachineName;
    public string? InstanceRole { get; set; }
    public string? SiteName { get; set; }
    public string? Version { get; set; }

    public string StatePath { get; set; } = "state/magic-control";
    public string ManifestFileName { get; set; } = "group-manifest.protected";
    public string ClientStateFileName { get; set; } = "client-state.protected";
    public string PeerDirectoryFileName { get; set; } = "peer-directory.protected";

    /// <summary>
    /// Presence of this non-secret, permission-restricted marker means this application has
    /// accepted a signed Secured policy and must not fall back to open behavior merely because
    /// authority state is temporarily unavailable or unreadable.
    /// </summary>
    public string SecurityLatchFileName { get; set; } = "secured-policy.lock";

    public MagicControlStartupMode StartupMode { get; set; } = MagicControlStartupMode.CachedFirst;
    public MagicControlRouteSelectionMode RouteSelection { get; set; } = MagicControlRouteSelectionMode.Automatic;
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromSeconds(30);
    public TimeSpan MeshRequestTimeout { get; set; } = TimeSpan.FromSeconds(10);
    public TimeSpan DiscoveryTimeout { get; set; } = TimeSpan.FromMilliseconds(900);

    public bool EnableAutomaticDiscovery { get; set; } = true;
    public string DiscoveryMulticastAddress { get; set; } = MagicControlNodeProtocol.DiscoveryMulticastAddress;
    public int DiscoveryPort { get; set; } = MagicControlNodeProtocol.DiscoveryPort;

    /// <summary>
    /// Enables application-to-application LAN discovery inside MagicControl.Client. This path
    /// works without MagicControl Web, a Mesh API, or a cached authority directory.
    /// </summary>
    public bool EnableDirectPeerDiscovery { get; set; } = true;

    public string PeerDiscoveryMulticastAddress { get; set; } = MagicControlNodeProtocol.PeerDiscoveryMulticastAddress;
    public int PeerDiscoveryPort { get; set; } = MagicControlNodeProtocol.PeerDiscoveryPort;
    public TimeSpan PeerAdvertisementTtl { get; set; } = TimeSpan.FromSeconds(20);
    public TimeSpan PeerDiscoveryQueryInterval { get; set; } = TimeSpan.FromSeconds(5);
    public TimeSpan PeerCacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Allows identity-verified direct peers to be returned when no usable authority manifest
    /// exists and this application has never accepted a signed Secured policy. This never grants
    /// membership or capabilities. A sticky secured policy always takes precedence.
    /// </summary>
    public bool AllowIdentityVerifiedPeersWithoutAuthority { get; set; } = true;

    public bool AllowInsecureHttp { get; set; }

    public List<Uri> MeshEndpointSeeds { get; } = [];
    public List<string> RequestedCapabilities { get; } = [];
    public List<MagicControlServiceEndpointAnnouncement> AdvertisedEndpoints { get; } = [];

    // Compatibility alias. These are discovery seeds/overrides, not the normal discovery path.
    public List<Uri> MeshEndpoints => MeshEndpointSeeds;

    /// <summary>
    /// Optional explicit authority pin. Normal secured enrollment installs the authority
    /// automatically after an administrator approves this exact node credential.
    /// </summary>
    public string? TrustedAuthorityPublicKey { get; set; }

    /// <summary>
    /// Unsafe compatibility escape hatch for accepting a secured manifest without an
    /// approved bootstrap response. Normal applications should leave this disabled.
    /// </summary>
    public bool AllowAuthorityTrustOnFirstUse { get; set; }

    public void AddMeshEndpointOverride(string endpoint)
        => MeshEndpointSeeds.Add(new Uri(endpoint, UriKind.Absolute));

    public void AddMeshEndpoint(string endpoint)
        => AddMeshEndpointOverride(endpoint);

    public void AdvertiseEndpoint(
        string endpoint,
        int priority = 100,
        bool isLoopback = false,
        bool isLan = false,
        string? transport = null)
    {
        var uri = new Uri(endpoint, UriKind.Absolute);
        AdvertisedEndpoints.Add(new MagicControlServiceEndpointAnnouncement(
            uri,
            priority,
            isLoopback || uri.IsLoopback,
            isLan,
            transport ?? uri.Scheme));
    }

    internal string ComputeContextHash(string bootstrapNonce)
        => MagicControlNodeContext.Compute(
            GroupId,
            ApplicationName,
            DisplayName!,
            InstanceName,
            InstanceRole,
            SiteName,
            Version,
            bootstrapNonce,
            RequestedCapabilities,
            AdvertisedEndpoints);

    internal void Validate()
    {
        if (GroupId == Guid.Empty)
        {
            throw new InvalidOperationException("MagicControl client GroupId is required.");
        }

        if (string.IsNullOrWhiteSpace(ApplicationName))
        {
            throw new InvalidOperationException("MagicControl client ApplicationName is required.");
        }

        if (string.IsNullOrWhiteSpace(SecurityLatchFileName))
        {
            throw new InvalidOperationException("MagicControl security latch file name is required.");
        }

        DisplayName = string.IsNullOrWhiteSpace(DisplayName)
            ? $"{ApplicationName} on {Environment.MachineName}"
            : DisplayName.Trim();
        InstanceName = string.IsNullOrWhiteSpace(InstanceName)
            ? Environment.MachineName
            : InstanceName.Trim();

        if (RefreshInterval < TimeSpan.FromSeconds(1))
        {
            throw new InvalidOperationException("MagicControl client refresh interval must be at least one second.");
        }

        if (MeshRequestTimeout <= TimeSpan.Zero)
        {
            throw new InvalidOperationException("MagicControl client Mesh request timeout must be positive.");
        }

        if (DiscoveryTimeout <= TimeSpan.Zero)
        {
            throw new InvalidOperationException("MagicControl discovery timeout must be positive.");
        }

        if (DiscoveryPort is < 1 or > 65535)
        {
            throw new InvalidOperationException("MagicControl discovery port must be a valid UDP port.");
        }

        if (PeerDiscoveryPort is < 1 or > 65535)
        {
            throw new InvalidOperationException("MagicControl peer discovery port must be a valid UDP port.");
        }

        if (PeerAdvertisementTtl < TimeSpan.FromSeconds(5)
            || PeerAdvertisementTtl > TimeSpan.FromMinutes(5))
        {
            throw new InvalidOperationException("MagicControl peer advertisement TTL must be between five seconds and five minutes.");
        }

        if (PeerDiscoveryQueryInterval < TimeSpan.FromSeconds(1))
        {
            throw new InvalidOperationException("MagicControl peer discovery query interval must be at least one second.");
        }

        if (PeerCacheDuration < PeerAdvertisementTtl)
        {
            throw new InvalidOperationException("MagicControl peer cache duration must be at least as long as the advertisement TTL.");
        }

        foreach (var endpoint in MeshEndpointSeeds)
        {
            ValidateEndpoint(endpoint);
        }

        foreach (var endpoint in AdvertisedEndpoints)
        {
            ValidateEndpoint(endpoint.Uri);
        }
    }

    internal bool IsEndpointAllowed(Uri endpoint)
    {
        if (endpoint.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return endpoint.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
               && (endpoint.IsLoopback || AllowInsecureHttp);
    }

    private void ValidateEndpoint(Uri endpoint)
    {
        if (!IsEndpointAllowed(endpoint))
        {
            throw new InvalidOperationException(
                $"MagicControl endpoint '{endpoint}' must use HTTPS unless it is loopback or AllowInsecureHttp is explicitly enabled.");
        }
    }
}
