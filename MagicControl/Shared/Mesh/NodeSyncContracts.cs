using MagicSettings.Share;

namespace MagicControl.Shared.Mesh;

public enum MagicControlEnrollmentState
{
    LocalOnly = 0,
    PendingApproval = 1,
    Approved = 2,
    Rejected = 3,
    Faulted = 4
}

public sealed record MagicControlMeshAdvertisement(
    Guid GatewayId,
    Guid MeshNodeId,
    Uri Endpoint,
    string? AuthorityKeyId,
    DateTimeOffset IssuedUtc,
    int TimeToLiveSeconds = 20);

public sealed record MagicControlServiceEndpointAnnouncement(
    Uri Uri,
    int Priority = 100,
    bool IsLoopback = false,
    bool IsLan = false,
    string Transport = "https");

public sealed record MagicControlNodeSyncRequest(
    Guid GroupId,
    string ApplicationName,
    string DisplayName,
    string? InstanceName,
    string? InstanceRole,
    string? SiteName,
    string? Version,
    string BootstrapNonce,
    IReadOnlyList<string> RequestedCapabilities,
    IReadOnlyList<MagicControlServiceEndpointAnnouncement> Endpoints,
    MagicSettingsSyncRequest Settings);

public sealed record MagicControlNodeSyncResponse(
    MagicControlEnrollmentState EnrollmentState,
    MagicSettingsSyncResponse Settings,
    MagicRemoteSnapshot OfflineSnapshot,
    SignedMagicControlGroupManifest? Manifest,
    string BootstrapNonce,
    IReadOnlyList<Uri> MeshEndpoints,
    string? PairingCode = null,
    string? Message = null,
    TimeSpan? SuggestedPollInterval = null);

public sealed record MagicControlNodeSecretRequest(
    Guid GroupId,
    string ApplicationName,
    MagicSecretRequest Secret);

public static class MagicControlLogicalUris
{
    public static Uri ControlPlaneBase(Guid groupId)
        => new($"https://magiccontrol.local/groups/{groupId:D}/", UriKind.Absolute);

    public static Uri SettingsSync(Guid groupId)
        => new(ControlPlaneBase(groupId), "magicsettings/sync");

    public static Uri SecretResolve(Guid groupId)
        => new(ControlPlaneBase(groupId), "magicsettings/secrets/resolve");
}
