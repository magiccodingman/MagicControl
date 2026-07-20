using MagicSettings.Share;

namespace MagicControl.Shared.Mesh;

public sealed record MagicControlPeerAdvertisement(
    int ProtocolVersion,
    Guid GroupId,
    string ApplicationName,
    string DisplayName,
    string? InstanceName,
    string? InstanceRole,
    string? SiteName,
    string? Version,
    MagicNodeIdentityDescriptor Identity,
    IReadOnlyList<MagicControlServiceEndpointAnnouncement> Endpoints,
    long Sequence,
    DateTimeOffset IssuedUtc,
    int TimeToLiveSeconds = 20);

public sealed record SignedMagicControlPeerAdvertisement(
    MagicControlPeerAdvertisement Advertisement,
    MagicAuthenticationProof Proof);
