namespace MagicControl.Shared.Mesh;

public sealed record MagicControlGroupDescriptor(
    Guid GroupId,
    string GroupName,
    MagicControlGroupSecurityMode SecurityMode,
    long ManifestRevision,
    Guid SecurityEpoch,
    MagicControlOfflineTrustPolicy OfflineTrust);
