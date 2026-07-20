using MagicSettings.Share;

namespace MagicControl.Shared.Enrollments;

public enum EnrollmentKind
{
    ApplicationInstance = 1,
    MeshApi = 2
}

public enum EnrollmentRequestStatus
{
    Pending = 1,
    Approved = 2,
    Rejected = 3
}

public enum ManagedInstanceStatus
{
    Active = 1,
    Disabled = 2,
    Revoked = 3
}

public sealed record EnrollmentSubmission
{
    public required EnrollmentKind Kind { get; init; }
    public required MagicNodeIdentityDescriptor Identity { get; init; }

    public required string DisplayName { get; init; }
    public string? ApplicationName { get; init; }
    public string? GroupName { get; init; }
    public string? InstanceName { get; init; }
    public string? InstanceRole { get; init; }
    public string? SiteName { get; init; }

    public string? Version { get; init; }
    public string? AdvertisedEndpoint { get; init; }
    public IReadOnlyList<string> RequestedRoles { get; init; } = [];
    public IReadOnlyDictionary<string, string> Capabilities { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);
    public IReadOnlyDictionary<string, string> Metadata { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);
}

public sealed record EnrollmentReceipt(
    Guid RequestId,
    EnrollmentRequestStatus Status,
    string Message);

public sealed record EnrollmentRequestSummary(
    Guid Id,
    EnrollmentKind Kind,
    EnrollmentRequestStatus Status,
    Guid NodeId,
    Guid CredentialId,
    string DisplayName,
    string? ApplicationName,
    string? GroupName,
    string? InstanceName,
    string? InstanceRole,
    string? SiteName,
    string? Version,
    string? AdvertisedEndpoint,
    string Fingerprint,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    DateTimeOffset? ReviewedUtc,
    string? DecisionReason,
    Guid? GroupId = null,
    string? PairingCode = null,
    IReadOnlyList<string>? RequestedCapabilities = null);

public sealed record ManagedInstanceSummary(
    Guid Id,
    EnrollmentKind Kind,
    ManagedInstanceStatus Status,
    string DisplayName,
    string? ApplicationName,
    string? GroupName,
    string? InstanceName,
    string? InstanceRole,
    string? SiteName,
    string? AdvertisedEndpoint,
    string? Version,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? LastSeenUtc);
