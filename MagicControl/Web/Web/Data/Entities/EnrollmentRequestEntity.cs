using MagicControl.Shared.Enrollments;

namespace MagicControl.Web.Data.Entities;

public sealed class EnrollmentRequestEntity
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public EnrollmentKind Kind { get; set; }
    public EnrollmentRequestStatus Status { get; set; } = EnrollmentRequestStatus.Pending;

    public Guid NodeId { get; set; }
    public Guid CredentialId { get; set; }
    public required string PublicKey { get; set; }
    public required string Fingerprint { get; set; }
    public required string SignatureAlgorithm { get; set; }

    public required string DisplayName { get; set; }
    public string? ApplicationName { get; set; }
    public string? GroupName { get; set; }
    public string? InstanceName { get; set; }
    public string? InstanceRole { get; set; }
    public string? SiteName { get; set; }
    public string? Version { get; set; }
    public string? AdvertisedEndpoint { get; set; }

    public string RequestedRolesJson { get; set; } = "[]";
    public string CapabilitiesJson { get; set; } = "{}";
    public string MetadataJson { get; set; } = "{}";

    public DateTimeOffset FirstSeenUtc { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }
    public DateTimeOffset? ReviewedUtc { get; set; }
    public Guid? ReviewedByUserId { get; set; }
    public string? DecisionReason { get; set; }

    public Guid? ManagedInstanceId { get; set; }
    public ManagedInstance? ManagedInstance { get; set; }
}
