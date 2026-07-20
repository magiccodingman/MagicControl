using MagicControl.Shared.Enrollments;

namespace MagicControl.Web.Data.Entities;

public sealed class ManagedInstance
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public EnrollmentKind Kind { get; set; }
    public ManagedInstanceStatus Status { get; set; } = ManagedInstanceStatus.Active;

    public required string DisplayName { get; set; }
    public string? ApplicationName { get; set; }
    public string? InstanceName { get; set; }
    public string? InstanceRole { get; set; }
    public string? SiteName { get; set; }
    public string? AdvertisedEndpoint { get; set; }
    public string? Version { get; set; }
    public string CapabilitiesJson { get; set; } = "{}";
    public string MetadataJson { get; set; } = "{}";
    public string EndpointsJson { get; set; } = "[]";
    public long DirectorySequence { get; set; }

    public Guid? GroupId { get; set; }
    public ControlGroup? Group { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset ApprovedUtc { get; set; }
    public DateTimeOffset? LastSeenUtc { get; set; }

    public ICollection<InstanceCredential> Credentials { get; set; } = [];
}
