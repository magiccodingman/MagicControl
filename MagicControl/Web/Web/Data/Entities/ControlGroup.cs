using MagicControl.Shared.Mesh;

namespace MagicControl.Web.Data.Entities;

public sealed class ControlGroup
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public required string NormalizedName { get; set; }
    public string? Description { get; set; }

    // Retained for compatibility with the foundation schema. SecurityMode is the
    // authoritative group-wide setting; a group is never simultaneously open and secured.
    public bool AllowOpenLocalMembers { get; set; }
    public MagicControlGroupSecurityMode SecurityMode { get; set; } = MagicControlGroupSecurityMode.Open;
    public Guid SecurityEpoch { get; set; } = Guid.NewGuid();
    public long ManifestRevision { get; set; } = 1;

    // Null means infinite offline trust. This is the default for homelab-friendly resilience.
    public long? OfflineTrustDurationSeconds { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; }

    public ICollection<ManagedInstance> Instances { get; set; } = [];
}
