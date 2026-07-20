namespace MagicControl.Web.Data.Entities;

public sealed class AuditEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTimeOffset OccurredUtc { get; set; }
    public string? ActorType { get; set; }
    public string? ActorId { get; set; }
    public required string Action { get; set; }
    public required string TargetType { get; set; }
    public string? TargetId { get; set; }
    public string MetadataJson { get; set; } = "{}";
}
