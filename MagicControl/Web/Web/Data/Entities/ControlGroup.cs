namespace MagicControl.Web.Data.Entities;

public sealed class ControlGroup
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public required string NormalizedName { get; set; }
    public string? Description { get; set; }
    public bool AllowOpenLocalMembers { get; set; }
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; }

    public ICollection<ManagedInstance> Instances { get; set; } = [];
}
