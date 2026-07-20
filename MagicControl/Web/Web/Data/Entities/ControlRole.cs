namespace MagicControl.Web.Data.Entities;

public sealed class ControlRole
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public required string NormalizedName { get; set; }
    public bool IsBuiltIn { get; set; }
    public DateTimeOffset CreatedUtc { get; set; }

    public ICollection<ControlUserRole> UserRoles { get; set; } = [];
}
