namespace MagicControl.Web.Data.Entities;

public sealed class ControlUserRole
{
    public Guid UserId { get; set; }
    public ControlUser User { get; set; } = null!;

    public Guid RoleId { get; set; }
    public ControlRole Role { get; set; } = null!;
}
