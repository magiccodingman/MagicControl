namespace MagicControl.Web.Data.Entities;

public sealed class ControlUser
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Username { get; set; }
    public required string NormalizedUsername { get; set; }
    public required string PasswordHash { get; set; }
    public required string SecurityStamp { get; set; }

    public bool MustChangePassword { get; set; }
    public bool IsDisabled { get; set; }
    public int FailedLoginCount { get; set; }
    public DateTimeOffset? LockoutEndUtc { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; }
    public DateTimeOffset PasswordChangedUtc { get; set; }
    public DateTimeOffset? LastLoginUtc { get; set; }

    public ICollection<ControlUserRole> UserRoles { get; set; } = [];
}
