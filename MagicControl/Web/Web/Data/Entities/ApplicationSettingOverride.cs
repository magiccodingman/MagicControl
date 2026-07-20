using MagicSettings.Share;

namespace MagicControl.Web.Data.Entities;

public enum MagicControlSettingScopeKind
{
    Application = 1,
    Site = 2,
    Role = 3,
    Instance = 4
}

public sealed class ApplicationSettingOverride
{
    public Guid Id { get; set; }
    public Guid ApplicationSchemaId { get; set; }
    public ApplicationSchemaRecord ApplicationSchema { get; set; } = null!;

    public required string Path { get; set; }
    public MagicControlSettingScopeKind ScopeKind { get; set; }
    public string ScopeValue { get; set; } = string.Empty;
    public MagicValueState ValueState { get; set; } = MagicValueState.Value;
    public string? ValueJson { get; set; }
    public MagicRemoteValueDurability Durability { get; set; } = MagicRemoteValueDurability.Sticky;
    public bool PersistOffline { get; set; } = true;
    public bool IsSecret { get; set; }
    public string? ProtectedSecret { get; set; }
    public DateTimeOffset? ExpiresUtc { get; set; }
    public long Revision { get; set; }
    public Guid UpdatedByUserId { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; }
}
