namespace MagicControl.Web.Data.Entities;

public sealed class ApplicationSchemaRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid GroupId { get; set; }
    public ControlGroup Group { get; set; } = null!;

    public required string ApplicationName { get; set; }
    public required string ApplicationVersion { get; set; }
    public int SchemaVersion { get; set; }
    public required string SchemaFingerprint { get; set; }
    public required string ManifestJson { get; set; }
    public string MigrationReviewJson { get; set; } = "[]";
    public long SettingsRevision { get; set; }
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; }

    public ICollection<ApplicationSettingOverride> Overrides { get; set; } = [];
}
