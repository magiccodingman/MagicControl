namespace MagicControl.Web.Data.Entities;

public sealed class SystemState
{
    public required string Key { get; set; }
    public required string Value { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; }
}
