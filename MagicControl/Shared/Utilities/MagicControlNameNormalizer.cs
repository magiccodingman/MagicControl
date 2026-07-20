namespace MagicControl.Shared.Utilities;

public static class MagicControlNameNormalizer
{
    public static string Normalize(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        return value.Trim().ToUpperInvariant();
    }
}
