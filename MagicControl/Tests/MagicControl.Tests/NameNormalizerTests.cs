using MagicControl.Shared.Utilities;

namespace MagicControl.Tests;

public sealed class NameNormalizerTests
{
    [Fact]
    public void Normalize_trims_and_uses_invariant_uppercase()
        => Assert.Equal("MAGICCONTROL", MagicControlNameNormalizer.Normalize("  MagicControl  "));
}
