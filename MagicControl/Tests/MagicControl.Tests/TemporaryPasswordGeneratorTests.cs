using MagicControl.Web.Features.Common;

namespace MagicControl.Tests;

public sealed class TemporaryPasswordGeneratorTests
{
    [Fact]
    public void Generated_password_contains_each_required_character_class()
    {
        var password = new TemporaryPasswordGenerator().Generate(24);

        Assert.Equal(24, password.Length);
        Assert.True(password.Any(char.IsUpper));
        Assert.True(password.Any(char.IsLower));
        Assert.True(password.Any(char.IsDigit));
        Assert.True(password.Any(character => "!@$%*-_+?".Contains(character)));
    }

    [Fact]
    public void Passwords_are_not_deterministic()
    {
        var generator = new TemporaryPasswordGenerator();
        var passwords = Enumerable.Range(0, 32)
            .Select(_ => generator.Generate(24))
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(32, passwords.Count);
    }
}
