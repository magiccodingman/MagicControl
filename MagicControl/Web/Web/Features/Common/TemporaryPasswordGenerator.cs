using System.Security.Cryptography;

namespace MagicControl.Web.Features.Common;

public sealed class TemporaryPasswordGenerator
{
    private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Lower = "abcdefghijkmnopqrstuvwxyz";
    private const string Digits = "23456789";
    private const string Symbols = "!@$%*-_+?";
    private const string All = Upper + Lower + Digits + Symbols;

    public string Generate(int length)
    {
        if (length < 12)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Temporary passwords must be at least 12 characters.");
        }

        var characters = new char[length];
        characters[0] = Pick(Upper);
        characters[1] = Pick(Lower);
        characters[2] = Pick(Digits);
        characters[3] = Pick(Symbols);

        for (var i = 4; i < characters.Length; i++)
        {
            characters[i] = Pick(All);
        }

        for (var i = characters.Length - 1; i > 0; i--)
        {
            var swapIndex = RandomNumberGenerator.GetInt32(i + 1);
            (characters[i], characters[swapIndex]) = (characters[swapIndex], characters[i]);
        }

        return new string(characters);
    }

    private static char Pick(string alphabet)
        => alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
}
