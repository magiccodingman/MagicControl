using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace MagicControl.Client;

public sealed class ProtectedManifestFileCodec : IDisposable
{
    private static readonly byte[] Header = "MAGICCONTROL-MANIFEST-V1\n"u8.ToArray();
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false
    };

    private readonly IDataProtectionProvider _provider;
    private readonly IDataProtector _protector;
    private readonly string _keyDirectory;

    public ProtectedManifestFileCodec(
        string statePath,
        string applicationDiscriminator)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationDiscriminator);

        _keyDirectory = Path.GetFullPath(Path.Combine(statePath, "data-protection"));
        Directory.CreateDirectory(_keyDirectory);
        RestrictDirectoryPermissions(_keyDirectory);

        _provider = DataProtectionProvider.Create(
            new DirectoryInfo(_keyDirectory),
            configuration => configuration.SetApplicationName(applicationDiscriminator));
        _protector = _provider.CreateProtector(
            "MagicControl",
            "SignedManifestCache",
            "v1");
    }

    public byte[] Protect<T>(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        var protectedPayload = _protector.Protect(plaintext);
        var result = new byte[Header.Length + protectedPayload.Length];
        Header.CopyTo(result, 0);
        protectedPayload.CopyTo(result, Header.Length);
        RestrictGeneratedKeyFiles();
        return result;
    }

    public T Unprotect<T>(ReadOnlySpan<byte> contents)
    {
        if (contents.Length <= Header.Length
            || !contents[..Header.Length].SequenceEqual(Header))
        {
            throw new CryptographicException(
                "The MagicControl manifest cache has an unknown or invalid protected format.");
        }

        var plaintext = _protector.Unprotect(contents[Header.Length..].ToArray());
        return JsonSerializer.Deserialize<T>(plaintext, JsonOptions)
               ?? throw new InvalidDataException(
                   "The protected MagicControl manifest cache was empty.");
    }

    private void RestrictGeneratedKeyFiles()
    {
        if (OperatingSystem.IsWindows() || !Directory.Exists(_keyDirectory))
        {
            return;
        }

        foreach (var path in Directory.EnumerateFiles(_keyDirectory))
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    private static void RestrictDirectoryPermissions(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    public void Dispose()
    {
        if (_provider is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}
