using System.Security.Cryptography;
using System.Text.Json;
using MagicControl.Shared.Mesh;
using MagicControl.Web.Configuration;
using Microsoft.Extensions.Options;

namespace MagicControl.Web.Features.Mesh;

public sealed record MagicControlAuthorityDescriptor(string KeyId, string PublicKey);

public sealed class MagicControlAuthoritySigningService(
    IOptionsMonitor<MagicControlSettings> settings)
    : IAsyncDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly SemaphoreSlim _gate = new(1, 1);
    private ECDsa? _key;
    private MagicControlAuthorityDescriptor? _descriptor;

    public async ValueTask<SignedMagicControlGroupManifest> SignAsync(
        MagicControlGroupManifest manifest,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await EnsureLoadedAsync(cancellationToken);
            return MagicControlManifestCryptography.Sign(manifest, _key!);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<MagicControlAuthorityDescriptor> GetAuthorityAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await EnsureLoadedAsync(cancellationToken);
            return _descriptor!;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async ValueTask EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        if (_key is not null)
        {
            return;
        }

        var path = Path.GetFullPath(
            settings.CurrentValue.Mesh.AuthoritySigningKeyPath);
        AuthorityKeyFile stored;

        if (File.Exists(path))
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                16_384,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            stored = await JsonSerializer.DeserializeAsync<AuthorityKeyFile>(
                         stream,
                         JsonOptions,
                         cancellationToken)
                     ?? throw new InvalidDataException(
                         "The MagicControl authority signing key file is empty.");
        }
        else
        {
            using var generated = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var publicKey = Convert.ToBase64String(generated.ExportSubjectPublicKeyInfo());
            stored = new AuthorityKeyFile(
                MagicControlManifestCryptography.ComputeKeyId(publicKey),
                publicKey,
                Convert.ToBase64String(generated.ExportPkcs8PrivateKey()));
            await WriteAtomicallyAsync(path, stored, cancellationToken);
        }

        var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(Convert.FromBase64String(stored.PrivateKey), out _);
        var exportedPublicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

        if (!MagicControlManifestCryptography.PublicKeysMatch(
                stored.PublicKey,
                exportedPublicKey)
            || !string.Equals(
                stored.KeyId,
                MagicControlManifestCryptography.ComputeKeyId(exportedPublicKey),
                StringComparison.Ordinal))
        {
            key.Dispose();
            throw new CryptographicException(
                "The MagicControl authority signing key file is inconsistent.");
        }

        _key = key;
        _descriptor = new MagicControlAuthorityDescriptor(stored.KeyId, stored.PublicKey);
    }

    private static async ValueTask WriteAtomicallyAsync(
        string path,
        AuthorityKeyFile key,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);
        var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";

        try
        {
            await using (var stream = new FileStream(
                             temporaryPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             16_384,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, key, JsonOptions, cancellationToken);
                await stream.FlushAsync(cancellationToken);
            }

            RestrictPermissions(temporaryPath);
            File.Move(temporaryPath, path, overwrite: false);
            RestrictPermissions(path);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static void RestrictPermissions(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    public ValueTask DisposeAsync()
    {
        _key?.Dispose();
        _gate.Dispose();
        return ValueTask.CompletedTask;
    }

    private sealed record AuthorityKeyFile(
        string KeyId,
        string PublicKey,
        string PrivateKey);
}
