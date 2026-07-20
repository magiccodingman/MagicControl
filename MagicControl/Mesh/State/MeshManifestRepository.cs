using System.Security.Cryptography;
using MagicControl.Client;
using MagicControl.Shared.Mesh;
using Microsoft.Extensions.Options;

namespace MagicControl.Mesh;

public sealed class MeshManifestRepository(
    IOptionsMonitor<MagicControlMeshSettings> settings,
    MagicControlManifestCache cache,
    ILogger<MeshManifestRepository> logger) : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _stateDirectory = Path.GetFullPath(settings.CurrentValue.StatePath);
    private readonly ProtectedManifestFileCodec _codec = new(
        settings.CurrentValue.StatePath,
        "MagicControl.Mesh");

    public async ValueTask LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(_stateDirectory))
        {
            return;
        }

        foreach (var path in Directory.EnumerateFiles(_stateDirectory, "*.manifest.protected"))
        {
            try
            {
                var contents = await File.ReadAllBytesAsync(path, cancellationToken);
                var stored = _codec.Unprotect<StoredMagicControlManifest>(contents);
                if (!await ValidateAsync(stored, offline: true, cancellationToken))
                {
                    continue;
                }

                cache.Set(new MagicControlManifestState(
                    stored.Envelope,
                    stored.LastAuthorityContactUtc,
                    LoadedFromDisk: true));
            }
            catch (Exception exception) when (
                exception is IOException or CryptographicException or InvalidDataException)
            {
                logger.LogWarning(exception, "Ignoring invalid cached Mesh manifest {Path}.", path);
            }
        }
    }

    public async ValueTask AcceptAuthoritativeAsync(
        SignedMagicControlGroupManifest envelope,
        DateTimeOffset contactUtc,
        CancellationToken cancellationToken = default)
    {
        var stored = new StoredMagicControlManifest(envelope, contactUtc);
        if (!await ValidateAsync(stored, offline: false, cancellationToken))
        {
            throw new InvalidDataException(
                $"The control plane returned an untrusted manifest for group {envelope.Manifest.GroupId:D}.");
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(_stateDirectory);
            RestrictDirectoryPermissions(_stateDirectory);
            var path = Path.Combine(
                _stateDirectory,
                $"{envelope.Manifest.GroupId:D}.manifest.protected");
            var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            var protectedContents = _codec.Protect(stored);

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
                    await stream.WriteAsync(protectedContents, cancellationToken);
                    await stream.FlushAsync(cancellationToken);
                }

                RestrictPermissions(temporaryPath);
                File.Move(temporaryPath, path, overwrite: true);
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
        finally
        {
            _gate.Release();
        }

        cache.Set(new MagicControlManifestState(envelope, contactUtc, LoadedFromDisk: false));
    }

    private async ValueTask<bool> ValidateAsync(
        StoredMagicControlManifest stored,
        bool offline,
        CancellationToken cancellationToken)
    {
        var manifest = stored.Envelope.Manifest;
        if (!MagicControlManifestCryptography.Verify(stored.Envelope))
        {
            return false;
        }

        if (manifest.Settings.Values.Any(value => !value.PersistOffline))
        {
            return false;
        }

        if (offline && !manifest.OfflineTrust.AllowsOfflineUse(
                manifest.IssuedUtc,
                DateTimeOffset.UtcNow))
        {
            return false;
        }

        var configured = settings.CurrentValue.TrustedAuthorityPublicKey;
        var pinPath = Path.Combine(_stateDirectory, "authority-public-key.txt");
        var pinned = configured;
        if (string.IsNullOrWhiteSpace(pinned) && File.Exists(pinPath))
        {
            pinned = (await File.ReadAllTextAsync(pinPath, cancellationToken)).Trim();
        }

        if (string.IsNullOrWhiteSpace(pinned))
        {
            if (!settings.CurrentValue.AllowAuthorityTrustOnFirstUse)
            {
                return false;
            }

            Directory.CreateDirectory(_stateDirectory);
            RestrictDirectoryPermissions(_stateDirectory);
            await File.WriteAllTextAsync(
                pinPath,
                stored.Envelope.AuthorityPublicKey,
                cancellationToken);
            RestrictPermissions(pinPath);
            pinned = stored.Envelope.AuthorityPublicKey;
        }

        return MagicControlManifestCryptography.PublicKeysMatch(
            pinned,
            stored.Envelope.AuthorityPublicKey);
    }

    private static void RestrictPermissions(string path)
    {
        if (!OperatingSystem.IsWindows())
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
        _codec.Dispose();
        _gate.Dispose();
    }
}
