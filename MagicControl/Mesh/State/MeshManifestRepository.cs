using System.Text.Json;
using MagicControl.Client;
using MagicControl.Shared.Mesh;
using Microsoft.Extensions.Options;

namespace MagicControl.Mesh;

public sealed class MeshManifestRepository(
    IOptionsMonitor<MagicControlMeshSettings> settings,
    MagicControlManifestCache cache,
    ILogger<MeshManifestRepository> logger)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly SemaphoreSlim _gate = new(1, 1);

    public async ValueTask LoadAsync(CancellationToken cancellationToken = default)
    {
        var directory = StateDirectory();
        if (!Directory.Exists(directory))
        {
            return;
        }

        foreach (var path in Directory.EnumerateFiles(directory, "*.manifest.json"))
        {
            try
            {
                await using var stream = File.OpenRead(path);
                var stored = await JsonSerializer.DeserializeAsync<StoredMagicControlManifest>(
                    stream,
                    JsonOptions,
                    cancellationToken);
                if (stored is null || !await ValidateAsync(stored, offline: true, cancellationToken))
                {
                    continue;
                }

                cache.Set(new MagicControlManifestState(
                    stored.Envelope,
                    stored.LastAuthorityContactUtc,
                    LoadedFromDisk: true));
            }
            catch (Exception exception) when (exception is IOException or JsonException)
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
            var directory = StateDirectory();
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, $"{envelope.Manifest.GroupId:D}.manifest.json");
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
                    await JsonSerializer.SerializeAsync(stream, stored, JsonOptions, cancellationToken);
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
        if (!MagicControlManifestCryptography.Verify(stored.Envelope))
        {
            return false;
        }

        if (offline && !stored.Envelope.Manifest.OfflineTrust.AllowsOfflineUse(
                stored.LastAuthorityContactUtc,
                DateTimeOffset.UtcNow))
        {
            return false;
        }

        var configured = settings.CurrentValue.TrustedAuthorityPublicKey;
        var pinPath = Path.Combine(StateDirectory(), "authority-public-key.txt");
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

            Directory.CreateDirectory(StateDirectory());
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

    private string StateDirectory()
        => Path.GetFullPath(settings.CurrentValue.StatePath);

    private static void RestrictPermissions(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}
