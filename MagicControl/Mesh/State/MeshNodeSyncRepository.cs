using System.Security.Cryptography;
using MagicControl.Client;
using MagicControl.Shared.Mesh;
using MagicSettings.Share;
using Microsoft.Extensions.Options;

namespace MagicControl.Mesh;

public sealed class MeshNodeSyncRepository : IDisposable
{
    private readonly string _path;
    private readonly ProtectedManifestFileCodec _codec;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Dictionary<string, MagicControlNodeSyncResponse>? _cache;

    public MeshNodeSyncRepository(IOptionsMonitor<MagicControlMeshSettings> settings)
    {
        var statePath = settings.CurrentValue.StatePath;
        _path = Path.GetFullPath(Path.Combine(statePath, "node-sync-cache.protected"));
        _codec = new ProtectedManifestFileCodec(
            statePath,
            "MagicControl.Mesh.NodeSyncCache");
    }

    public async ValueTask SaveAsync(
        MagicControlNodeSyncRequest request,
        MagicControlNodeSyncResponse response,
        CancellationToken cancellationToken = default)
    {
        if (response.EnrollmentState != MagicControlEnrollmentState.Approved
            || response.Manifest is null)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            var cache = await LoadUnderLockAsync(cancellationToken);
            cache[Key(request)] = response with
            {
                Settings = response.Settings with
                {
                    State = MagicControlPlaneState.Active,
                    Snapshot = response.OfflineSnapshot
                },
                Message = "MagicControl Web is unavailable; Mesh returned last-known-good approved state."
            };
            await PersistUnderLockAsync(cache, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<MagicControlNodeSyncResponse?> LoadAsync(
        MagicControlNodeSyncRequest request,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var cache = await LoadUnderLockAsync(cancellationToken);
            if (!cache.TryGetValue(Key(request), out var response)
                || response.Manifest is null
                || !MagicControlManifestCryptography.Verify(response.Manifest)
                || response.Manifest.Manifest.GroupId != request.GroupId
                || !response.Manifest.Manifest.Members.Any(member =>
                    member.NodeId == request.Settings.Identity.NodeId
                    && member.CredentialId == request.Settings.Identity.CredentialId)
                || !response.Manifest.Manifest.OfflineTrust.AllowsOfflineUse(
                    response.Manifest.Manifest.IssuedUtc,
                    DateTimeOffset.UtcNow))
            {
                return null;
            }

            return response with
            {
                BootstrapNonce = request.BootstrapNonce,
                Settings = response.Settings with
                {
                    State = MagicControlPlaneState.Active,
                    Snapshot = response.OfflineSnapshot
                },
                Message = "MagicControl Web is unavailable; Mesh returned last-known-good approved state."
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    private async ValueTask<Dictionary<string, MagicControlNodeSyncResponse>> LoadUnderLockAsync(
        CancellationToken cancellationToken)
    {
        if (_cache is not null)
        {
            return _cache;
        }

        if (!File.Exists(_path))
        {
            _cache = new Dictionary<string, MagicControlNodeSyncResponse>(StringComparer.Ordinal);
            return _cache;
        }

        try
        {
            var payload = await File.ReadAllBytesAsync(_path, cancellationToken);
            _cache = _codec.Unprotect<Dictionary<string, MagicControlNodeSyncResponse>>(payload);
        }
        catch (Exception exception) when (
            exception is IOException or CryptographicException or InvalidDataException)
        {
            _cache = new Dictionary<string, MagicControlNodeSyncResponse>(StringComparer.Ordinal);
        }

        return _cache;
    }

    private async ValueTask PersistUnderLockAsync(
        Dictionary<string, MagicControlNodeSyncResponse> cache,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(_path)!;
        Directory.CreateDirectory(directory);
        RestrictDirectory(directory);
        var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllBytesAsync(
                temporary,
                _codec.Protect(cache),
                cancellationToken);
            RestrictFile(temporary);
            File.Move(temporary, _path, overwrite: true);
            RestrictFile(_path);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static string Key(MagicControlNodeSyncRequest request)
        => string.Join(
            ':',
            request.GroupId.ToString("D"),
            request.ApplicationName,
            request.Settings.Identity.NodeId.ToString("D"),
            request.Settings.Identity.CredentialId.ToString("D"));

    private static void RestrictFile(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    private static void RestrictDirectory(string path)
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
        _gate.Dispose();
        _codec.Dispose();
    }
}
