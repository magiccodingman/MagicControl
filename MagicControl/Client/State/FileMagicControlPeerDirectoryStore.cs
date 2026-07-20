using System.Security.Cryptography;

namespace MagicControl.Client;

public sealed class FileMagicControlPeerDirectoryStore : IMagicControlPeerDirectoryStore, IDisposable
{
    private readonly string _path;
    private readonly ProtectedManifestFileCodec _codec;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public FileMagicControlPeerDirectoryStore(MagicControlClientOptions options)
    {
        _path = Path.GetFullPath(Path.Combine(options.StatePath, options.PeerDirectoryFileName));
        _codec = new ProtectedManifestFileCodec(
            options.StatePath,
            $"MagicControl.Client.Peers:{options.ApplicationName}:{options.GroupId:D}");
    }

    public async ValueTask<IReadOnlyList<MagicControlPeerObservation>> LoadAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(_path))
            {
                return [];
            }

            try
            {
                var contents = await File.ReadAllBytesAsync(_path, cancellationToken);
                return _codec.Unprotect<MagicControlPeerObservation[]>(contents);
            }
            catch (Exception exception) when (
                exception is IOException or CryptographicException or InvalidDataException)
            {
                return [];
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask SaveAsync(
        IReadOnlyList<MagicControlPeerObservation> observations,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(observations);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var directory = Path.GetDirectoryName(_path)!;
            Directory.CreateDirectory(directory);
            RestrictDirectory(directory);

            var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                var persistent = observations
                    .Select(observation => observation with { LoadedFromDisk = false })
                    .ToArray();
                await File.WriteAllBytesAsync(
                    temporary,
                    _codec.Protect(persistent),
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
        finally
        {
            _gate.Release();
        }
    }

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
