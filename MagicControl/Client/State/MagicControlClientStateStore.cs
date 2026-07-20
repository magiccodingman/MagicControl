using System.Security.Cryptography;
using MagicSettings.Share;

namespace MagicControl.Client;

public sealed record MagicControlClientPersistentState(
    string BootstrapNonce,
    string? AuthorityPublicKey,
    IReadOnlyList<Uri> MeshEndpoints,
    MagicRemoteSnapshot OfflineSnapshot,
    DateTimeOffset UpdatedUtc)
{
    public static MagicControlClientPersistentState CreateNew()
        => new(
            Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
            null,
            [],
            MagicRemoteSnapshot.Empty,
            DateTimeOffset.UtcNow);
}

public interface IMagicControlClientStateStore
{
    ValueTask<MagicControlClientPersistentState> LoadAsync(
        CancellationToken cancellationToken = default);

    ValueTask SaveAsync(
        MagicControlClientPersistentState state,
        CancellationToken cancellationToken = default);
}

public sealed class FileMagicControlClientStateStore : IMagicControlClientStateStore, IDisposable
{
    private readonly string _path;
    private readonly ProtectedManifestFileCodec _codec;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private MagicControlClientPersistentState? _loaded;

    public FileMagicControlClientStateStore(MagicControlClientOptions options)
    {
        _path = Path.GetFullPath(Path.Combine(options.StatePath, options.ClientStateFileName));
        _codec = new ProtectedManifestFileCodec(
            options.StatePath,
            $"MagicControl.Client.State:{options.ApplicationName}:{options.GroupId:D}");
    }

    public async ValueTask<MagicControlClientPersistentState> LoadAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_loaded is not null)
            {
                return _loaded;
            }

            if (!File.Exists(_path))
            {
                _loaded = MagicControlClientPersistentState.CreateNew();
                return _loaded;
            }

            try
            {
                var contents = await File.ReadAllBytesAsync(_path, cancellationToken);
                _loaded = _codec.Unprotect<MagicControlClientPersistentState>(contents);
            }
            catch (Exception exception) when (
                exception is IOException or CryptographicException or InvalidDataException)
            {
                _loaded = MagicControlClientPersistentState.CreateNew();
            }

            return _loaded;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask SaveAsync(
        MagicControlClientPersistentState state,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(state);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var directory = Path.GetDirectoryName(_path)!;
            Directory.CreateDirectory(directory);
            RestrictDirectory(directory);

            var temporaryPath = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                var payload = _codec.Protect(state);
                await File.WriteAllBytesAsync(temporaryPath, payload, cancellationToken);
                RestrictFile(temporaryPath);
                File.Move(temporaryPath, _path, overwrite: true);
                RestrictFile(_path);
                _loaded = state;
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
