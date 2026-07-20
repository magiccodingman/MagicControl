using System.Text;
using MagicControl.Shared.Mesh;

namespace MagicControl.Client;

/// <summary>
/// A one-way local security marker. Its contents are informational; the existence of the
/// restricted file is the latch so truncated or partially corrupted state remains fail-closed.
/// Only a successfully validated signed Open manifest may clear it.
/// </summary>
public interface IMagicControlSecurityLatchStore
{
    bool IsLatched { get; }

    ValueTask LatchAsync(
        SignedMagicControlGroupManifest manifest,
        CancellationToken cancellationToken = default);

    ValueTask ClearAsync(CancellationToken cancellationToken = default);
}

public sealed class FileMagicControlSecurityLatchStore : IMagicControlSecurityLatchStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public FileMagicControlSecurityLatchStore(MagicControlClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _path = Path.GetFullPath(Path.Combine(options.StatePath, options.SecurityLatchFileName));
    }

    public bool IsLatched => File.Exists(_path);

    public async ValueTask LatchAsync(
        SignedMagicControlGroupManifest manifest,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var directory = Path.GetDirectoryName(_path)!;
            Directory.CreateDirectory(directory);
            RestrictDirectory(directory);

            var payload = string.Join(
                '\n',
                "MAGICCONTROL-SECURED-POLICY-V1",
                manifest.Manifest.GroupId.ToString("D"),
                manifest.AuthorityKeyId,
                manifest.Manifest.SecurityEpoch.ToString("D"),
                manifest.Manifest.Revision.ToString(System.Globalization.CultureInfo.InvariantCulture),
                DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                string.Empty);
            var temporaryPath = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                await File.WriteAllTextAsync(
                    temporaryPath,
                    payload,
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                    cancellationToken);
                RestrictFile(temporaryPath);
                File.Move(temporaryPath, _path, overwrite: true);
                RestrictFile(_path);
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

    public async ValueTask ClearAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (File.Exists(_path))
            {
                File.Delete(_path);
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
}

public sealed class MagicControlRuntimeSecurityState(
    IMagicControlSecurityLatchStore latchStore)
{
    private int _requiresAuthorization = latchStore.IsLatched ? 1 : 0;

    public bool RequiresAuthorization => Volatile.Read(ref _requiresAuthorization) == 1;

    /// <summary>
    /// Applies a manifest only after the normal signature, authority pin, group, and membership
    /// validation path has accepted it.
    /// </summary>
    public async ValueTask ApplyValidatedManifestAsync(
        SignedMagicControlGroupManifest manifest,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        if (manifest.Manifest.SecurityMode == MagicControlGroupSecurityMode.Secured)
        {
            // Close the in-memory gate before touching disk so the next request is secured.
            Volatile.Write(ref _requiresAuthorization, 1);
            await latchStore.LatchAsync(manifest, cancellationToken);
            return;
        }

        // Opening is intentionally the reverse order: remove the persistent latch first, then
        // expose Open mode in memory. Callers must only invoke this for a validated authority
        // manifest, never because discovery or connectivity disappeared.
        await latchStore.ClearAsync(cancellationToken);
        Volatile.Write(ref _requiresAuthorization, 0);
    }
}
