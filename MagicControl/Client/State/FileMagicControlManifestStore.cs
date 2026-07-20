using System.Security.Cryptography;
using MagicControl.Shared.Mesh;

namespace MagicControl.Client;

public sealed record StoredMagicControlManifest(
    SignedMagicControlGroupManifest Envelope,
    DateTimeOffset LastAuthorityContactUtc);

public interface IMagicControlManifestStore
{
    ValueTask<StoredMagicControlManifest?> LoadAsync(CancellationToken cancellationToken = default);
    ValueTask SaveAsync(StoredMagicControlManifest manifest, CancellationToken cancellationToken = default);
}

public sealed class FileMagicControlManifestStore : IMagicControlManifestStore, IDisposable
{
    private readonly string _path;
    private readonly ProtectedManifestFileCodec _codec;

    public FileMagicControlManifestStore(MagicControlClientOptions options)
    {
        _path = Path.GetFullPath(Path.Combine(options.StatePath, options.ManifestFileName));
        _codec = new ProtectedManifestFileCodec(
            options.StatePath,
            $"MagicControl.Client:{options.ApplicationName}:{options.GroupId:D}");
    }

    public async ValueTask<StoredMagicControlManifest?> LoadAsync(
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_path))
        {
            return null;
        }

        try
        {
            var contents = await File.ReadAllBytesAsync(_path, cancellationToken);
            return _codec.Unprotect<StoredMagicControlManifest>(contents);
        }
        catch (Exception exception) when (
            exception is IOException or CryptographicException or InvalidDataException)
        {
            return null;
        }
    }

    public async ValueTask SaveAsync(
        StoredMagicControlManifest manifest,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        EnsureOfflineSafe(manifest.Envelope.Manifest.Settings);

        var directory = Path.GetDirectoryName(_path)!;
        Directory.CreateDirectory(directory);
        RestrictDirectoryPermissions(directory);

        var protectedContents = _codec.Protect(manifest);
        var temporaryPath = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
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

            RestrictFilePermissions(temporaryPath);
            File.Move(temporaryPath, _path, overwrite: true);
            RestrictFilePermissions(_path);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static void EnsureOfflineSafe(MagicControlSettingsSnapshot settings)
    {
        if (settings.Values.Any(value => !value.PersistOffline))
        {
            throw new InvalidDataException(
                "The signed fallback manifest contains a setting that is not permitted on disk. " +
                "Non-persistable settings must be delivered through the live settings channel.");
        }
    }

    private static void RestrictFilePermissions(string path)
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

    public void Dispose() => _codec.Dispose();
}

public sealed record MagicControlManifestValidationResult(bool IsValid, string? Error)
{
    public static MagicControlManifestValidationResult Valid { get; } = new(true, null);
    public static MagicControlManifestValidationResult Invalid(string error) => new(false, error);
}

public sealed class MagicControlManifestValidator(MagicControlClientOptions options)
{
    private readonly string _authorityPinPath = Path.GetFullPath(
        Path.Combine(options.StatePath, "authority-public-key.txt"));

    public async ValueTask<MagicControlManifestValidationResult> ValidateAsync(
        StoredMagicControlManifest stored,
        bool offline,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stored);
        var envelope = stored.Envelope;

        if (envelope.Manifest.GroupId != options.GroupId)
        {
            return MagicControlManifestValidationResult.Invalid(
                "The manifest belongs to a different MagicControl group.");
        }

        if (!MagicControlManifestCryptography.Verify(envelope))
        {
            return MagicControlManifestValidationResult.Invalid(
                "The manifest authority signature is invalid.");
        }

        if (envelope.Manifest.Settings.Values.Any(value => !value.PersistOffline))
        {
            return MagicControlManifestValidationResult.Invalid(
                "The fallback manifest contains a non-persistable setting.");
        }

        var pinnedPublicKey = options.TrustedAuthorityPublicKey;
        if (string.IsNullOrWhiteSpace(pinnedPublicKey) && File.Exists(_authorityPinPath))
        {
            pinnedPublicKey = (await File.ReadAllTextAsync(_authorityPinPath, cancellationToken)).Trim();
        }

        if (envelope.Manifest.SecurityMode == MagicControlGroupSecurityMode.Secured)
        {
            if (string.IsNullOrWhiteSpace(pinnedPublicKey))
            {
                if (!options.AllowAuthorityTrustOnFirstUse)
                {
                    return MagicControlManifestValidationResult.Invalid(
                        "The secured group authority is not pinned. Complete enrollment or explicitly enable trust on first use.");
                }

                await PinAuthorityAsync(envelope.AuthorityPublicKey, cancellationToken);
                pinnedPublicKey = envelope.AuthorityPublicKey;
            }

            if (!MagicControlManifestCryptography.PublicKeysMatch(
                    pinnedPublicKey,
                    envelope.AuthorityPublicKey))
            {
                return MagicControlManifestValidationResult.Invalid(
                    "The manifest was signed by an unexpected MagicControl authority.");
            }
        }

        if (offline && !envelope.Manifest.OfflineTrust.AllowsOfflineUse(
                envelope.Manifest.IssuedUtc,
                nowUtc))
        {
            return MagicControlManifestValidationResult.Invalid(
                "The group's configured offline trust period has expired.");
        }

        return MagicControlManifestValidationResult.Valid;
    }

    private async ValueTask PinAuthorityAsync(
        string publicKey,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(_authorityPinPath)!;
        Directory.CreateDirectory(directory);
        await File.WriteAllTextAsync(_authorityPinPath, publicKey, cancellationToken);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                _authorityPinPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}
