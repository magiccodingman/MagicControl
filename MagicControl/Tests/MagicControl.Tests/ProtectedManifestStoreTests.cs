using System.Security.Cryptography;
using System.Text;
using MagicControl.Client;
using MagicControl.Shared.Mesh;

namespace MagicControl.Tests;

public sealed class ProtectedManifestStoreTests
{
    [Fact]
    public async Task PersistedManifest_IsEncryptedAndReloadable()
    {
        var statePath = Path.Combine(
            Path.GetTempPath(),
            "magic-control-tests",
            Guid.NewGuid().ToString("N"));
        var groupId = Guid.NewGuid();
        var options = new MagicControlClientOptions
        {
            GroupId = groupId,
            ApplicationName = "Orders",
            StatePath = statePath
        };

        try
        {
            var now = DateTimeOffset.UtcNow;
            var settings = new MagicControlSettingsSnapshot(
                4,
                now,
                [new MagicControlSettingValue("Database:Password", "not-readable-on-disk")]);
            var manifest = new MagicControlGroupManifest(
                groupId,
                "Home",
                MagicControlGroupSecurityMode.Secured,
                Guid.NewGuid(),
                9,
                now,
                MagicControlOfflineTrustPolicy.Infinite,
                [],
                [],
                settings);

            using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var stored = new StoredMagicControlManifest(
                MagicControlManifestCryptography.Sign(manifest, authority),
                now);

            using (var writer = new FileMagicControlManifestStore(options))
            {
                await writer.SaveAsync(stored);
            }

            var path = Path.Combine(statePath, options.ManifestFileName);
            var rawContents = await File.ReadAllBytesAsync(path);
            Assert.DoesNotContain(
                "not-readable-on-disk",
                Encoding.UTF8.GetString(rawContents),
                StringComparison.Ordinal);

            using var reader = new FileMagicControlManifestStore(options);
            var reloaded = await reader.LoadAsync();

            Assert.NotNull(reloaded);
            Assert.Equal(9, reloaded.Envelope.Manifest.Revision);
            Assert.Equal(
                "not-readable-on-disk",
                reloaded.Envelope.Manifest.Settings.Values.Single().Value);
        }
        finally
        {
            if (Directory.Exists(statePath))
            {
                Directory.Delete(statePath, recursive: true);
            }
        }
    }
}
