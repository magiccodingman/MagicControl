using MagicControl.Client;
using MagicControl.Shared.Enrollments;
using MagicControl.Shared.Mesh;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using MagicControl.Web.Features.Settings;
using MagicSettings.Share;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Tests;

public sealed class ConnectedPlatformTests
{
    [Fact]
    public async Task DiscoveryResolver_AllowsSdkOnlyLocalMode()
    {
        var statePath = Path.Combine(
            Path.GetTempPath(),
            "magic-control-local-only",
            Guid.NewGuid().ToString("N"));
        try
        {
            var options = new MagicControlClientOptions
            {
                GroupId = Guid.NewGuid(),
                ApplicationName = "Orders",
                StatePath = statePath,
                EnableAutomaticDiscovery = false
            };
            options.Validate();
            using var store = new FileMagicControlClientStateStore(options);
            var resolver = new DiscoveringMagicControlMeshEndpointResolver(options, store);

            var endpoints = await resolver.ResolveAsync();

            Assert.Empty(endpoints);
        }
        finally
        {
            if (Directory.Exists(statePath))
            {
                Directory.Delete(statePath, recursive: true);
            }
        }
    }

    [Fact]
    public void ServiceResolver_PrefersLoopbackThenFailsOver()
    {
        var groupId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var directory = new MagicControlDirectoryEntry(
            Guid.NewGuid(),
            "Orders",
            "primary",
            "api",
            "home",
            [
                new MagicControlServiceEndpoint(
                    new Uri("https://203.0.113.10:7443"),
                    Priority: 5),
                new MagicControlServiceEndpoint(
                    new Uri("https://192.168.1.10:7443"),
                    Priority: 20,
                    IsLan: true),
                new MagicControlServiceEndpoint(
                    new Uri("https://127.0.0.1:7443"),
                    Priority: 100,
                    IsLoopback: true)
            ],
            1,
            now,
            now.AddMinutes(2));
        var manifest = new MagicControlGroupManifest(
            groupId,
            "Home",
            MagicControlGroupSecurityMode.Secured,
            Guid.NewGuid(),
            1,
            now,
            MagicControlOfflineTrustPolicy.Infinite,
            [],
            [directory],
            MagicControlSettingsSnapshot.Empty(now));
        using var authority = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var cache = new MagicControlManifestCache();
        cache.Set(new MagicControlManifestState(
            MagicControlManifestCryptography.Sign(manifest, authority),
            now,
            false));
        var options = new MagicControlClientOptions
        {
            GroupId = groupId,
            ApplicationName = "Consumer"
        };
        var resolver = new MagicControlServiceResolver(options, cache);

        var first = resolver.Resolve("Orders");
        Assert.Equal("127.0.0.1", first?.Endpoint.Uri.Host);

        resolver.ReportFailure(first!.Endpoint.Uri, TimeSpan.FromMinutes(1));
        var second = resolver.Resolve("Orders");
        Assert.Equal("192.168.1.10", second?.Endpoint.Uri.Host);
    }

    [Fact]
    public async Task SettingsService_AppliesScopedPrecedenceAndKeepsSecretsLiveOnly()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"magic-control-settings-{Guid.NewGuid():N}.db");
        var protectionPath = Path.Combine(
            Path.GetTempPath(),
            "magic-control-data-protection",
            Guid.NewGuid().ToString("N"));
        var options = new DbContextOptionsBuilder<MagicControlDbContext>()
            .UseSqlite($"Data Source={databasePath}")
            .Options;
        var factory = new TestDbContextFactory(options);
        var dataProtection = DataProtectionProvider.Create(new DirectoryInfo(protectionPath));
        var service = new ApplicationSettingsService(factory, dataProtection);
        var groupId = Guid.NewGuid();
        var instanceId = Guid.NewGuid();
        var actorId = Guid.NewGuid();

        try
        {
            await using (var db = new MagicControlDbContext(options))
            {
                await db.Database.EnsureCreatedAsync();
                var group = new ControlGroup
                {
                    Id = groupId,
                    Name = "Home",
                    NormalizedName = "HOME",
                    SecurityMode = MagicControlGroupSecurityMode.Secured,
                    SecurityEpoch = Guid.NewGuid(),
                    ManifestRevision = 1,
                    CreatedUtc = DateTimeOffset.UtcNow,
                    UpdatedUtc = DateTimeOffset.UtcNow
                };
                db.Groups.Add(group);
                db.ManagedInstances.Add(new ManagedInstance
                {
                    Id = instanceId,
                    Kind = EnrollmentKind.ApplicationInstance,
                    Status = ManagedInstanceStatus.Active,
                    DisplayName = "Orders primary",
                    ApplicationName = "Orders",
                    InstanceName = "orders-1",
                    InstanceRole = "api",
                    SiteName = "home",
                    CapabilitiesJson = "{}",
                    MetadataJson = "{}",
                    EndpointsJson = "[]",
                    Group = group,
                    CreatedUtc = DateTimeOffset.UtcNow,
                    ApprovedUtc = DateTimeOffset.UtcNow
                });
                await db.SaveChangesAsync();
            }

            var manifest = new MagicSettingsSchemaManifest(
                "Orders",
                "1.0.0",
                1,
                "schema-fingerprint",
                [
                    new MagicSettingManifestEntry(
                        "Database:Host",
                        typeof(string).FullName!,
                        false,
                        false,
                        true),
                    new MagicSettingManifestEntry(
                        "Database:Password",
                        typeof(string).FullName!,
                        false,
                        true,
                        true)
                ]);
            var schema = await service.UpsertSchemaAsync(groupId, manifest, null);

            await service.SaveOverrideAsync(
                schema.Id,
                new SaveApplicationSettingOverrideRequest(
                    "Database:Host",
                    MagicControlSettingScopeKind.Application,
                    null,
                    "application.example",
                    false,
                    MagicRemoteValueDurability.Sticky,
                    true,
                    false,
                    null),
                actorId);
            await service.SaveOverrideAsync(
                schema.Id,
                new SaveApplicationSettingOverrideRequest(
                    "Database:Host",
                    MagicControlSettingScopeKind.Site,
                    "home",
                    "site.example",
                    false,
                    MagicRemoteValueDurability.Sticky,
                    true,
                    false,
                    null),
                actorId);
            await service.SaveOverrideAsync(
                schema.Id,
                new SaveApplicationSettingOverrideRequest(
                    "Database:Host",
                    MagicControlSettingScopeKind.Instance,
                    instanceId.ToString("D"),
                    "instance.example",
                    false,
                    MagicRemoteValueDurability.Sticky,
                    true,
                    false,
                    null),
                actorId);
            await service.SaveOverrideAsync(
                schema.Id,
                new SaveApplicationSettingOverrideRequest(
                    "Database:Password",
                    MagicControlSettingScopeKind.Instance,
                    instanceId.ToString("D"),
                    "super-secret",
                    false,
                    MagicRemoteValueDurability.Refreshable,
                    true,
                    true,
                    null),
                actorId);

            ManagedInstance instance;
            await using (var db = new MagicControlDbContext(options))
            {
                instance = await db.ManagedInstances.AsNoTracking().SingleAsync();
            }

            var snapshots = await service.BuildSnapshotsAsync(instance);
            var host = snapshots.Effective.Values["Database:Host"];
            Assert.Equal("instance.example", host.Value?.GetString());
            Assert.Equal("instance.example", snapshots.Offline.Values["Database:Host"].Value?.GetString());
            Assert.DoesNotContain("Database:Password", snapshots.Effective.Values.Keys);
            Assert.DoesNotContain("Database:Password", snapshots.Offline.Values.Keys);

            var secret = await service.ResolveSecretAsync(instance, "Database:Password");
            Assert.True(secret.Found);
            Assert.Equal("super-secret", secret.Value);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            File.Delete(databasePath);
            if (Directory.Exists(protectionPath))
            {
                Directory.Delete(protectionPath, recursive: true);
            }
        }
    }

    private sealed class TestDbContextFactory(
        DbContextOptions<MagicControlDbContext> options)
        : IDbContextFactory<MagicControlDbContext>
    {
        public MagicControlDbContext CreateDbContext() => new(options);

        public Task<MagicControlDbContext> CreateDbContextAsync(
            CancellationToken cancellationToken = default)
            => Task.FromResult(CreateDbContext());
    }
}
