using System.Text.Json;
using MagicControl.Shared.Enrollments;
using MagicControl.Shared.Mesh;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using MagicControl.Web.Features.Instances;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Tests;

public sealed class CapabilityAdministrationTests
{
    [Fact]
    public async Task UpdateCapabilities_AdvancesGroupManifestRevisionAndAuditsChange()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"magic-control-capabilities-{Guid.NewGuid():N}.db");
        var options = new DbContextOptionsBuilder<MagicControlDbContext>()
            .UseSqlite($"Data Source={databasePath}")
            .Options;
        var factory = new TestDbContextFactory(options);
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
                    ManifestRevision = 7,
                    CreatedUtc = DateTimeOffset.UtcNow,
                    UpdatedUtc = DateTimeOffset.UtcNow
                };
                db.ManagedInstances.Add(new ManagedInstance
                {
                    Id = instanceId,
                    Kind = EnrollmentKind.ApplicationInstance,
                    Status = ManagedInstanceStatus.Active,
                    DisplayName = "Orders",
                    ApplicationName = "Orders",
                    CapabilitiesJson = JsonSerializer.Serialize(new Dictionary<string, string>
                    {
                        ["orders.read"] = "approved"
                    }),
                    MetadataJson = "{}",
                    EndpointsJson = "[]",
                    Group = group,
                    CreatedUtc = DateTimeOffset.UtcNow,
                    ApprovedUtc = DateTimeOffset.UtcNow
                });
                await db.SaveChangesAsync();
            }

            var service = new ManagedInstanceAdministrationService(factory);
            await service.UpdateCapabilitiesAsync(
                instanceId,
                ["orders.write", "orders.read", "orders.write"],
                actorId);

            await using var verification = new MagicControlDbContext(options);
            var instance = await verification.ManagedInstances
                .AsNoTracking()
                .SingleAsync(candidate => candidate.Id == instanceId);
            var groupRevision = await verification.Groups
                .AsNoTracking()
                .Where(candidate => candidate.Id == groupId)
                .Select(candidate => candidate.ManifestRevision)
                .SingleAsync();
            var capabilities = JsonSerializer.Deserialize<Dictionary<string, string>>(
                instance.CapabilitiesJson)!;
            var audit = await verification.AuditEvents
                .AsNoTracking()
                .SingleAsync(candidate =>
                    candidate.Action == "managed-instance.capabilities.changed");

            Assert.Equal(8, groupRevision);
            Assert.Equal(["orders.read", "orders.write"], capabilities.Keys.OrderBy(value => value));
            Assert.Equal(actorId.ToString("D"), audit.ActorId);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            File.Delete(databasePath);
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
