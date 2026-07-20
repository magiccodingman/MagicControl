using MagicControl.Shared.Mesh;
using MagicControl.Web.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Tests;

public sealed class ConnectedMigrationTests
{
    [Fact]
    public async Task DatabaseMigrations_CreateConnectedSettingsTables()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"magic-control-migration-{Guid.NewGuid():N}.db");
        try
        {
            var options = new DbContextOptionsBuilder<MagicControlDbContext>()
                .UseSqlite($"Data Source={databasePath}")
                .Options;
            await using (var db = new MagicControlDbContext(options))
            {
                await db.Database.MigrateAsync();
            }

            await using var connection = new SqliteConnection($"Data Source={databasePath}");
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table'";
            await using var reader = await command.ExecuteReaderAsync();
            var tables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            while (await reader.ReadAsync())
            {
                tables.Add(reader.GetString(0));
            }

            Assert.Contains("ApplicationSchemas", tables);
            Assert.Contains("ApplicationSettingOverrides", tables);
            Assert.Contains("EnrollmentRequests", tables);
            Assert.Contains("ManagedInstances", tables);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            File.Delete(databasePath);
        }
    }

    [Fact]
    public void NodeContext_IsStableButBindsCapabilitiesAndEndpoints()
    {
        var groupId = Guid.NewGuid();
        var endpoint = new MagicControlServiceEndpointAnnouncement(
            new Uri("https://192.168.1.20:7443"),
            10,
            IsLan: true);

        var first = MagicControlNodeContext.Compute(
            groupId,
            "Orders",
            "Orders primary",
            "orders-1",
            "api",
            "home",
            "1.0.0",
            "nonce",
            ["orders.write", "orders.read"],
            [endpoint]);
        var reordered = MagicControlNodeContext.Compute(
            groupId,
            "Orders",
            "Orders primary",
            "orders-1",
            "api",
            "home",
            "1.0.0",
            "nonce",
            ["orders.read", "orders.write"],
            [endpoint]);
        var changedGrant = MagicControlNodeContext.Compute(
            groupId,
            "Orders",
            "Orders primary",
            "orders-1",
            "api",
            "home",
            "1.0.0",
            "nonce",
            ["orders.read"],
            [endpoint]);
        var changedEndpoint = MagicControlNodeContext.Compute(
            groupId,
            "Orders",
            "Orders primary",
            "orders-1",
            "api",
            "home",
            "1.0.0",
            "nonce",
            ["orders.write", "orders.read"],
            [endpoint with { Uri = new Uri("https://192.168.1.21:7443") }]);

        Assert.Equal(first, reordered);
        Assert.NotEqual(first, changedGrant);
        Assert.NotEqual(first, changedEndpoint);
    }
}
