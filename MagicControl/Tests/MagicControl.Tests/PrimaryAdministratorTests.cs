using MagicControl.Shared.Security;
using MagicControl.Shared.Utilities;
using MagicControl.Web.Configuration;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using MagicControl.Web.Features.Common;
using MagicControl.Web.Features.Setup;
using MagicControl.Web.Features.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace MagicControl.Tests;

public sealed class PrimaryAdministratorTests
{
    [Fact]
    public async Task CompleteAsync_CreatesFixedAdminAndPrimaryState()
    {
        var databasePath = TemporaryDatabasePath();
        var options = CreateOptions(databasePath);

        try
        {
            await using (var db = new MagicControlDbContext(options))
            {
                await db.Database.EnsureCreatedAsync();
            }

            var setup = new SetupService(
                new TestDbContextFactory(options),
                new PasswordHasher<ControlUser>(),
                new TestOptionsMonitor<MagicControlSettings>(MagicControlSettings.CreateDefaults()));

            var result = await setup.CompleteAsync(
                new InitialSetupRequest("A-very-long-primary-password!", "A-very-long-primary-password!"));

            Assert.True(result.Succeeded);
            Assert.NotNull(result.UserId);

            await using var verification = new MagicControlDbContext(options);
            var user = await verification.Users.SingleAsync();
            var primaryId = await verification.SystemStates
                .Where(x => x.Key == PrimaryAdministratorStore.StateKey)
                .Select(x => x.Value)
                .SingleAsync();

            Assert.Equal(PrimaryAdministratorStore.Username, user.Username);
            Assert.Equal(user.Id.ToString("D"), primaryId);
        }
        finally
        {
            DeleteDatabase(databasePath);
        }
    }

    [Fact]
    public async Task ExistingFirstSuperAdministrator_IsBackfilledAndProtected()
    {
        var databasePath = TemporaryDatabasePath();
        var options = CreateOptions(databasePath);
        var primaryUserId = Guid.NewGuid();

        try
        {
            await using (var db = new MagicControlDbContext(options))
            {
                await db.Database.EnsureCreatedAsync();
                var createdUtc = DateTimeOffset.Parse("2026-07-20T12:00:00Z");
                var primary = new ControlUser
                {
                    Id = primaryUserId,
                    Username = "legacy-owner",
                    NormalizedUsername = MagicControlNameNormalizer.Normalize("legacy-owner"),
                    PasswordHash = "not-used",
                    SecurityStamp = Guid.NewGuid().ToString("N"),
                    CreatedUtc = createdUtc,
                    UpdatedUtc = createdUtc,
                    PasswordChangedUtc = createdUtc
                };
                var superAdministrator = new ControlRole
                {
                    Name = MagicControlRoles.SuperAdministrator,
                    NormalizedName = MagicControlNameNormalizer.Normalize(
                        MagicControlRoles.SuperAdministrator),
                    IsBuiltIn = true,
                    CreatedUtc = createdUtc
                };
                var viewer = new ControlRole
                {
                    Name = MagicControlRoles.Viewer,
                    NormalizedName = MagicControlNameNormalizer.Normalize(MagicControlRoles.Viewer),
                    IsBuiltIn = true,
                    CreatedUtc = createdUtc
                };

                db.Users.Add(primary);
                db.Roles.AddRange(superAdministrator, viewer);
                db.UserRoles.Add(new ControlUserRole
                {
                    User = primary,
                    Role = superAdministrator
                });
                await db.SaveChangesAsync();
            }

            var users = CreateUserAdministration(options);
            var summaries = await users.GetUsersAsync();

            var summary = Assert.Single(summaries);
            Assert.True(summary.IsPrimaryAdministrator);

            var disableException = await Assert.ThrowsAsync<InvalidOperationException>(
                () => users.SetDisabledAsync(primaryUserId, true, Guid.NewGuid()).AsTask());
            Assert.Equal("The primary administrator cannot be disabled.", disableException.Message);

            var roleException = await Assert.ThrowsAsync<InvalidOperationException>(
                () => users.SetRolesAsync(
                    primaryUserId,
                    [MagicControlRoles.Viewer],
                    Guid.NewGuid()).AsTask());
            Assert.Equal(
                "The primary administrator must retain the Super Administrator role.",
                roleException.Message);

            await using var verification = new MagicControlDbContext(options);
            var storedPrimaryId = await verification.SystemStates
                .Where(x => x.Key == PrimaryAdministratorStore.StateKey)
                .Select(x => x.Value)
                .SingleAsync();
            var user = await verification.Users
                .Include(x => x.UserRoles)
                .ThenInclude(x => x.Role)
                .SingleAsync(x => x.Id == primaryUserId);

            Assert.Equal(primaryUserId.ToString("D"), storedPrimaryId);
            Assert.False(user.IsDisabled);
            Assert.Contains(
                user.UserRoles,
                x => x.Role.Name == MagicControlRoles.SuperAdministrator);
        }
        finally
        {
            DeleteDatabase(databasePath);
        }
    }

    private static UserAdministrationService CreateUserAdministration(
        DbContextOptions<MagicControlDbContext> options)
        => new(
            new TestDbContextFactory(options),
            new PasswordHasher<ControlUser>(),
            new TemporaryPasswordGenerator(),
            new TestOptionsMonitor<MagicControlSettings>(MagicControlSettings.CreateDefaults()));

    private static DbContextOptions<MagicControlDbContext> CreateOptions(string databasePath)
        => new DbContextOptionsBuilder<MagicControlDbContext>()
            .UseSqlite($"Data Source={databasePath}")
            .Options;

    private static string TemporaryDatabasePath()
        => Path.Combine(
            Path.GetTempPath(),
            $"magic-control-primary-admin-{Guid.NewGuid():N}.db");

    private static void DeleteDatabase(string databasePath)
    {
        SqliteConnection.ClearAllPools();
        File.Delete(databasePath);
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

    private sealed class TestOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
