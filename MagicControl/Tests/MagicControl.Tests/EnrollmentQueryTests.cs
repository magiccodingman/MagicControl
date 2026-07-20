using MagicControl.Shared.Enrollments;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using MagicControl.Web.Features.Enrollments;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Tests;

public sealed class EnrollmentQueryTests
{
    [Fact]
    public async Task GetRequestsAsync_OrdersDateTimeOffsetValuesWithSqlite()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"magic-control-enrollment-{Guid.NewGuid():N}.db");
        var options = new DbContextOptionsBuilder<MagicControlDbContext>()
            .UseSqlite($"Data Source={databasePath}")
            .Options;

        try
        {
            await using (var db = new MagicControlDbContext(options))
            {
                await db.Database.EnsureCreatedAsync();
                db.EnrollmentRequests.AddRange(
                    CreateRequest(
                        "Older pending",
                        EnrollmentRequestStatus.Pending,
                        DateTimeOffset.Parse("2026-07-20T12:00:00Z")),
                    CreateRequest(
                        "Newer pending",
                        EnrollmentRequestStatus.Pending,
                        DateTimeOffset.Parse("2026-07-20T13:00:00Z")),
                    CreateRequest(
                        "Newest rejected",
                        EnrollmentRequestStatus.Rejected,
                        DateTimeOffset.Parse("2026-07-20T14:00:00Z")));
                await db.SaveChangesAsync();
            }

            var service = new EnrollmentService(new TestDbContextFactory(options));

            var requests = await service.GetRequestsAsync();

            Assert.Equal(
                ["Newer pending", "Older pending", "Newest rejected"],
                requests.Select(x => x.DisplayName));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            File.Delete(databasePath);
        }
    }

    private static EnrollmentRequestEntity CreateRequest(
        string displayName,
        EnrollmentRequestStatus status,
        DateTimeOffset lastSeenUtc)
        => new()
        {
            Kind = EnrollmentKind.ApplicationInstance,
            Status = status,
            NodeId = Guid.NewGuid(),
            CredentialId = Guid.NewGuid(),
            PublicKey = "test-public-key",
            Fingerprint = Guid.NewGuid().ToString("N"),
            SignatureAlgorithm = "test",
            DisplayName = displayName,
            FirstSeenUtc = lastSeenUtc.AddMinutes(-1),
            LastSeenUtc = lastSeenUtc
        };

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
