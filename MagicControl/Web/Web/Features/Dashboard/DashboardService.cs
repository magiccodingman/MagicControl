using MagicControl.Shared.Enrollments;
using MagicControl.Web.Data;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Dashboard;

public sealed record DashboardSummary(
    int Users,
    int PendingApplications,
    int PendingMeshApis,
    int ManagedApplications,
    int ManagedMeshApis);

public sealed class DashboardService(IDbContextFactory<MagicControlDbContext> dbFactory)
{
    public async ValueTask<DashboardSummary> GetAsync(
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        return new(
            await db.Users.CountAsync(cancellationToken),
            await db.EnrollmentRequests.CountAsync(
                x => x.Status == EnrollmentRequestStatus.Pending
                     && x.Kind == EnrollmentKind.ApplicationInstance,
                cancellationToken),
            await db.EnrollmentRequests.CountAsync(
                x => x.Status == EnrollmentRequestStatus.Pending
                     && x.Kind == EnrollmentKind.MeshApi,
                cancellationToken),
            await db.ManagedInstances.CountAsync(
                x => x.Kind == EnrollmentKind.ApplicationInstance,
                cancellationToken),
            await db.ManagedInstances.CountAsync(
                x => x.Kind == EnrollmentKind.MeshApi,
                cancellationToken));
    }
}
