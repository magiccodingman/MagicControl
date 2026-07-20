using MagicControl.Shared.Enrollments;
using MagicControl.Web.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Enrollments;

public sealed partial class EnrollmentService
{
    public async ValueTask<IReadOnlyList<EnrollmentRequestSummary>> GetRequestsAsync(
        EnrollmentRequestStatus? status = null,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.EnrollmentRequests.AsNoTracking();

        if (status is not null)
        {
            query = query.Where(x => x.Status == status);
        }

        // SQLite can persist DateTimeOffset values but cannot translate ordering by them.
        // Keep filtering in the database and perform the final presentation ordering in memory.
        var rows = await query.ToListAsync(cancellationToken);

        return rows
            .OrderByDescending(x => x.Status == EnrollmentRequestStatus.Pending)
            .ThenByDescending(x => x.LastSeenUtc)
            .Select(ToSummary)
            .ToArray();
    }

    public async ValueTask<IReadOnlyList<ManagedInstanceSummary>> GetManagedInstancesAsync(
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.ManagedInstances
            .AsNoTracking()
            .Include(x => x.Group)
            .OrderBy(x => x.Kind)
            .ThenBy(x => x.DisplayName)
            .Select(x => new ManagedInstanceSummary(
                x.Id,
                x.Kind,
                x.Status,
                x.DisplayName,
                x.ApplicationName,
                x.Group == null ? null : x.Group.Name,
                x.InstanceName,
                x.InstanceRole,
                x.SiteName,
                x.AdvertisedEndpoint,
                x.Version,
                x.CreatedUtc,
                x.LastSeenUtc))
            .ToListAsync(cancellationToken);
    }

    public async ValueTask<ManagedInstanceDetail?> GetManagedInstanceAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var instance = await db.ManagedInstances
            .AsNoTracking()
            .Include(x => x.Group)
            .Include(x => x.Credentials)
            .SingleOrDefaultAsync(x => x.Id == id, cancellationToken);

        if (instance is null)
        {
            return null;
        }

        return new(
            new ManagedInstanceSummary(
                instance.Id,
                instance.Kind,
                instance.Status,
                instance.DisplayName,
                instance.ApplicationName,
                instance.Group?.Name,
                instance.InstanceName,
                instance.InstanceRole,
                instance.SiteName,
                instance.AdvertisedEndpoint,
                instance.Version,
                instance.CreatedUtc,
                instance.LastSeenUtc),
            instance.Credentials
                .OrderByDescending(x => x.UpdatedUtc)
                .Select(x => new ManagedCredentialSummary(
                    x.NodeId,
                    x.CredentialId,
                    x.Fingerprint,
                    x.Status,
                    x.CreatedUtc,
                    x.UpdatedUtc))
                .ToArray());
    }

    private static EnrollmentRequestSummary ToSummary(EnrollmentRequestEntity x)
        => new(
            x.Id,
            x.Kind,
            x.Status,
            x.NodeId,
            x.CredentialId,
            x.DisplayName,
            x.ApplicationName,
            x.GroupName,
            x.InstanceName,
            x.InstanceRole,
            x.SiteName,
            x.Version,
            x.AdvertisedEndpoint,
            x.Fingerprint,
            x.FirstSeenUtc,
            x.LastSeenUtc,
            x.ReviewedUtc,
            x.DecisionReason);
}
