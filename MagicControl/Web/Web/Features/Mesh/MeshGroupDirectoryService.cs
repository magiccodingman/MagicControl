using MagicControl.Shared.Mesh;
using MagicControl.Web.Data;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Mesh;

public sealed class MeshGroupDirectoryService(
    IDbContextFactory<MagicControlDbContext> dbFactory)
{
    public async ValueTask<IReadOnlyList<MagicControlGroupDescriptor>> GetGroupsAsync(
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var groups = await db.Groups
            .AsNoTracking()
            .OrderBy(group => group.Name)
            .ToListAsync(cancellationToken);

        return groups.Select(group => new MagicControlGroupDescriptor(
                group.Id,
                group.Name,
                group.SecurityMode,
                Math.Max(1, group.ManifestRevision),
                group.SecurityEpoch,
                group.OfflineTrustDurationSeconds is null
                    ? MagicControlOfflineTrustPolicy.Infinite
                    : new MagicControlOfflineTrustPolicy
                    {
                        MaximumOfflineSeconds = group.OfflineTrustDurationSeconds
                    }))
            .ToArray();
    }
}
