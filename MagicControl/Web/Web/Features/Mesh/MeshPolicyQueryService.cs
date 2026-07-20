using MagicControl.Shared.Mesh;
using MagicControl.Web.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Mesh;

public sealed record GroupMeshPolicySummary(
    Guid Id,
    string Name,
    MagicControlGroupSecurityMode SecurityMode,
    long? MaximumOfflineSeconds,
    long ManifestRevision,
    Guid SecurityEpoch,
    int ActiveInstanceCount);

public sealed partial class MeshManifestService
{
    public async ValueTask<IReadOnlyList<GroupMeshPolicySummary>> GetPoliciesAsync(
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var groups = await db.Groups
            .AsNoTracking()
            .Include(group => group.Instances)
            .OrderBy(group => group.Name)
            .ToListAsync(cancellationToken);

        return groups.Select(group => new GroupMeshPolicySummary(
                group.Id,
                group.Name,
                group.SecurityMode,
                group.OfflineTrustDurationSeconds,
                Math.Max(1, group.ManifestRevision),
                group.SecurityEpoch,
                group.Instances.Count(instance => instance.Status == ManagedInstanceStatus.Active)))
            .ToArray();
    }
}
