using System.Text.Json;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Common;

public sealed class AuditService(IDbContextFactory<MagicControlDbContext> dbFactory)
{
    public async ValueTask WriteAsync(
        string action,
        string targetType,
        string? targetId,
        string? actorType,
        string? actorId,
        object? metadata = null,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        db.AuditEvents.Add(new AuditEvent
        {
            OccurredUtc = DateTimeOffset.UtcNow,
            ActorType = actorType,
            ActorId = actorId,
            Action = action,
            TargetType = targetType,
            TargetId = targetId,
            MetadataJson = metadata is null ? "{}" : JsonSerializer.Serialize(metadata)
        });
        await db.SaveChangesAsync(cancellationToken);
    }
}
