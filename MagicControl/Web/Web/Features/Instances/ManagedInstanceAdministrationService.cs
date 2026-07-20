using System.Text.Json;
using MagicControl.Web.Data;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Instances;

public sealed record ManagedInstanceCapabilityState(
    Guid InstanceId,
    IReadOnlyList<string> Capabilities);

public sealed class ManagedInstanceAdministrationService(
    IDbContextFactory<MagicControlDbContext> dbFactory)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async ValueTask<ManagedInstanceCapabilityState> GetCapabilitiesAsync(
        Guid instanceId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var instance = await db.ManagedInstances
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == instanceId, cancellationToken)
            ?? throw new KeyNotFoundException("The managed instance was not found.");

        return new ManagedInstanceCapabilityState(
            instance.Id,
            ReadCapabilities(instance.CapabilitiesJson));
    }

    public async ValueTask UpdateCapabilitiesAsync(
        Guid instanceId,
        IEnumerable<string> capabilities,
        Guid actorUserId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(capabilities);
        var normalized = capabilities
            .Select(value => value.Trim())
            .Where(value => value.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var instance = await db.ManagedInstances
            .Include(candidate => candidate.Group)
            .SingleOrDefaultAsync(candidate => candidate.Id == instanceId, cancellationToken)
            ?? throw new KeyNotFoundException("The managed instance was not found.");

        var current = ReadCapabilities(instance.CapabilitiesJson);
        if (current.SequenceEqual(normalized, StringComparer.Ordinal))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        instance.CapabilitiesJson = JsonSerializer.Serialize(
            normalized.ToDictionary(value => value, _ => "approved", StringComparer.Ordinal),
            JsonOptions);
        if (instance.Group is not null)
        {
            instance.Group.ManifestRevision = checked(
                Math.Max(1, instance.Group.ManifestRevision) + 1);
            instance.Group.UpdatedUtc = now;
        }

        db.AuditEvents.Add(new Data.Entities.AuditEvent
        {
            OccurredUtc = now,
            ActorType = "user",
            ActorId = actorUserId.ToString("D"),
            Action = "managed-instance.capabilities.changed",
            TargetType = "managed-instance",
            TargetId = instance.Id.ToString("D"),
            MetadataJson = JsonSerializer.Serialize(new
            {
                Previous = current,
                Current = normalized,
                ManifestRevision = instance.Group?.ManifestRevision
            }, JsonOptions)
        });

        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private static IReadOnlyList<string> ReadCapabilities(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, string>>(json, JsonOptions)
                       ?.Keys
                       .OrderBy(value => value, StringComparer.Ordinal)
                       .ToArray()
                   ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
