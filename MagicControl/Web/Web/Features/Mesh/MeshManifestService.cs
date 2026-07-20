using System.Text.Json;
using MagicControl.Shared.Enrollments;
using MagicControl.Shared.Mesh;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using MagicSettings.Share;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Mesh;

public sealed record UpdateGroupMeshPolicyRequest(
    MagicControlGroupSecurityMode SecurityMode,
    long? MaximumOfflineSeconds);

public sealed partial class MeshManifestService(
    IDbContextFactory<MagicControlDbContext> dbFactory,
    MagicControlAuthoritySigningService authority)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async ValueTask<SignedMagicControlGroupManifest> GetSignedManifestAsync(
        Guid groupId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var group = await db.Groups
            .Include(candidate => candidate.Instances)
            .ThenInclude(instance => instance.Credentials)
            .SingleOrDefaultAsync(candidate => candidate.Id == groupId, cancellationToken)
            ?? throw new KeyNotFoundException("The MagicControl group was not found.");

        if (group.SecurityEpoch == Guid.Empty)
        {
            group.SecurityEpoch = Guid.NewGuid();
            group.ManifestRevision = Math.Max(1, group.ManifestRevision);
            group.UpdatedUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
        }

        var now = DateTimeOffset.UtcNow;
        var activeInstances = group.Instances
            .Where(instance => instance.Status == ManagedInstanceStatus.Active)
            .OrderBy(instance => instance.ApplicationName, StringComparer.Ordinal)
            .ThenBy(instance => instance.InstanceName, StringComparer.Ordinal)
            .ThenBy(instance => instance.Id)
            .ToArray();

        var members = activeInstances
            .SelectMany(instance => instance.Credentials
                .Where(credential => credential.Status is
                    MagicCredentialStatus.Approved or MagicCredentialStatus.Retiring)
                .OrderBy(credential => credential.CredentialId)
                .Select(credential => new MagicControlMember(
                    instance.Id,
                    instance.Kind,
                    instance.DisplayName,
                    instance.ApplicationName,
                    instance.InstanceName,
                    instance.InstanceRole,
                    instance.SiteName,
                    credential.NodeId,
                    credential.CredentialId,
                    credential.PublicKey,
                    credential.Status,
                    [],
                    ReadCapabilities(instance.CapabilitiesJson))))
            .ToArray();

        var directory = activeInstances
            .Select(instance => CreateDirectoryEntry(instance, now))
            .Where(entry => entry is not null)
            .Cast<MagicControlDirectoryEntry>()
            .ToArray();

        var manifest = new MagicControlGroupManifest(
            group.Id,
            group.Name,
            group.SecurityMode,
            group.SecurityEpoch,
            Math.Max(1, group.ManifestRevision),
            now,
            group.OfflineTrustDurationSeconds is null
                ? MagicControlOfflineTrustPolicy.Infinite
                : new MagicControlOfflineTrustPolicy
                {
                    MaximumOfflineSeconds = group.OfflineTrustDurationSeconds
                },
            members,
            directory,
            MagicControlSettingsSnapshot.Empty(now));

        return await authority.SignAsync(manifest, cancellationToken);
    }

    public async ValueTask UpdatePolicyAsync(
        Guid groupId,
        UpdateGroupMeshPolicyRequest request,
        Guid actorUserId,
        CancellationToken cancellationToken = default)
    {
        if (request.MaximumOfflineSeconds is <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request),
                "MaximumOfflineSeconds must be null for infinite trust or greater than zero.");
        }

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var group = await db.Groups.SingleOrDefaultAsync(
                        candidate => candidate.Id == groupId,
                        cancellationToken)
                    ?? throw new KeyNotFoundException("The MagicControl group was not found.");

        var modeChanged = group.SecurityMode != request.SecurityMode;
        group.SecurityMode = request.SecurityMode;
        group.AllowOpenLocalMembers = request.SecurityMode == MagicControlGroupSecurityMode.Open;
        group.OfflineTrustDurationSeconds = request.MaximumOfflineSeconds;
        group.ManifestRevision = checked(Math.Max(1, group.ManifestRevision) + 1);
        group.UpdatedUtc = DateTimeOffset.UtcNow;

        if (modeChanged || group.SecurityEpoch == Guid.Empty)
        {
            group.SecurityEpoch = Guid.NewGuid();
        }

        db.AuditEvents.Add(new AuditEvent
        {
            OccurredUtc = group.UpdatedUtc,
            ActorType = "user",
            ActorId = actorUserId.ToString("D"),
            Action = "group.mesh-policy.changed",
            TargetType = "group",
            TargetId = group.Id.ToString("D"),
            MetadataJson = JsonSerializer.Serialize(new
            {
                SecurityMode = group.SecurityMode.ToString(),
                group.OfflineTrustDurationSeconds,
                group.SecurityEpoch,
                group.ManifestRevision
            }, JsonOptions)
        });

        await db.SaveChangesAsync(cancellationToken);
    }

    private static IReadOnlyList<string> ReadCapabilities(string json)
    {
        try
        {
            var values = JsonSerializer.Deserialize<Dictionary<string, string>>(json, JsonOptions);
            return values?.Keys.OrderBy(key => key, StringComparer.Ordinal).ToArray() ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static MagicControlDirectoryEntry? CreateDirectoryEntry(
        ManagedInstance instance,
        DateTimeOffset observedUtc)
    {
        if (string.IsNullOrWhiteSpace(instance.AdvertisedEndpoint)
            || !Uri.TryCreate(instance.AdvertisedEndpoint, UriKind.Absolute, out var endpoint))
        {
            return null;
        }

        var isLoopback = endpoint.IsLoopback;
        return new MagicControlDirectoryEntry(
            instance.Id,
            instance.ApplicationName,
            instance.InstanceName,
            instance.InstanceRole,
            instance.SiteName,
            [new MagicControlServiceEndpoint(
                endpoint,
                Priority: isLoopback ? 0 : 100,
                IsLoopback: isLoopback,
                IsLan: false,
                Transport: endpoint.Scheme)],
            instance.LastSeenUtc?.ToUnixTimeMilliseconds()
                ?? instance.ApprovedUtc.ToUnixTimeMilliseconds(),
            observedUtc,
            ExpiresUtc: null);
    }
}
