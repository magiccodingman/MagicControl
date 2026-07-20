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
            // MagicSettings overrides are node-specific and are delivered through node sync,
            // never through the group-wide authorization manifest.
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
        var endpoints = ReadEndpoints(instance);
        if (endpoints.Count == 0)
        {
            return null;
        }

        var lastSeen = instance.LastSeenUtc ?? instance.ApprovedUtc;
        return new MagicControlDirectoryEntry(
            instance.Id,
            instance.ApplicationName,
            instance.InstanceName,
            instance.InstanceRole,
            instance.SiteName,
            endpoints,
            instance.DirectorySequence > 0
                ? instance.DirectorySequence
                : lastSeen.ToUnixTimeMilliseconds(),
            lastSeen,
            lastSeen.AddSeconds(90));
    }

    private static IReadOnlyList<MagicControlServiceEndpoint> ReadEndpoints(
        ManagedInstance instance)
    {
        try
        {
            var announcements = JsonSerializer.Deserialize<
                IReadOnlyList<MagicControlServiceEndpointAnnouncement>>(
                instance.EndpointsJson,
                JsonOptions);
            if (announcements is { Count: > 0 })
            {
                return announcements
                    .Where(candidate => candidate.Uri.IsAbsoluteUri)
                    .Select(candidate => new MagicControlServiceEndpoint(
                        candidate.Uri,
                        candidate.Priority,
                        candidate.IsLoopback || candidate.Uri.IsLoopback,
                        candidate.IsLan,
                        candidate.Transport))
                    .OrderBy(candidate => candidate.Priority)
                    .ThenByDescending(candidate => candidate.IsLoopback)
                    .ThenByDescending(candidate => candidate.IsLan)
                    .ToArray();
            }
        }
        catch (JsonException)
        {
        }

        if (string.IsNullOrWhiteSpace(instance.AdvertisedEndpoint)
            || !Uri.TryCreate(instance.AdvertisedEndpoint, UriKind.Absolute, out var fallback))
        {
            return [];
        }

        return [new MagicControlServiceEndpoint(
            fallback,
            Priority: fallback.IsLoopback ? 0 : 100,
            IsLoopback: fallback.IsLoopback,
            IsLan: IsPrivateAddress(fallback.Host),
            Transport: fallback.Scheme)];
    }

    private static bool IsPrivateAddress(string host)
    {
        if (!System.Net.IPAddress.TryParse(host, out var address)
            || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 10
               || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
               || (bytes[0] == 192 && bytes[1] == 168);
    }
}
