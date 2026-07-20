using System.Security.Cryptography;
using System.Text;
using MagicSettings.Share;

namespace MagicControl.Shared.Mesh;

public enum MagicControlEnrollmentState
{
    LocalOnly = 0,
    PendingApproval = 1,
    Approved = 2,
    Rejected = 3,
    Faulted = 4
}

public sealed record MagicControlMeshAdvertisement(
    Guid GatewayId,
    Guid MeshNodeId,
    Uri Endpoint,
    string? AuthorityKeyId,
    DateTimeOffset IssuedUtc,
    int TimeToLiveSeconds = 20);

public sealed record MagicControlServiceEndpointAnnouncement(
    Uri Uri,
    int Priority = 100,
    bool IsLoopback = false,
    bool IsLan = false,
    string Transport = "https");

public sealed record MagicControlNodeSyncRequest(
    Guid GroupId,
    string ApplicationName,
    string DisplayName,
    string? InstanceName,
    string? InstanceRole,
    string? SiteName,
    string? Version,
    string BootstrapNonce,
    string ContextHash,
    IReadOnlyList<string> RequestedCapabilities,
    IReadOnlyList<MagicControlServiceEndpointAnnouncement> Endpoints,
    MagicSettingsSyncRequest Settings);

public sealed record MagicControlNodeSyncResponse(
    MagicControlEnrollmentState EnrollmentState,
    MagicSettingsSyncResponse Settings,
    MagicRemoteSnapshot OfflineSnapshot,
    SignedMagicControlGroupManifest? Manifest,
    string BootstrapNonce,
    IReadOnlyList<Uri> MeshEndpoints,
    string? PairingCode = null,
    string? Message = null,
    TimeSpan? SuggestedPollInterval = null);

public sealed record MagicControlNodeSecretRequest(
    Guid GroupId,
    string ApplicationName,
    string ContextHash,
    MagicSecretRequest Secret);

public static class MagicControlNodeContext
{
    public static string Compute(
        Guid groupId,
        string applicationName,
        string displayName,
        string? instanceName,
        string? instanceRole,
        string? siteName,
        string? version,
        string bootstrapNonce,
        IEnumerable<string> requestedCapabilities,
        IEnumerable<MagicControlServiceEndpointAnnouncement> endpoints)
    {
        var canonical = new StringBuilder()
            .AppendLine("MAGICCONTROL-NODE-CONTEXT-V1")
            .AppendLine(groupId.ToString("D"))
            .AppendLine(applicationName.Trim())
            .AppendLine(displayName.Trim())
            .AppendLine(instanceName?.Trim() ?? string.Empty)
            .AppendLine(instanceRole?.Trim() ?? string.Empty)
            .AppendLine(siteName?.Trim() ?? string.Empty)
            .AppendLine(version?.Trim() ?? string.Empty)
            .AppendLine(bootstrapNonce.Trim());

        foreach (var capability in requestedCapabilities
                     .Select(value => value.Trim())
                     .Where(value => value.Length > 0)
                     .Distinct(StringComparer.Ordinal)
                     .OrderBy(value => value, StringComparer.Ordinal))
        {
            canonical.Append("capability:").AppendLine(capability);
        }

        foreach (var endpoint in endpoints
                     .OrderBy(value => value.Uri.AbsoluteUri, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(value => value.Priority)
                     .ThenBy(value => value.Transport, StringComparer.Ordinal))
        {
            canonical
                .Append("endpoint:")
                .Append(endpoint.Uri.AbsoluteUri)
                .Append('|')
                .Append(endpoint.Priority)
                .Append('|')
                .Append(endpoint.IsLoopback ? '1' : '0')
                .Append('|')
                .Append(endpoint.IsLan ? '1' : '0')
                .Append('|')
                .AppendLine(endpoint.Transport);
        }

        return Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString())))
            .ToLowerInvariant();
    }

    public static string Compute(MagicControlNodeSyncRequest request)
        => Compute(
            request.GroupId,
            request.ApplicationName,
            request.DisplayName,
            request.InstanceName,
            request.InstanceRole,
            request.SiteName,
            request.Version,
            request.BootstrapNonce,
            request.RequestedCapabilities,
            request.Endpoints);
}

public static class MagicControlLogicalUris
{
    public static Uri ControlPlaneBase(Guid groupId, string contextHash)
        => new(
            $"https://magiccontrol.local/groups/{groupId:D}/contexts/{contextHash}/",
            UriKind.Absolute);

    public static Uri SettingsSync(Guid groupId, string contextHash)
        => new(ControlPlaneBase(groupId, contextHash), "magicsettings/sync");

    public static Uri SecretResolve(Guid groupId, string contextHash)
        => new(ControlPlaneBase(groupId, contextHash), "magicsettings/secrets/resolve");
}
