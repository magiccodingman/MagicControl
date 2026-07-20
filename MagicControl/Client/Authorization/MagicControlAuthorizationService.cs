using MagicControl.Shared.Mesh;
using MagicSettings.Server;

namespace MagicControl.Client;

public sealed record MagicControlAuthorizationDecision(
    bool Allowed,
    string? Reason,
    MagicControlMember? Member,
    IReadOnlyList<Guid> GroupIds)
{
    public static MagicControlAuthorizationDecision Permit(
        MagicControlMember member,
        IReadOnlyList<Guid> groupIds)
        => new(true, null, member, groupIds);

    public static MagicControlAuthorizationDecision Deny(string reason)
        => new(false, reason, null, []);
}

public interface IMagicControlAuthorizationService
{
    MagicControlAuthorizationDecision AuthenticateCredential(
        Guid nodeId,
        Guid credentialId,
        DateTimeOffset? nowUtc = null);

    MagicControlAuthorizationDecision AuthorizeMember(
        Guid groupId,
        Guid nodeId,
        Guid credentialId,
        string? requiredCapability = null,
        DateTimeOffset? nowUtc = null);

    IReadOnlyList<MagicControlDirectoryEntry> ResolveAll(
        Guid groupId,
        string applicationName,
        DateTimeOffset? nowUtc = null);
}

public sealed class MagicControlAuthorizationService(MagicControlManifestCache cache)
    : IMagicControlAuthorizationService
{
    public MagicControlAuthorizationDecision AuthenticateCredential(
        Guid nodeId,
        Guid credentialId,
        DateTimeOffset? nowUtc = null)
    {
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        var matches = cache.GetAll()
            .Where(state => state.AllowsOfflineUse(now))
            .Select(state => new
            {
                state.Manifest.GroupId,
                Member = state.Manifest.Members.FirstOrDefault(candidate =>
                    candidate.NodeId == nodeId && candidate.CredentialId == credentialId)
            })
            .Where(match => match.Member is not null)
            .ToArray();

        if (matches.Length == 0)
        {
            return MagicControlAuthorizationDecision.Deny(
                "The caller does not have an approved credential in any trusted group manifest.");
        }

        return MagicControlAuthorizationDecision.Permit(
            matches[0].Member!,
            matches.Select(match => match.GroupId).Distinct().ToArray());
    }

    public MagicControlAuthorizationDecision AuthorizeMember(
        Guid groupId,
        Guid nodeId,
        Guid credentialId,
        string? requiredCapability = null,
        DateTimeOffset? nowUtc = null)
    {
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        var state = cache.Get(groupId);
        if (state is null)
        {
            return MagicControlAuthorizationDecision.Deny("No trusted group manifest is available.");
        }

        if (!state.AllowsOfflineUse(now))
        {
            return MagicControlAuthorizationDecision.Deny(
                "The group's configured offline trust period has expired.");
        }

        var member = state.Manifest.Members.FirstOrDefault(candidate =>
            candidate.NodeId == nodeId && candidate.CredentialId == credentialId);

        if (member is null)
        {
            return MagicControlAuthorizationDecision.Deny(
                "The caller is not an approved member of this group.");
        }

        if (!string.IsNullOrWhiteSpace(requiredCapability)
            && !member.Capabilities.Contains(requiredCapability, StringComparer.Ordinal))
        {
            return MagicControlAuthorizationDecision.Deny(
                $"The caller does not have the '{requiredCapability}' capability.");
        }

        return MagicControlAuthorizationDecision.Permit(member, [groupId]);
    }

    public IReadOnlyList<MagicControlDirectoryEntry> ResolveAll(
        Guid groupId,
        string applicationName,
        DateTimeOffset? nowUtc = null)
        => cache.ResolveAll(groupId, applicationName, nowUtc ?? DateTimeOffset.UtcNow);
}

public sealed class MagicControlCachedCredentialRegistry(MagicControlManifestCache cache)
    : IMagicCredentialRegistry
{
    public ValueTask<MagicRegisteredCredential?> FindAsync(
        Guid nodeId,
        Guid credentialId,
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var member = cache.GetAll()
            .Where(state => state.AllowsOfflineUse(now))
            .SelectMany(state => state.Manifest.Members)
            .FirstOrDefault(candidate =>
                candidate.NodeId == nodeId && candidate.CredentialId == credentialId);

        return ValueTask.FromResult(member is null
            ? null
            : new MagicRegisteredCredential(
                member.NodeId,
                member.CredentialId,
                member.PublicKey,
                member.CredentialStatus,
                now));
    }

    public ValueTask UpsertAsync(
        MagicRegisteredCredential credential,
        CancellationToken cancellationToken = default)
        => throw new NotSupportedException(
            "MagicControl client credentials are replaced only by signed authority manifests.");
}
