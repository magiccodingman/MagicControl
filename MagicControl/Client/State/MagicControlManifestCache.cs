using MagicControl.Shared.Mesh;

namespace MagicControl.Client;

public sealed record MagicControlManifestState(
    SignedMagicControlGroupManifest Envelope,
    DateTimeOffset LastAuthorityContactUtc,
    bool LoadedFromDisk)
{
    public MagicControlGroupManifest Manifest => Envelope.Manifest;

    public bool AllowsOfflineUse(DateTimeOffset nowUtc)
        => Manifest.OfflineTrust.AllowsOfflineUse(LastAuthorityContactUtc, nowUtc);
}

public interface IMagicControlManifestSource
{
    MagicControlManifestState? Get(Guid groupId);
    IReadOnlyList<MagicControlManifestState> GetAll();
}

public sealed class MagicControlManifestCache : IMagicControlManifestSource
{
    private readonly object _gate = new();
    private readonly Dictionary<Guid, MagicControlManifestState> _groups = [];

    public event EventHandler<MagicControlManifestState>? Changed;

    public MagicControlManifestState? Get(Guid groupId)
    {
        lock (_gate)
        {
            return _groups.GetValueOrDefault(groupId);
        }
    }

    public IReadOnlyList<MagicControlManifestState> GetAll()
    {
        lock (_gate)
        {
            return _groups.Values.ToArray();
        }
    }

    public void Set(MagicControlManifestState state)
    {
        ArgumentNullException.ThrowIfNull(state);

        lock (_gate)
        {
            if (_groups.TryGetValue(state.Manifest.GroupId, out var existing)
                && existing.Manifest.SecurityEpoch == state.Manifest.SecurityEpoch
                && existing.Manifest.Revision > state.Manifest.Revision)
            {
                return;
            }

            _groups[state.Manifest.GroupId] = state;
        }

        Changed?.Invoke(this, state);
    }

    public IReadOnlyList<MagicControlDirectoryEntry> ResolveAll(
        Guid groupId,
        string applicationName,
        DateTimeOffset nowUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationName);
        var state = Get(groupId);
        if (state is null)
        {
            return [];
        }

        return state.Manifest.Directory
            .Where(entry => string.Equals(
                entry.ApplicationName,
                applicationName,
                StringComparison.OrdinalIgnoreCase))
            .Where(entry => entry.ExpiresUtc is null || entry.ExpiresUtc >= nowUtc)
            .OrderBy(entry => entry.Endpoints.Min(endpoint => endpoint.Priority))
            .ThenBy(entry => entry.ManagedInstanceId)
            .ToArray();
    }

    public MagicControlMember? FindMember(Guid nodeId, Guid credentialId)
        => GetAll()
            .SelectMany(state => state.Manifest.Members)
            .FirstOrDefault(member =>
                member.NodeId == nodeId && member.CredentialId == credentialId);
}
