using System.Security.Cryptography;
using MagicControl.Shared.Mesh;

namespace MagicControl.Client;

public sealed record MagicControlPeerObservation(
    SignedMagicControlPeerAdvertisement Envelope,
    DateTimeOffset LastSeenUtc,
    bool LoadedFromDisk)
{
    public MagicControlPeerAdvertisement Advertisement => Envelope.Advertisement;

    public bool IsLive(DateTimeOffset nowUtc)
        => Advertisement.IssuedUtc.AddSeconds(Advertisement.TimeToLiveSeconds) >= nowUtc;
}

public interface IMagicControlPeerDirectoryStore
{
    ValueTask<IReadOnlyList<MagicControlPeerObservation>> LoadAsync(
        CancellationToken cancellationToken = default);

    ValueTask SaveAsync(
        IReadOnlyList<MagicControlPeerObservation> observations,
        CancellationToken cancellationToken = default);
}

public sealed class MagicControlPeerDirectory(MagicControlClientOptions options)
{
    private readonly object _gate = new();
    private readonly Dictionary<string, MagicControlPeerObservation> _observations =
        new(StringComparer.OrdinalIgnoreCase);

    internal bool Accept(
        SignedMagicControlPeerAdvertisement envelope,
        DateTimeOffset receivedUtc,
        bool loadedFromDisk = false)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var advertisement = envelope.Advertisement;
        var key = Key(advertisement);

        lock (_gate)
        {
            if (_observations.TryGetValue(key, out var existing))
            {
                if (!PublicKeysMatch(
                        existing.Advertisement.Identity.PublicKey,
                        advertisement.Identity.PublicKey))
                {
                    return false;
                }

                if (advertisement.Sequence < existing.Advertisement.Sequence
                    || (advertisement.Sequence == existing.Advertisement.Sequence
                        && advertisement.IssuedUtc <= existing.Advertisement.IssuedUtc))
                {
                    return false;
                }
            }

            _observations[key] = new MagicControlPeerObservation(
                envelope,
                receivedUtc,
                loadedFromDisk);
            return true;
        }
    }

    public IReadOnlyList<MagicControlPeerObservation> GetActive(
        DateTimeOffset? nowUtc = null)
    {
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        lock (_gate)
        {
            RemoveExpiredUnderLock(now);
            return _observations.Values
                .OrderByDescending(observation => observation.IsLive(now))
                .ThenByDescending(observation => observation.LastSeenUtc)
                .ToArray();
        }
    }

    internal IReadOnlyList<MagicControlPeerObservation> Snapshot()
    {
        lock (_gate)
        {
            return _observations.Values.ToArray();
        }
    }

    private void RemoveExpiredUnderLock(DateTimeOffset nowUtc)
    {
        foreach (var key in _observations
                     .Where(pair => pair.Value.LastSeenUtc.Add(options.PeerCacheDuration) < nowUtc)
                     .Select(pair => pair.Key)
                     .ToArray())
        {
            _observations.Remove(key);
        }
    }

    private static string Key(MagicControlPeerAdvertisement advertisement)
        => string.Join(
            ':',
            advertisement.GroupId.ToString("D"),
            advertisement.ApplicationName,
            advertisement.Identity.NodeId.ToString("D"),
            advertisement.Identity.CredentialId.ToString("D"));

    private static bool PublicKeysMatch(string expected, string actual)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(expected),
                Convert.FromBase64String(actual));
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
