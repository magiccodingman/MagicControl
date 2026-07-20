using System.Security.Cryptography;
using System.Text;
using MagicControl.Shared.Mesh;
using MagicSettings.Share;

namespace MagicControl.Client;

public enum MagicControlPeerTrustLevel
{
    IdentityVerified = 1,
    AuthorityDirectory = 2,
    AuthorityApproved = 3
}

public enum MagicControlServiceDiscoverySource
{
    DirectPeerCache = 1,
    DirectPeerLan = 2,
    SignedDirectory = 3
}

public sealed record MagicControlResolvedService(
    MagicControlDirectoryEntry Instance,
    MagicControlServiceEndpoint Endpoint)
{
    public MagicControlPeerTrustLevel TrustLevel { get; init; } =
        MagicControlPeerTrustLevel.AuthorityDirectory;

    public MagicControlServiceDiscoverySource Source { get; init; } =
        MagicControlServiceDiscoverySource.SignedDirectory;

    public bool IsAuthorityApproved =>
        TrustLevel == MagicControlPeerTrustLevel.AuthorityApproved;
}

public interface IMagicControlServiceResolver
{
    IReadOnlyList<MagicControlResolvedService> ResolveAll(
        string applicationName,
        DateTimeOffset? nowUtc = null);

    MagicControlResolvedService? Resolve(
        string applicationName,
        DateTimeOffset? nowUtc = null);

    void ReportSuccess(Uri endpoint);
    void ReportFailure(Uri endpoint, TimeSpan? retryAfter = null);
}

public sealed class MagicControlServiceResolver : IMagicControlServiceResolver
{
    private readonly MagicControlClientOptions _options;
    private readonly MagicControlManifestCache _cache;
    private readonly MagicControlPeerDirectory _peers;
    private readonly object _gate = new();
    private readonly Dictionary<string, int> _roundRobin = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _unhealthyUntil = new(StringComparer.OrdinalIgnoreCase);

    public MagicControlServiceResolver(
        MagicControlClientOptions options,
        MagicControlManifestCache cache)
        : this(options, cache, new MagicControlPeerDirectory(options))
    {
    }

    public MagicControlServiceResolver(
        MagicControlClientOptions options,
        MagicControlManifestCache cache,
        MagicControlPeerDirectory peers)
    {
        _options = options;
        _cache = cache;
        _peers = peers;
    }

    public IReadOnlyList<MagicControlResolvedService> ResolveAll(
        string applicationName,
        DateTimeOffset? nowUtc = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationName);
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        var state = _cache.Get(_options.GroupId);
        var usableManifest = state is not null && state.AllowsOfflineUse(now)
            ? state.Manifest
            : null;

        var all = new List<MagicControlResolvedService>();
        if (usableManifest is not null)
        {
            all.AddRange(FromSignedDirectory(usableManifest, applicationName, now));
        }

        if (usableManifest is not null || _options.AllowIdentityVerifiedPeersWithoutAuthority)
        {
            all.AddRange(FromDirectPeers(usableManifest, applicationName, now));
        }

        var deduplicated = all
            .GroupBy(
                candidate => $"{candidate.Instance.ManagedInstanceId:D}|{candidate.Endpoint.Uri.AbsoluteUri.TrimEnd('/')}",
                StringComparer.OrdinalIgnoreCase)
            .Select(group => group
                .OrderByDescending(candidate => candidate.TrustLevel)
                .ThenBy(candidate => SourceScore(candidate.Source))
                .First())
            .ToArray();

        var healthy = Order(
                deduplicated.Where(candidate => IsHealthy(candidate.Endpoint.Uri, now)))
            .ToArray();
        return healthy.Length > 0
            ? healthy
            : Order(deduplicated).ToArray();
    }

    public MagicControlResolvedService? Resolve(
        string applicationName,
        DateTimeOffset? nowUtc = null)
    {
        var candidates = ResolveAll(applicationName, nowUtc);
        if (candidates.Count == 0)
        {
            return null;
        }

        if (_options.RouteSelection != MagicControlRouteSelectionMode.RoundRobin)
        {
            return candidates[0];
        }

        lock (_gate)
        {
            var index = _roundRobin.GetValueOrDefault(applicationName);
            var selected = candidates[index % candidates.Count];
            _roundRobin[applicationName] = unchecked(index + 1);
            return selected;
        }
    }

    public void ReportSuccess(Uri endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        lock (_gate)
        {
            _unhealthyUntil.Remove(endpoint.AbsoluteUri);
        }
    }

    public void ReportFailure(Uri endpoint, TimeSpan? retryAfter = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        lock (_gate)
        {
            _unhealthyUntil[endpoint.AbsoluteUri] = DateTimeOffset.UtcNow.Add(
                retryAfter ?? TimeSpan.FromSeconds(15));
        }
    }

    private IEnumerable<MagicControlResolvedService> FromSignedDirectory(
        MagicControlGroupManifest manifest,
        string applicationName,
        DateTimeOffset nowUtc)
        => manifest.Directory
            .Where(instance => string.Equals(
                instance.ApplicationName,
                applicationName,
                StringComparison.OrdinalIgnoreCase))
            .Where(instance => instance.ExpiresUtc is null || instance.ExpiresUtc >= nowUtc)
            .SelectMany(instance => instance.Endpoints.Select(endpoint =>
                new MagicControlResolvedService(instance, endpoint)
                {
                    TrustLevel = manifest.SecurityMode == MagicControlGroupSecurityMode.Secured
                        ? MagicControlPeerTrustLevel.AuthorityApproved
                        : MagicControlPeerTrustLevel.AuthorityDirectory,
                    Source = MagicControlServiceDiscoverySource.SignedDirectory
                }));

    private IEnumerable<MagicControlResolvedService> FromDirectPeers(
        MagicControlGroupManifest? manifest,
        string applicationName,
        DateTimeOffset nowUtc)
    {
        foreach (var observation in _peers.GetActive(nowUtc))
        {
            var advertisement = observation.Advertisement;
            if (!string.Equals(
                    advertisement.ApplicationName,
                    applicationName,
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            MagicControlMember? member = null;
            if (manifest is not null)
            {
                member = manifest.Members.SingleOrDefault(candidate =>
                    candidate.NodeId == advertisement.Identity.NodeId
                    && candidate.CredentialId == advertisement.Identity.CredentialId
                    && candidate.CredentialStatus is MagicCredentialStatus.Approved or MagicCredentialStatus.Retiring
                    && string.Equals(
                        candidate.ApplicationName,
                        advertisement.ApplicationName,
                        StringComparison.OrdinalIgnoreCase)
                    && PublicKeysMatch(
                        candidate.PublicKey,
                        advertisement.Identity.PublicKey));

                if (manifest.SecurityMode == MagicControlGroupSecurityMode.Secured
                    && member is null)
                {
                    continue;
                }
            }

            var trust = member is not null
                ? MagicControlPeerTrustLevel.AuthorityApproved
                : MagicControlPeerTrustLevel.IdentityVerified;
            var instance = new MagicControlDirectoryEntry(
                member?.ManagedInstanceId ?? DerivePeerId(advertisement),
                advertisement.ApplicationName,
                advertisement.InstanceName,
                advertisement.InstanceRole,
                advertisement.SiteName,
                advertisement.Endpoints
                    .Select(endpoint => new MagicControlServiceEndpoint(
                        endpoint.Uri,
                        endpoint.Priority,
                        endpoint.IsLoopback || endpoint.Uri.IsLoopback,
                        endpoint.IsLan,
                        endpoint.Transport))
                    .ToArray(),
                advertisement.Sequence,
                observation.LastSeenUtc,
                observation.LastSeenUtc.Add(_options.PeerCacheDuration));
            var source = observation.LoadedFromDisk || !observation.IsLive(nowUtc)
                ? MagicControlServiceDiscoverySource.DirectPeerCache
                : MagicControlServiceDiscoverySource.DirectPeerLan;

            foreach (var endpoint in instance.Endpoints)
            {
                yield return new MagicControlResolvedService(instance, endpoint)
                {
                    TrustLevel = trust,
                    Source = source
                };
            }
        }
    }

    private IOrderedEnumerable<MagicControlResolvedService> Order(
        IEnumerable<MagicControlResolvedService> candidates)
        => candidates
            .OrderBy(candidate => RouteScore(candidate.Endpoint))
            .ThenBy(candidate => candidate.Endpoint.Priority)
            .ThenByDescending(candidate => candidate.TrustLevel)
            .ThenBy(candidate => SourceScore(candidate.Source))
            .ThenBy(candidate => candidate.Instance.ManagedInstanceId)
            .ThenBy(candidate => candidate.Endpoint.Uri.AbsoluteUri, StringComparer.OrdinalIgnoreCase);

    private bool IsHealthy(Uri endpoint, DateTimeOffset now)
    {
        lock (_gate)
        {
            return !_unhealthyUntil.TryGetValue(endpoint.AbsoluteUri, out var until)
                   || until <= now;
        }
    }

    private static int RouteScore(MagicControlServiceEndpoint endpoint)
    {
        if (endpoint.IsLoopback || endpoint.Uri.IsLoopback)
        {
            return 0;
        }
        if (endpoint.IsLan)
        {
            return 10;
        }
        if (IsPrivateAddress(endpoint.Uri.Host))
        {
            return 20;
        }
        return 30;
    }

    private static int SourceScore(MagicControlServiceDiscoverySource source)
        => source switch
        {
            MagicControlServiceDiscoverySource.DirectPeerLan => 0,
            MagicControlServiceDiscoverySource.SignedDirectory => 10,
            MagicControlServiceDiscoverySource.DirectPeerCache => 20,
            _ => 30
        };

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

    private static Guid DerivePeerId(MagicControlPeerAdvertisement advertisement)
    {
        var canonical = string.Join(
            ':',
            advertisement.GroupId.ToString("D"),
            advertisement.ApplicationName,
            advertisement.Identity.NodeId.ToString("D"),
            advertisement.Identity.CredentialId.ToString("D"));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return new Guid(hash.AsSpan(0, 16));
    }

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
