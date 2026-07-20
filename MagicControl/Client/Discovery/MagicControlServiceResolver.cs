using MagicControl.Shared.Mesh;

namespace MagicControl.Client;

public sealed record MagicControlResolvedService(
    MagicControlDirectoryEntry Instance,
    MagicControlServiceEndpoint Endpoint);

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

public sealed class MagicControlServiceResolver(
    MagicControlClientOptions options,
    MagicControlManifestCache cache) : IMagicControlServiceResolver
{
    private readonly object _gate = new();
    private readonly Dictionary<string, int> _roundRobin = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _unhealthyUntil = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<MagicControlResolvedService> ResolveAll(
        string applicationName,
        DateTimeOffset? nowUtc = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationName);
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        var state = cache.Get(options.GroupId);
        if (state is null || !state.AllowsOfflineUse(now))
        {
            return [];
        }

        var resolved = state.Manifest.Directory
            .Where(instance => string.Equals(
                instance.ApplicationName,
                applicationName,
                StringComparison.OrdinalIgnoreCase))
            .Where(instance => instance.ExpiresUtc is null || instance.ExpiresUtc >= now)
            .SelectMany(instance => instance.Endpoints.Select(endpoint =>
                new MagicControlResolvedService(instance, endpoint)))
            .Where(candidate => IsHealthy(candidate.Endpoint.Uri, now))
            .OrderBy(candidate => RouteScore(candidate.Endpoint))
            .ThenBy(candidate => candidate.Endpoint.Priority)
            .ThenBy(candidate => candidate.Instance.ManagedInstanceId)
            .ThenBy(candidate => candidate.Endpoint.Uri.AbsoluteUri, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return resolved.Length > 0
            ? resolved
            : state.Manifest.Directory
                .Where(instance => string.Equals(
                    instance.ApplicationName,
                    applicationName,
                    StringComparison.OrdinalIgnoreCase))
                .Where(instance => instance.ExpiresUtc is null || instance.ExpiresUtc >= now)
                .SelectMany(instance => instance.Endpoints.Select(endpoint =>
                    new MagicControlResolvedService(instance, endpoint)))
                .OrderBy(candidate => RouteScore(candidate.Endpoint))
                .ThenBy(candidate => candidate.Endpoint.Priority)
                .ToArray();
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

        if (options.RouteSelection != MagicControlRouteSelectionMode.RoundRobin)
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
