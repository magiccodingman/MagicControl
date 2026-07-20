using System.Net.Http.Json;
using MagicControl.Shared.Mesh;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MagicControl.Client;

public interface IMagicControlMeshEndpointResolver
{
    ValueTask<IReadOnlyList<Uri>> ResolveAsync(CancellationToken cancellationToken = default);
}

public sealed class ConfiguredMagicControlMeshEndpointResolver(MagicControlClientOptions options)
    : IMagicControlMeshEndpointResolver
{
    public ValueTask<IReadOnlyList<Uri>> ResolveAsync(
        CancellationToken cancellationToken = default)
        => ValueTask.FromResult<IReadOnlyList<Uri>>(options.MeshEndpoints.ToArray());
}

public sealed class MagicControlClientStatus
{
    private readonly object _gate = new();
    private DateTimeOffset? _lastRefreshUtc;
    private string? _lastError;
    private Uri? _activeMeshEndpoint;

    public DateTimeOffset? LastRefreshUtc
    {
        get { lock (_gate) return _lastRefreshUtc; }
    }

    public string? LastError
    {
        get { lock (_gate) return _lastError; }
    }

    public Uri? ActiveMeshEndpoint
    {
        get { lock (_gate) return _activeMeshEndpoint; }
    }

    internal void RecordSuccess(Uri endpoint, DateTimeOffset nowUtc)
    {
        lock (_gate)
        {
            _activeMeshEndpoint = endpoint;
            _lastRefreshUtc = nowUtc;
            _lastError = null;
        }
    }

    internal void RecordFailure(string error)
    {
        lock (_gate)
        {
            _lastError = error;
        }
    }
}

public sealed class MagicControlClientHostedService(
    MagicControlClientOptions options,
    IMagicControlManifestStore store,
    MagicControlManifestValidator validator,
    MagicControlManifestCache cache,
    IMagicControlMeshEndpointResolver endpointResolver,
    IHttpClientFactory httpClientFactory,
    MagicControlClientStatus status,
    ILogger<MagicControlClientHostedService> logger) : BackgroundService
{
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        var stored = await store.LoadAsync(cancellationToken);
        if (stored is not null)
        {
            var validation = await validator.ValidateAsync(
                stored,
                offline: true,
                DateTimeOffset.UtcNow,
                cancellationToken);

            if (validation.IsValid)
            {
                cache.Set(new MagicControlManifestState(
                    stored.Envelope,
                    stored.LastAuthorityContactUtc,
                    LoadedFromDisk: true));
            }
            else
            {
                logger.LogWarning(
                    "The cached MagicControl manifest was ignored: {Reason}",
                    validation.Error);
            }
        }

        if (options.StartupMode is MagicControlStartupMode.PreferMesh or MagicControlStartupMode.RequireMesh)
        {
            var refreshed = await TryRefreshAsync(cancellationToken);
            if (!refreshed && options.StartupMode == MagicControlStartupMode.RequireMesh)
            {
                throw new InvalidOperationException(
                    status.LastError ?? "MagicControl Mesh was required during startup but could not be reached.");
            }
        }

        await base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await TryRefreshAsync(stoppingToken);
                await Task.Delay(options.RefreshInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private async Task<bool> TryRefreshAsync(CancellationToken cancellationToken)
    {
        var endpoints = await endpointResolver.ResolveAsync(cancellationToken);
        if (endpoints.Count == 0)
        {
            status.RecordFailure("No MagicControl Mesh endpoint is currently known.");
            return false;
        }

        var client = httpClientFactory.CreateClient(MagicControlHttpClients.Mesh);
        client.Timeout = options.MeshRequestTimeout;
        Exception? lastException = null;

        foreach (var endpoint in endpoints)
        {
            try
            {
                var requestUri = new Uri(
                    EnsureTrailingSlash(endpoint),
                    $"api/v1/groups/{options.GroupId:D}/manifest");
                var envelope = await client.GetFromJsonAsync<SignedMagicControlGroupManifest>(
                    requestUri,
                    cancellationToken);

                if (envelope is null)
                {
                    throw new InvalidDataException("The Mesh API returned an empty group manifest.");
                }

                var now = DateTimeOffset.UtcNow;
                var stored = new StoredMagicControlManifest(envelope, now);
                var validation = await validator.ValidateAsync(
                    stored,
                    offline: false,
                    now,
                    cancellationToken);

                if (!validation.IsValid)
                {
                    throw new InvalidDataException(
                        validation.Error ?? "The Mesh API returned an invalid group manifest.");
                }

                await store.SaveAsync(stored, cancellationToken);
                cache.Set(new MagicControlManifestState(envelope, now, LoadedFromDisk: false));
                status.RecordSuccess(endpoint, now);
                return true;
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                lastException = exception;
                logger.LogDebug(
                    exception,
                    "MagicControl Mesh refresh failed through {Endpoint}.",
                    endpoint);
            }
        }

        var error = lastException?.Message ?? "Every known MagicControl Mesh endpoint failed.";
        status.RecordFailure(error);
        logger.LogWarning("MagicControl is continuing with last-known-good state: {Reason}", error);
        return false;
    }

    private static Uri EnsureTrailingSlash(Uri endpoint)
        => endpoint.AbsoluteUri.EndsWith("/", StringComparison.Ordinal)
            ? endpoint
            : new Uri(endpoint.AbsoluteUri + "/", UriKind.Absolute);
}

public static class MagicControlHttpClients
{
    public const string Mesh = "MagicControl.Mesh";
}
