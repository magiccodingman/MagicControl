using System.Net.Http.Json;
using MagicControl.Shared.Mesh;
using MagicSettings;
using Microsoft.Extensions.DependencyInjection;
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
        => ValueTask.FromResult<IReadOnlyList<Uri>>(options.MeshEndpointSeeds.ToArray());
}

public sealed class MagicControlClientStatus
{
    private readonly object _gate = new();
    private DateTimeOffset? _lastRefreshUtc;
    private string? _lastError;
    private Uri? _activeMeshEndpoint;
    private MagicControlEnrollmentState _enrollmentState = MagicControlEnrollmentState.LocalOnly;
    private string? _pairingCode;

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

    public MagicControlEnrollmentState EnrollmentState
    {
        get { lock (_gate) return _enrollmentState; }
    }

    public string? PairingCode
    {
        get { lock (_gate) return _pairingCode; }
    }

    public bool IsLocalOnly => EnrollmentState == MagicControlEnrollmentState.LocalOnly;

    internal void RecordSuccess(Uri endpoint, DateTimeOffset nowUtc)
    {
        lock (_gate)
        {
            _activeMeshEndpoint = endpoint;
            _lastRefreshUtc = nowUtc;
            _lastError = null;
            _enrollmentState = MagicControlEnrollmentState.Approved;
            _pairingCode = null;
        }
    }

    internal void RecordEnrollment(
        MagicControlEnrollmentState state,
        string? message,
        string? pairingCode = null,
        Uri? endpoint = null)
    {
        lock (_gate)
        {
            _enrollmentState = state;
            _lastError = message;
            _pairingCode = pairingCode;
            _activeMeshEndpoint = endpoint ?? _activeMeshEndpoint;
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
    IServiceProvider serviceProvider,
    MagicControlClientStatus status,
    MagicControlRuntimeSecurityState securityState,
    ILogger<MagicControlClientHostedService> logger) : BackgroundService
{
    private IMagicSettingsControlPlane? _controlPlane;

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        var cached = await LoadCachedManifestAsync(cancellationToken);
        _controlPlane = serviceProvider.GetService<IMagicSettingsControlPlane>();

        if (options.StartupMode is MagicControlStartupMode.PreferConnected
            or MagicControlStartupMode.RequireApprovedState)
        {
            var connected = _controlPlane is not null
                ? await RefreshControlPlaneAsync(cancellationToken)
                : await TryLegacyManifestRefreshAsync(cancellationToken);

            if (!connected
                && !cached
                && options.StartupMode == MagicControlStartupMode.RequireApprovedState)
            {
                throw new InvalidOperationException(
                    status.LastError
                    ?? "MagicControl approved state was required during startup but is unavailable.");
            }
        }

        await base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_controlPlane is not null)
        {
            // MagicSettings owns polling for the integrated transport. This service only
            // loads the authorization cache and enforces startup policy.
            await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken);
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await TryLegacyManifestRefreshAsync(stoppingToken);
                await Task.Delay(options.RefreshInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private async ValueTask<bool> LoadCachedManifestAsync(CancellationToken cancellationToken)
    {
        var stored = await store.LoadAsync(cancellationToken);
        if (stored is null)
        {
            // A persistent secured latch, if present, intentionally remains active.
            return false;
        }

        var validation = await validator.ValidateAsync(
            stored,
            offline: true,
            DateTimeOffset.UtcNow,
            cancellationToken);
        if (!validation.IsValid)
        {
            logger.LogWarning(
                "The cached MagicControl manifest was ignored: {Reason}",
                validation.Error);
            // Invalid or expired cache never clears a previously secured policy.
            return false;
        }

        // The manifest is already durable at this point. Applying Open may safely clear the latch.
        await securityState.ApplyValidatedManifestAsync(stored.Envelope, cancellationToken);
        cache.Set(new MagicControlManifestState(
            stored.Envelope,
            stored.LastAuthorityContactUtc,
            LoadedFromDisk: true));
        return true;
    }

    private async ValueTask<bool> RefreshControlPlaneAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _controlPlane!.RefreshAsync(cancellationToken);
            return _controlPlane.State == MagicSettings.Share.MagicControlPlaneState.Active;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            status.RecordFailure(exception.Message);
            logger.LogWarning(
                exception,
                "MagicControl could not establish connected state during startup; cached or local-only settings remain active.");
            return false;
        }
    }

    private async Task<bool> TryLegacyManifestRefreshAsync(CancellationToken cancellationToken)
    {
        var endpoints = await endpointResolver.ResolveAsync(cancellationToken);
        if (endpoints.Count == 0)
        {
            status.RecordEnrollment(
                MagicControlEnrollmentState.LocalOnly,
                "No MagicControl Mesh endpoint is currently known.");
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

                if (envelope.Manifest.SecurityMode == MagicControlGroupSecurityMode.Secured)
                {
                    await securityState.ApplyValidatedManifestAsync(envelope, cancellationToken);
                    await store.SaveAsync(stored, cancellationToken);
                }
                else
                {
                    await store.SaveAsync(stored, cancellationToken);
                    await securityState.ApplyValidatedManifestAsync(envelope, cancellationToken);
                }

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
