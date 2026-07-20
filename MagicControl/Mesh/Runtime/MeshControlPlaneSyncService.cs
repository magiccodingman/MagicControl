using System.Net.Http.Json;
using MagicControl.Shared.Mesh;
using Microsoft.Extensions.Options;

namespace MagicControl.Mesh;

public static class MeshHttpClients
{
    public const string ControlPlane = "MagicControl.Mesh.ControlPlane";
}

public sealed class MeshControlPlaneStatus
{
    private readonly object _gate = new();
    private DateTimeOffset? _lastSuccessUtc;
    private string? _lastError;

    public DateTimeOffset? LastSuccessUtc
    {
        get { lock (_gate) return _lastSuccessUtc; }
    }

    public string? LastError
    {
        get { lock (_gate) return _lastError; }
    }

    internal void Success(DateTimeOffset nowUtc)
    {
        lock (_gate)
        {
            _lastSuccessUtc = nowUtc;
            _lastError = null;
        }
    }

    internal void Failure(string error)
    {
        lock (_gate)
        {
            _lastError = error;
        }
    }
}

public sealed class MeshControlPlaneSyncService(
    IHttpClientFactory httpClientFactory,
    MeshManifestRepository repository,
    IOptionsMonitor<MagicControlMeshSettings> settings,
    MeshControlPlaneStatus status,
    ILogger<MeshControlPlaneSyncService> logger) : BackgroundService
{
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await repository.LoadAsync(cancellationToken);
        await base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RefreshAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                status.Failure(exception.Message);
                logger.LogWarning(
                    exception,
                    "MagicControl Web is unavailable; Mesh is serving last-known-good manifests.");
            }

            var seconds = Math.Max(1, settings.CurrentValue.RefreshIntervalSeconds);
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(seconds), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private async Task RefreshAsync(CancellationToken cancellationToken)
    {
        var client = httpClientFactory.CreateClient(MeshHttpClients.ControlPlane);
        var groups = await client.GetFromJsonAsync<IReadOnlyList<MagicControlGroupDescriptor>>(
                         "api/v1/mesh/groups",
                         cancellationToken)
                     ?? throw new InvalidDataException(
                         "MagicControl Web returned an empty group directory response.");

        var now = DateTimeOffset.UtcNow;
        foreach (var group in groups)
        {
            var manifest = await client.GetFromJsonAsync<SignedMagicControlGroupManifest>(
                               $"api/v1/mesh/groups/{group.GroupId:D}/manifest",
                               cancellationToken)
                           ?? throw new InvalidDataException(
                               $"MagicControl Web returned an empty manifest for {group.GroupId:D}.");

            await repository.AcceptAuthoritativeAsync(manifest, now, cancellationToken);
        }

        status.Success(now);
    }
}
