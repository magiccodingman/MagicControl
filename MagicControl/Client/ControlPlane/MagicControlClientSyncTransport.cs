using System.Net.Http.Json;
using MagicControl.Shared.Mesh;
using MagicSettings;
using MagicSettings.Share;

namespace MagicControl.Client;

public sealed class MagicControlClientSyncTransport :
    IMagicControlPlaneTransport,
    IMagicSecretTransport,
    IDisposable
{
    private readonly MagicControlClientOptions _options;
    private readonly IMagicControlMeshEndpointResolver _endpointResolver;
    private readonly IMagicControlClientStateStore _stateStore;
    private readonly IMagicControlManifestStore _manifestStore;
    private readonly MagicControlManifestValidator _manifestValidator;
    private readonly MagicControlManifestCache _manifestCache;
    private readonly MagicControlClientStatus _status;
    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public MagicControlClientSyncTransport(
        MagicControlClientOptions options,
        IMagicControlMeshEndpointResolver endpointResolver,
        IMagicControlClientStateStore stateStore,
        IMagicControlManifestStore manifestStore,
        MagicControlManifestValidator manifestValidator,
        MagicControlManifestCache manifestCache,
        MagicControlClientStatus status)
    {
        _options = options;
        _endpointResolver = endpointResolver;
        _stateStore = stateStore;
        _manifestStore = manifestStore;
        _manifestValidator = manifestValidator;
        _manifestCache = manifestCache;
        _status = status;

        _httpClient = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = System.Net.DecompressionMethods.All
        });
    }

    public async ValueTask<MagicSettingsSyncResponse> SynchronizeAsync(
        Uri endpoint,
        MagicControlPlaneTrust trust,
        MagicSettingsSyncRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var state = await _stateStore.LoadAsync(cancellationToken);
            var endpoints = await _endpointResolver.ResolveAsync(cancellationToken);
            if (endpoints.Count == 0)
            {
                return await CreateOfflineResponseAsync(
                    state,
                    "No MagicControl Mesh endpoint was discovered. Local MagicSettings remains active.",
                    cancellationToken);
            }

            Exception? lastException = null;
            foreach (var meshEndpoint in endpoints)
            {
                try
                {
                    var response = await SynchronizeThroughAsync(
                        meshEndpoint,
                        state,
                        request,
                        cancellationToken);
                    return response;
                }
                catch (Exception exception) when (
                    exception is not OperationCanceledException
                    || !cancellationToken.IsCancellationRequested)
                {
                    lastException = exception;
                }
            }

            return await CreateOfflineResponseAsync(
                state,
                lastException?.Message ?? "Every discovered MagicControl Mesh endpoint failed.",
                cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<MagicSecretResponse> ResolveSecretAsync(
        Uri endpoint,
        MagicControlPlaneTrust trust,
        MagicSecretRequest request,
        CancellationToken cancellationToken = default)
    {
        var endpoints = await _endpointResolver.ResolveAsync(cancellationToken);
        Exception? lastException = null;

        foreach (var meshEndpoint in endpoints)
        {
            try
            {
                var uri = new Uri(EnsureTrailingSlash(meshEndpoint), "api/v1/nodes/secrets");
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(_options.MeshRequestTimeout);
                using var response = await _httpClient.PostAsJsonAsync(
                    uri,
                    new MagicControlNodeSecretRequest(
                        _options.GroupId,
                        _options.ApplicationName,
                        request),
                    timeout.Token);

                if (!response.IsSuccessStatusCode)
                {
                    throw new HttpRequestException(
                        $"MagicControl secret resolution failed with HTTP {(int)response.StatusCode}.");
                }

                return await response.Content.ReadFromJsonAsync<MagicSecretResponse>(
                           cancellationToken: timeout.Token)
                       ?? throw new InvalidDataException(
                           "MagicControl returned an empty secret response.");
            }
            catch (Exception exception) when (
                exception is not OperationCanceledException
                || !cancellationToken.IsCancellationRequested)
            {
                lastException = exception;
            }
        }

        throw new InvalidOperationException(
            lastException?.Message ?? "No MagicControl Mesh endpoint is available for secret resolution.",
            lastException);
    }

    private async ValueTask<MagicSettingsSyncResponse> SynchronizeThroughAsync(
        Uri meshEndpoint,
        MagicControlClientPersistentState state,
        MagicSettingsSyncRequest settingsRequest,
        CancellationToken cancellationToken)
    {
        var uri = new Uri(EnsureTrailingSlash(meshEndpoint), "api/v1/nodes/sync");
        var request = new MagicControlNodeSyncRequest(
            _options.GroupId,
            _options.ApplicationName,
            _options.DisplayName!,
            _options.InstanceName,
            _options.InstanceRole,
            _options.SiteName,
            _options.Version,
            state.BootstrapNonce,
            _options.RequestedCapabilities.ToArray(),
            _options.AdvertisedEndpoints.ToArray(),
            settingsRequest);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.MeshRequestTimeout);
        using var httpResponse = await _httpClient.PostAsJsonAsync(uri, request, timeout.Token);
        if (!httpResponse.IsSuccessStatusCode)
        {
            var detail = await httpResponse.Content.ReadAsStringAsync(timeout.Token);
            throw new HttpRequestException(
                $"MagicControl node synchronization failed with HTTP {(int)httpResponse.StatusCode}: {detail}");
        }

        var response = await httpResponse.Content.ReadFromJsonAsync<MagicControlNodeSyncResponse>(
                           cancellationToken: timeout.Token)
                       ?? throw new InvalidDataException(
                           "MagicControl returned an empty node synchronization response.");

        if (!string.Equals(
                response.BootstrapNonce,
                state.BootstrapNonce,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The MagicControl bootstrap response was not bound to this client's enrollment nonce.");
        }

        var knownEndpoints = response.MeshEndpoints
            .Append(meshEndpoint)
            .Where(_options.IsEndpointAllowed)
            .DistinctBy(candidate => candidate.AbsoluteUri.TrimEnd('/'), StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var authority = state.AuthorityPublicKey;
        if (response.EnrollmentState == MagicControlEnrollmentState.Approved)
        {
            var manifest = response.Manifest
                           ?? throw new InvalidDataException(
                               "An approved MagicControl response did not include the initial signed manifest.");
            ValidateApprovedManifest(manifest, settingsRequest.Identity, authority);

            authority ??= manifest.AuthorityPublicKey;
            _options.TrustedAuthorityPublicKey ??= authority;

            var stored = new StoredMagicControlManifest(manifest, DateTimeOffset.UtcNow);
            var validation = await _manifestValidator.ValidateAsync(
                stored,
                offline: false,
                DateTimeOffset.UtcNow,
                cancellationToken);
            if (!validation.IsValid)
            {
                throw new InvalidDataException(
                    validation.Error ?? "MagicControl returned an invalid signed manifest.");
            }

            await _manifestStore.SaveAsync(stored, cancellationToken);
            _manifestCache.Set(new MagicControlManifestState(
                manifest,
                DateTimeOffset.UtcNow,
                LoadedFromDisk: false));
        }

        var updatedState = state with
        {
            AuthorityPublicKey = authority,
            MeshEndpoints = knownEndpoints,
            OfflineSnapshot = response.OfflineSnapshot,
            UpdatedUtc = DateTimeOffset.UtcNow
        };
        await _stateStore.SaveAsync(updatedState, cancellationToken);

        if (response.EnrollmentState == MagicControlEnrollmentState.Approved)
        {
            _status.RecordSuccess(meshEndpoint, DateTimeOffset.UtcNow);
            return response.Settings with
            {
                State = MagicControlPlaneState.Active,
                Snapshot = response.Settings.Snapshot
            };
        }

        if (response.EnrollmentState == MagicControlEnrollmentState.PendingApproval)
        {
            _status.RecordFailure(
                response.Message ?? "This application is waiting for MagicControl approval.");
            return response.Settings with
            {
                State = MagicControlPlaneState.PendingApproval,
                Snapshot = MagicRemoteSnapshot.Empty
            };
        }

        if (response.EnrollmentState == MagicControlEnrollmentState.LocalOnly)
        {
            _status.RecordFailure(
                response.Message ?? "MagicControl is operating in local-only mode.");
            return response.Settings with
            {
                State = MagicControlPlaneState.Disconnected,
                Snapshot = MagicRemoteSnapshot.Empty
            };
        }

        _status.RecordFailure(response.Message ?? "MagicControl synchronization was rejected.");
        return response.Settings with
        {
            State = MagicControlPlaneState.Faulted,
            Snapshot = MagicRemoteSnapshot.Empty
        };
    }

    private async ValueTask<MagicSettingsSyncResponse> CreateOfflineResponseAsync(
        MagicControlClientPersistentState state,
        string reason,
        CancellationToken cancellationToken)
    {
        var stored = await _manifestStore.LoadAsync(cancellationToken);
        if (stored is not null)
        {
            var validation = await _manifestValidator.ValidateAsync(
                stored,
                offline: true,
                DateTimeOffset.UtcNow,
                cancellationToken);
            if (validation.IsValid)
            {
                _manifestCache.Set(new MagicControlManifestState(
                    stored.Envelope,
                    stored.LastAuthorityContactUtc,
                    LoadedFromDisk: true));
                _status.RecordFailure(reason);
                return new MagicSettingsSyncResponse(
                    MagicControlPlaneState.Active,
                    state.OfflineSnapshot,
                    $"{reason} Last-known-good approved state is active.");
            }
        }

        _status.RecordFailure(reason);
        return new MagicSettingsSyncResponse(
            MagicControlPlaneState.Disconnected,
            MagicRemoteSnapshot.Empty,
            reason);
    }

    private void ValidateApprovedManifest(
        SignedMagicControlGroupManifest manifest,
        MagicNodeIdentityDescriptor identity,
        string? pinnedAuthority)
    {
        if (manifest.Manifest.GroupId != _options.GroupId)
        {
            throw new InvalidDataException(
                "The approved MagicControl manifest belongs to a different group.");
        }

        if (!MagicControlManifestCryptography.Verify(manifest))
        {
            throw new InvalidDataException(
                "The approved MagicControl manifest signature is invalid.");
        }

        if (!manifest.Manifest.Members.Any(member =>
                member.NodeId == identity.NodeId
                && member.CredentialId == identity.CredentialId))
        {
            throw new InvalidDataException(
                "The approved MagicControl manifest does not grant membership to this node credential.");
        }

        var expectedAuthority = _options.TrustedAuthorityPublicKey ?? pinnedAuthority;
        if (!string.IsNullOrWhiteSpace(expectedAuthority)
            && !MagicControlManifestCryptography.PublicKeysMatch(
                expectedAuthority,
                manifest.AuthorityPublicKey))
        {
            throw new InvalidDataException(
                "The approved MagicControl response was signed by a different authority than the pinned installation.");
        }
    }

    private static Uri EnsureTrailingSlash(Uri endpoint)
        => endpoint.AbsoluteUri.EndsWith('/', StringComparison.Ordinal)
            ? endpoint
            : new Uri(endpoint.AbsoluteUri + "/", UriKind.Absolute);

    public void Dispose()
    {
        _gate.Dispose();
        _httpClient.Dispose();
    }
}
