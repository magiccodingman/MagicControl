using MagicControl.Shared.Mesh;
using MagicSettings;
using MagicSettings.Server;
using MagicSettings.Share;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace MagicControl.Client;

public static class MagicControlClientExtensions
{
    public static async ValueTask<MagicSettingsInitializationResult> AddMagicControlClientAsync<TSettings>(
        this IHostApplicationBuilder builder,
        string[]? args = null,
        Action<MagicSettingsOptions<TSettings>>? configureSettings = null,
        Action<MagicControlClientOptions>? configureClient = null,
        CancellationToken cancellationToken = default)
        where TSettings : class, new()
    {
        ArgumentNullException.ThrowIfNull(builder);

        var clientOptions = new MagicControlClientOptions
        {
            Version = typeof(TSettings).Assembly.GetName().Version?.ToString()
        };
        configureClient?.Invoke(clientOptions);
        clientOptions.Validate();

        var cache = new MagicControlManifestCache();
        var manifestStore = new FileMagicControlManifestStore(clientOptions);
        var clientStateStore = new FileMagicControlClientStateStore(clientOptions);
        var peerDirectory = new MagicControlPeerDirectory(clientOptions);
        var peerDirectoryStore = new FileMagicControlPeerDirectoryStore(clientOptions);
        var securityLatchStore = new FileMagicControlSecurityLatchStore(clientOptions);
        var securityState = new MagicControlRuntimeSecurityState(securityLatchStore);
        var persistentState = await clientStateStore.LoadAsync(cancellationToken);
        clientOptions.TrustedAuthorityPublicKey ??= persistentState.AuthorityPublicKey;
        var contextHash = clientOptions.ComputeContextHash(persistentState.BootstrapNonce);

        var validator = new MagicControlManifestValidator(clientOptions);
        var status = new MagicControlClientStatus();
        var endpointResolver = new DiscoveringMagicControlMeshEndpointResolver(
            clientOptions,
            clientStateStore);
        var transport = new MagicControlClientSyncTransport(
            clientOptions,
            endpointResolver,
            clientStateStore,
            manifestStore,
            validator,
            cache,
            status,
            securityState);
        var logicalEndpointResolver = new MagicControlLogicalEndpointResolver(
            clientOptions,
            contextHash);

        var initialization = await builder.AddMagicSettingsAsync<TSettings>(
            args,
            settings =>
            {
                configureSettings?.Invoke(settings);
                settings.ApplicationId = clientOptions.ApplicationName;
                settings.ApplicationVersion = clientOptions.Version
                                              ?? settings.ApplicationVersion;
                settings.ControlPlaneTransport = transport;
                settings.ControlPlaneEndpointResolver = logicalEndpointResolver;
                settings.ControlPlane.Bootstrap.CodeFallbackEndpoint =
                    MagicControlLogicalUris.ControlPlaneBase(
                        clientOptions.GroupId,
                        contextHash);
                settings.ControlPlane.Bootstrap.Trust =
                    MagicControlPlaneTrust.SystemTls(MagicControlNodeProtocol.NodeSyncAudience);
                settings.ControlPlane.Bootstrap.ConnectOnStartup = true;
                settings.ControlPlane.Bootstrap.WatchPersistentEndpoint = false;
                settings.ControlPlane.PollInterval = clientOptions.RefreshInterval;
                settings.ControlPlane.PollJitter = TimeSpan.FromSeconds(
                    Math.Min(5, Math.Max(0, clientOptions.RefreshInterval.TotalSeconds / 10)));
                settings.ControlPlane.KeepLastKnownGoodDuringOutage = true;
            },
            cancellationToken);

        if (!initialization.ShouldExit)
        {
            RegisterClientServices(
                builder.Services,
                clientOptions,
                cache,
                manifestStore,
                clientStateStore,
                peerDirectory,
                peerDirectoryStore,
                securityLatchStore,
                securityState,
                validator,
                endpointResolver,
                status,
                transport);
        }

        return initialization;
    }

    public static IServiceCollection AddMagicControlClient(
        this IServiceCollection services,
        Action<MagicControlClientOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        var options = new MagicControlClientOptions();
        configure?.Invoke(options);
        options.Validate();

        var cache = new MagicControlManifestCache();
        var manifestStore = new FileMagicControlManifestStore(options);
        var stateStore = new FileMagicControlClientStateStore(options);
        var peerDirectory = new MagicControlPeerDirectory(options);
        var peerDirectoryStore = new FileMagicControlPeerDirectoryStore(options);
        var securityLatchStore = new FileMagicControlSecurityLatchStore(options);
        var securityState = new MagicControlRuntimeSecurityState(securityLatchStore);
        var validator = new MagicControlManifestValidator(options);
        var status = new MagicControlClientStatus();
        var resolver = new DiscoveringMagicControlMeshEndpointResolver(options, stateStore);

        services.AddSingleton(options);
        services.AddSingleton(cache);
        services.AddSingleton<IMagicControlManifestSource>(cache);
        services.AddSingleton<IMagicControlManifestStore>(manifestStore);
        services.AddSingleton<IMagicControlClientStateStore>(stateStore);
        services.AddSingleton(peerDirectory);
        services.AddSingleton<IMagicControlPeerDirectoryStore>(peerDirectoryStore);
        services.AddSingleton<IMagicControlSecurityLatchStore>(securityLatchStore);
        services.AddSingleton(securityState);
        services.AddSingleton(validator);
        services.AddSingleton<IMagicControlMeshEndpointResolver>(resolver);
        services.AddSingleton(status);
        services.AddSingleton<IMagicControlServiceResolver, MagicControlServiceResolver>();
        services.AddMagicControlNodeAuthorization();
        services.AddHttpClient(MagicControlHttpClients.Mesh)
            .AddMagicNodeAuthentication(MagicControlMeshProtocol.MeshPeerAudience);
        services.AddHostedService<MagicControlClientHostedService>();
        services.AddHostedService<MagicControlPeerDiscoveryService>();
        return services;
    }

    public static IServiceCollection AddMagicControlNodeAuthorization(
        this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<MagicControlManifestCache>();
        services.TryAddSingleton<IMagicControlManifestSource>(provider =>
            provider.GetRequiredService<MagicControlManifestCache>());
        services.TryAddSingleton(_ => new MagicControlRuntimeSecurityState());
        services.TryAddSingleton<IMagicControlAuthorizationService, MagicControlAuthorizationService>();
        services.TryAddSingleton<MagicControlCachedCredentialRegistry>();
        services.TryAddSingleton<InMemoryMagicReplayCache>();
        services.TryAddSingleton(provider => new MagicNodeProofVerifier(
            provider.GetRequiredService<MagicControlCachedCredentialRegistry>(),
            provider.GetRequiredService<InMemoryMagicReplayCache>()));

        services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, MagicControlNodeAuthenticationHandler>(
                MagicControlMeshProtocol.NodeAuthenticationScheme,
                _ => { });
        services.AddAuthorization();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IAuthorizationHandler, MagicControlAccessHandler>());
        services.Replace(ServiceDescriptor.Singleton<IAuthorizationPolicyProvider,
            MagicControlCapabilityPolicyProvider>());

        return services;
    }

    private static void RegisterClientServices(
        IServiceCollection services,
        MagicControlClientOptions options,
        MagicControlManifestCache cache,
        FileMagicControlManifestStore manifestStore,
        FileMagicControlClientStateStore stateStore,
        MagicControlPeerDirectory peerDirectory,
        FileMagicControlPeerDirectoryStore peerDirectoryStore,
        FileMagicControlSecurityLatchStore securityLatchStore,
        MagicControlRuntimeSecurityState securityState,
        MagicControlManifestValidator validator,
        DiscoveringMagicControlMeshEndpointResolver endpointResolver,
        MagicControlClientStatus status,
        MagicControlClientSyncTransport transport)
    {
        services.AddSingleton(options);
        services.AddSingleton(cache);
        services.AddSingleton<IMagicControlManifestSource>(cache);
        services.AddSingleton<IMagicControlManifestStore>(manifestStore);
        services.AddSingleton<IMagicControlClientStateStore>(stateStore);
        services.AddSingleton(peerDirectory);
        services.AddSingleton<IMagicControlPeerDirectoryStore>(peerDirectoryStore);
        services.AddSingleton<IMagicControlSecurityLatchStore>(securityLatchStore);
        services.AddSingleton(securityState);
        services.AddSingleton(validator);
        services.AddSingleton<IMagicControlMeshEndpointResolver>(endpointResolver);
        services.AddSingleton(status);
        services.AddSingleton(transport);
        services.AddSingleton<IMagicControlServiceResolver, MagicControlServiceResolver>();

        services.AddMagicControlNodeAuthorization();
        services.AddHttpClient(MagicControlHttpClients.Mesh)
            .AddMagicNodeAuthentication(MagicControlMeshProtocol.MeshPeerAudience);
        services.AddHostedService<MagicControlClientHostedService>();
        services.AddHostedService<MagicControlPeerDiscoveryService>();
    }
}
