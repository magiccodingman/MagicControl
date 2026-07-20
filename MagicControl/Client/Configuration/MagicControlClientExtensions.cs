using MagicControl.Shared.Mesh;
using MagicSettings;
using MagicSettings.Server;
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

        var initialization = await builder.AddMagicSettingsAsync(
            args,
            configureSettings,
            cancellationToken);

        if (!initialization.ShouldExit)
        {
            builder.Services.AddMagicControlClient(configureClient);
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

        services.AddMagicControlNodeAuthorization();
        services.AddSingleton(options);
        services.AddSingleton<IMagicControlManifestStore, FileMagicControlManifestStore>();
        services.AddSingleton<MagicControlManifestValidator>();
        services.AddSingleton<IMagicControlMeshEndpointResolver, ConfiguredMagicControlMeshEndpointResolver>();
        services.AddSingleton<MagicControlClientStatus>();

        services.AddHttpClient(MagicControlHttpClients.Mesh)
            .AddMagicNodeAuthentication(MagicControlMeshProtocol.MeshPeerAudience);

        services.AddHostedService<MagicControlClientHostedService>();
        return services;
    }

    public static IServiceCollection AddMagicControlNodeAuthorization(
        this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<MagicControlManifestCache>();
        services.TryAddSingleton<IMagicControlManifestSource>(provider =>
            provider.GetRequiredService<MagicControlManifestCache>());
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
            ServiceDescriptor.Singleton<IAuthorizationHandler, MagicControlCapabilityHandler>());
        services.Replace(ServiceDescriptor.Singleton<IAuthorizationPolicyProvider,
            MagicControlCapabilityPolicyProvider>());

        return services;
    }
}
