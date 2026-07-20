using System.Text.Json.Nodes;
using MagicControl.Shared.Mesh;
using MagicSettings;
using MagicSettings.Share;

namespace MagicControl.Client;

public sealed class MagicControlLogicalEndpointResolver(
    MagicControlClientOptions options,
    string contextHash) : IMagicControlPlaneEndpointResolver
{
    public MagicResolvedControlPlaneEndpoint Resolve<TSettings>(
        MagicSettingsOptions<TSettings> settings,
        JsonObject persistentDocument,
        Uri? runtimeOverride = null)
        where TSettings : class, new()
        => new(
            runtimeOverride
            ?? MagicControlLogicalUris.ControlPlaneBase(options.GroupId, contextHash),
            runtimeOverride is null
                ? MagicControlPlaneEndpointSource.CodeFallback
                : MagicControlPlaneEndpointSource.RuntimeOverride);
}
