using MagicControl.Client;
using MagicControl.Mesh;
using MagicControl.Shared.Mesh;
using MagicSettings;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

var magicSettings = await builder.AddMagicSettingsAsync<MagicControlMeshSettings>(
    args,
    options =>
    {
        options.ApplicationId = "MagicControl.Mesh";
        options.ApplicationVersion =
            typeof(Program).Assembly.GetName().Version?.ToString() ?? "development";
        options.SchemaVersion = 2;
        options.Template = MagicControlMeshSettings.CreateDefaults(
            builder.Environment.IsDevelopment());
        options.Path = "state/mesh";
        options.FileName = "appsettings.json";
        options.IdentityPath = "state/mesh";
        options.PreserveUnknownProperties = true;
        options.ControlPlane.Bootstrap.ConnectOnStartup = false;
    });

if (magicSettings.ShouldExit)
{
    Environment.ExitCode = magicSettings.ExitCode;
    return;
}

builder.Services.AddProblemDetails();
builder.Services.AddMagicControlNodeAuthorization();
builder.Services.AddSingleton<MeshManifestRepository>();
builder.Services.AddSingleton<MeshNodeSyncRepository>();
builder.Services.AddSingleton<MeshControlPlaneStatus>();
builder.Services.AddSingleton<MagicControlMeshDiscoveryService>();
builder.Services.AddHostedService(
    provider => provider.GetRequiredService<MagicControlMeshDiscoveryService>());
builder.Services.AddHostedService<MeshControlPlaneSyncService>();

builder.Services.AddHttpClient(MeshHttpClients.ControlPlane, (services, client) =>
    {
        var settings = services.GetRequiredService<
            IOptionsMonitor<MagicControlMeshSettings>>().CurrentValue;
        var endpoint = new Uri(settings.ControlPlaneEndpoint, UriKind.Absolute);
        client.BaseAddress = endpoint.AbsoluteUri.EndsWith("/", StringComparison.Ordinal)
            ? endpoint
            : new Uri(endpoint.AbsoluteUri + "/", UriKind.Absolute);
        client.Timeout = TimeSpan.FromSeconds(Math.Max(1, settings.ControlPlaneTimeoutSeconds));
    })
    .AddMagicNodeAuthentication(MagicControlMeshProtocol.MeshControlPlaneAudience);

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler();
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapMagicControlMeshApi();

app.Run();

public partial class Program { }
