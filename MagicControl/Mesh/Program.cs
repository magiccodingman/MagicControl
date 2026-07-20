using MagicControl.Client;
using MagicControl.Shared.Mesh;
using MagicSettings;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

var magicSettings = await builder.AddMagicSettingsAsync<MagicControl.Mesh.MagicControlMeshSettings>(
    args,
    options =>
    {
        options.ApplicationId = "MagicControl.Mesh";
        options.ApplicationVersion =
            typeof(Program).Assembly.GetName().Version?.ToString() ?? "development";
        options.SchemaVersion = 1;
        options.Template = MagicControl.Mesh.MagicControlMeshSettings.CreateDefaults(
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
builder.Services.AddSingleton<MagicControl.Mesh.MeshManifestRepository>();
builder.Services.AddSingleton<MagicControl.Mesh.MeshControlPlaneStatus>();
builder.Services.AddHostedService<MagicControl.Mesh.MeshControlPlaneSyncService>();

builder.Services.AddHttpClient(MagicControl.Mesh.MeshHttpClients.ControlPlane, (services, client) =>
    {
        var settings = services.GetRequiredService<
            IOptionsMonitor<MagicControl.Mesh.MagicControlMeshSettings>>().CurrentValue;
        var endpoint = new Uri(settings.ControlPlaneEndpoint, UriKind.Absolute);
        client.BaseAddress = endpoint.AbsoluteUri.EndsWith('/', StringComparison.Ordinal)
            ? endpoint
            : new Uri(endpoint.AbsoluteUri + '/', UriKind.Absolute);
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
