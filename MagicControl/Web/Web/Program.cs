using MagicControl.Web.Components;
using MagicControl.Web.Configuration;
using MagicControl.Web.Data;
using MagicControl.Web.Features.Dashboard;
using MagicControl.Web.Features.Mesh;
using MagicControl.Web.Features.Nodes;
using MagicControl.Web.Features.Settings;
using MagicControl.Web.Health;
using MagicControl.Web.Security;
using MagicSettings;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using MudBlazor.Services;

var builder = WebApplication.CreateBuilder(args);

var magicSettings = await builder.AddMagicSettingsAsync<MagicControlSettings>(
    args,
    options =>
    {
        options.ApplicationId = "MagicControl.Web";
        options.ApplicationVersion =
            typeof(Program).Assembly.GetName().Version?.ToString() ?? "development";
        options.SchemaVersion = 1;
        options.Template = MagicControlSettings.CreateDefaults(builder.Environment.IsDevelopment());
        options.Path = "state";
        options.FileName = "appsettings.json";
        options.IdentityPath = "state";
        options.PreserveUnknownProperties = true;
        options.ControlPlane.Bootstrap.ConnectOnStartup = false;
    });

if (magicSettings.ShouldExit)
{
    Environment.ExitCode = magicSettings.ExitCode;
    return;
}

builder.Services.AddMudServices();
builder.Services.AddProblemDetails();
builder.Services.AddMagicControlControllers();
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddInteractiveWebAssemblyComponents();
builder.Services.AddCascadingAuthenticationState();

builder.Services.AddMagicControlDatabase(builder.Configuration);
builder.Services.AddMagicControlDataProtection(builder.Configuration);
builder.Services.AddMagicControlSecurity(builder.Configuration);
builder.Services.AddScoped<DashboardService>();
builder.Services.AddScoped<ApplicationSettingsService>();
builder.Services.AddScoped<MagicControlNodeSyncService>();
builder.Services.AddSingleton<MagicControlAuthoritySigningService>();
builder.Services.AddSingleton<MeshManifestService>();
builder.Services.AddSingleton<MeshGroupDirectoryService>();
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("database", tags: ["ready"]);

var app = builder.Build();

if (builder.Configuration.GetValue("Database:ApplyMigrationsOnStartup", true))
{
    await using var scope = app.Services.CreateAsyncScope();
    var factory = scope.ServiceProvider
        .GetRequiredService<IDbContextFactory<MagicControlDbContext>>();
    await using var db = await factory.CreateDbContextAsync();
    await db.Database.MigrateAsync();
}

if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler();
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseMiddleware<SetupRequiredMiddleware>();
app.UseAuthentication();
app.UseMiddleware<MustChangePasswordMiddleware>();
app.UseAuthorization();
app.UseAntiforgery();

app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = _ => false
}).AllowAnonymous();

app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = registration => registration.Tags.Contains("ready")
}).AllowAnonymous();

app.MapControllers();
app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .AddInteractiveWebAssemblyRenderMode();

app.Run();

public partial class Program { }
