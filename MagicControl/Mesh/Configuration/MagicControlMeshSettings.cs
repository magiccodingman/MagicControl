using MagicSettings;

namespace MagicControl.Mesh;

public sealed class MagicControlMeshSettings
{
    public MeshLoggingSettings Logging { get; set; } = MeshLoggingSettings.CreateDefaults(false);
    public string AllowedHosts { get; set; } = "*";
    public string ControlPlaneEndpoint { get; set; } = "https://localhost:7443";
    public string StatePath { get; set; } = "state/mesh";
    public int RefreshIntervalSeconds { get; set; } = 30;
    public int ControlPlaneTimeoutSeconds { get; set; } = 10;

    [MagicSensitive]
    public string? TrustedAuthorityPublicKey { get; set; }

    public bool AllowAuthorityTrustOnFirstUse { get; set; } = true;

    public static MagicControlMeshSettings CreateDefaults(bool isDevelopment) => new()
    {
        Logging = MeshLoggingSettings.CreateDefaults(isDevelopment)
    };
}

public sealed class MeshLoggingSettings
{
    public Dictionary<string, string> LogLevel { get; set; } = [];

    public static MeshLoggingSettings CreateDefaults(bool isDevelopment) => new()
    {
        LogLevel = new Dictionary<string, string>
        {
            ["Default"] = "Information",
            ["Microsoft.AspNetCore"] = isDevelopment ? "Information" : "Warning",
            ["System.Net.Http.HttpClient"] = isDevelopment ? "Information" : "Warning"
        }
    };
}
