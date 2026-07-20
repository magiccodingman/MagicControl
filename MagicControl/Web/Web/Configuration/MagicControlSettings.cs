using MagicSettings;

namespace MagicControl.Web.Configuration;

public sealed class MagicControlSettings
{
    public LoggingSettings Logging { get; set; } = LoggingSettings.CreateDefaults(isDevelopment: false);
    public string AllowedHosts { get; set; } = "*";
    public DatabaseSettings Database { get; set; } = new();
    public SecuritySettings Security { get; set; } = new();
    public InitialSetupSettings Setup { get; set; } = new();
    public RecoverySettings AdminRecovery { get; set; } = new();
    public EnrollmentSettings Enrollment { get; set; } = new();

    public static MagicControlSettings CreateDefaults(bool isDevelopment = false) => new()
    {
        Logging = LoggingSettings.CreateDefaults(isDevelopment)
    };
}

public sealed class LoggingSettings
{
    public Dictionary<string, string> LogLevel { get; set; } = [];

    public static LoggingSettings CreateDefaults(bool isDevelopment) => new()
    {
        LogLevel = new Dictionary<string, string>
        {
            ["Default"] = "Information",
            ["Microsoft.AspNetCore"] = isDevelopment ? "Information" : "Warning",
            ["Microsoft.EntityFrameworkCore.Database.Command"] = isDevelopment ? "Information" : "Warning"
        }
    };
}

public sealed class DatabaseSettings
{
    public string Provider { get; set; } = "Sqlite";
    public string SqliteConnectionString { get; set; } = "Data Source=state/magic-control.db";

    [MagicSensitive]
    public string PostgreSqlConnectionString { get; set; } = string.Empty;

    public bool ApplyMigrationsOnStartup { get; set; } = true;
}

public sealed class SecuritySettings
{
    public string DataProtectionKeyPath { get; set; } = "state/data-protection";
    public int CookieLifetimeHours { get; set; } = 12;
    public int PasswordMinimumLength { get; set; } = 14;
    public int MaximumFailedLogins { get; set; } = 8;
    public int LockoutMinutes { get; set; } = 15;
}

public sealed class InitialSetupSettings
{
    [MagicSensitive]
    public string? RemoteSetupToken { get; set; }
}

public sealed class RecoverySettings
{
    public bool Enabled { get; set; }

    [MagicSensitive]
    public string? OneTimeToken { get; set; }
}

public sealed class EnrollmentSettings
{
    public bool AllowNewRequests { get; set; } = true;
    public int MaximumRequestBytes { get; set; } = 262_144;
    public int RequestRetentionDays { get; set; } = 90;
}
