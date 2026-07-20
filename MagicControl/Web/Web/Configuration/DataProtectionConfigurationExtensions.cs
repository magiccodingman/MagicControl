using Microsoft.AspNetCore.DataProtection;

namespace MagicControl.Web.Configuration;

public static class DataProtectionConfigurationExtensions
{
    public static IServiceCollection AddMagicControlDataProtection(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var configuredPath = configuration["Security:DataProtectionKeyPath"]
                             ?? "state/data-protection";
        var keyDirectory = new DirectoryInfo(Path.GetFullPath(configuredPath));
        keyDirectory.Create();

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                keyDirectory.FullName,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        services.AddDataProtection()
            .SetApplicationName("MagicControl")
            .PersistKeysToFileSystem(keyDirectory);

        return services;
    }
}
