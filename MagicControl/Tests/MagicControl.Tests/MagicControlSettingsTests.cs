using MagicControl.Web.Configuration;

namespace MagicControl.Tests;

public sealed class MagicControlSettingsTests
{
    [Fact]
    public void CreateDefaults_Development_UsesVerboseFrameworkLogging()
    {
        var settings = MagicControlSettings.CreateDefaults(isDevelopment: true);

        Assert.Equal("Information", settings.Logging.LogLevel["Default"]);
        Assert.Equal("Information", settings.Logging.LogLevel["Microsoft.AspNetCore"]);
        Assert.Equal(
            "Information",
            settings.Logging.LogLevel["Microsoft.EntityFrameworkCore.Database.Command"]);
        Assert.Equal("*", settings.AllowedHosts);
    }

    [Fact]
    public void CreateDefaults_NonDevelopment_UsesWarningFrameworkLogging()
    {
        var settings = MagicControlSettings.CreateDefaults(isDevelopment: false);

        Assert.Equal("Information", settings.Logging.LogLevel["Default"]);
        Assert.Equal("Warning", settings.Logging.LogLevel["Microsoft.AspNetCore"]);
        Assert.Equal(
            "Warning",
            settings.Logging.LogLevel["Microsoft.EntityFrameworkCore.Database.Command"]);
        Assert.Equal("*", settings.AllowedHosts);
    }
}
