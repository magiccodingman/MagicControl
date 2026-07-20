using MagicControl.Web.Configuration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace MagicControl.Tests;

public sealed class MvcRegistrationTests
{
    [Fact]
    public void AddMagicControlControllers_AllowsValidateAntiforgeryFilterCreation()
    {
        var services = new ServiceCollection();

        services.AddMagicControlControllers();

        using var provider = services.BuildServiceProvider();
        var attribute = new ValidateAntiForgeryTokenAttribute();
        var filter = attribute.CreateInstance(provider);

        Assert.NotNull(filter);
    }
}
