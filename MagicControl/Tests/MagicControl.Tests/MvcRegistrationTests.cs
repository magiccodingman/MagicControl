using MagicControl.Web.Configuration;
using Microsoft.AspNetCore.Mvc.ViewFeatures.Filters;
using Microsoft.Extensions.DependencyInjection;

namespace MagicControl.Tests;

public sealed class MvcRegistrationTests
{
    [Fact]
    public void AddMagicControlControllers_RegistersValidateAntiforgeryTokenFilter()
    {
        var services = new ServiceCollection();

        services.AddMagicControlControllers();

        using var provider = services.BuildServiceProvider();
        var filter = provider.GetService<ValidateAntiforgeryTokenAuthorizationFilter>();

        Assert.NotNull(filter);
    }
}
