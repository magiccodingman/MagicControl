using Microsoft.AspNetCore.Mvc;

namespace MagicControl.Web.Configuration;

public static class MvcConfigurationExtensions
{
    public static IMvcBuilder AddMagicControlControllers(this IServiceCollection services)
        => services.AddControllersWithViews();
}
