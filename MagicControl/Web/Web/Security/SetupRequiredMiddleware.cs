using MagicControl.Web.Features.Setup;

namespace MagicControl.Web.Security;

public sealed class SetupRequiredMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, ISetupState setupState)
    {
        if (IsAlwaysAllowed(context.Request.Path))
        {
            await next(context);
            return;
        }

        var complete = await setupState.IsCompleteAsync(context.RequestAborted);
        if (!complete)
        {
            if (IsApiRequest(context.Request.Path))
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsJsonAsync(new
                {
                    error = "MagicControl has not completed first-time setup.",
                    setupUri = "/setup"
                }, context.RequestAborted);
                return;
            }

            context.Response.Redirect("/setup");
            return;
        }

        if (context.Request.Path.Equals("/setup", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Redirect("/");
            return;
        }

        await next(context);
    }

    private static bool IsAlwaysAllowed(PathString path)
        => path.StartsWithSegments("/setup")
           || path.StartsWithSegments("/account/setup")
           || path.StartsWithSegments("/api/v1/recovery")
           || path.StartsWithSegments("/health")
           || path.StartsWithSegments("/_framework")
           || path.StartsWithSegments("/_content")
           || path.StartsWithSegments("/favicon")
           || path.StartsWithSegments("/css");

    private static bool IsApiRequest(PathString path)
        => path.StartsWithSegments("/api");
}
