using MagicControl.Shared.Security;

namespace MagicControl.Web.Security;

public sealed class MustChangePasswordMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var mustChange = context.User.Identity?.IsAuthenticated == true
                         && string.Equals(
                             context.User.FindFirst(MagicControlClaimTypes.MustChangePassword)?.Value,
                             bool.TrueString,
                             StringComparison.OrdinalIgnoreCase);

        if (!mustChange || IsAllowed(context.Request.Path))
        {
            await next(context);
            return;
        }

        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "A password change is required before this account can access MagicControl."
            }, context.RequestAborted);
            return;
        }

        context.Response.Redirect("/change-password");
    }

    private static bool IsAllowed(PathString path)
        => path.StartsWithSegments("/change-password")
           || path.StartsWithSegments("/account/change-password")
           || path.StartsWithSegments("/account/logout")
           || path.StartsWithSegments("/api/v1/auth/me")
           || path.StartsWithSegments("/_framework")
           || path.StartsWithSegments("/_content")
           || path.StartsWithSegments("/favicon");
}
