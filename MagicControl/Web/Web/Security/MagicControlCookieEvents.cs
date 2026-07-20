using System.Security.Claims;
using MagicControl.Shared.Security;
using MagicControl.Web.Features.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace MagicControl.Web.Security;

public sealed class MagicControlCookieEvents(UserAuthenticationService authentication)
    : CookieAuthenticationEvents
{
    public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        var userIdValue = context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out var userId))
        {
            await RejectAsync(context);
            return;
        }

        var refreshed = await authentication.RefreshPrincipalAsync(userId, context.HttpContext.RequestAborted);
        if (refreshed is null)
        {
            await RejectAsync(context);
            return;
        }

        var presentedStamp = context.Principal?.FindFirstValue(MagicControlClaimTypes.SecurityStamp);
        var currentStamp = refreshed.FindFirstValue(MagicControlClaimTypes.SecurityStamp);
        if (!string.Equals(presentedStamp, currentStamp, StringComparison.Ordinal))
        {
            await RejectAsync(context);
            return;
        }

        context.ReplacePrincipal(refreshed);
    }

    private static async Task RejectAsync(CookieValidatePrincipalContext context)
    {
        context.RejectPrincipal();
        await context.HttpContext.SignOutAsync(MagicControlSecurity.UiCookieScheme);
    }
}
