using System.Security.Claims;
using MagicControl.Shared.Security;
using MagicControl.Web.Features.Authentication;
using MagicControl.Web.Features.Setup;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MagicControl.Web.Controllers;

[Route("account")]
public sealed class AccountController(
    SetupService setup,
    UserAuthenticationService authentication) : Controller
{
    [HttpPost("setup")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Setup(
        [FromForm] string username,
        [FromForm] string password,
        [FromForm] string confirmPassword,
        [FromForm] string? setupToken,
        CancellationToken cancellationToken)
    {
        if (!setup.IsRequestAllowed(HttpContext.Connection.RemoteIpAddress, setupToken))
        {
            return NotFound();
        }

        var result = await setup.CompleteAsync(
            new InitialSetupRequest(username, password, confirmPassword),
            cancellationToken);

        if (!result.Succeeded || result.UserId is null)
        {
            return LocalRedirect($"/setup?error={Uri.EscapeDataString(result.Error ?? "Setup failed.")}");
        }

        var principal = await authentication.RefreshPrincipalAsync(result.UserId.Value, cancellationToken);
        if (principal is null)
        {
            return LocalRedirect("/login?error=Setup completed, but automatic login failed.");
        }

        await HttpContext.SignInAsync(
            MagicControlSecurity.UiCookieScheme,
            principal,
            new AuthenticationProperties { IsPersistent = true });

        return LocalRedirect("/");
    }

    [HttpPost("login")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(
        [FromForm] string username,
        [FromForm] string password,
        [FromForm] string? returnUrl,
        CancellationToken cancellationToken)
    {
        var result = await authentication.AuthenticateAsync(username, password, cancellationToken);
        if (!result.Succeeded || result.Principal is null)
        {
            var destination = $"/login?error={Uri.EscapeDataString(result.Error ?? "Login failed.")}";
            if (!string.IsNullOrWhiteSpace(returnUrl))
            {
                destination += $"&returnUrl={Uri.EscapeDataString(returnUrl)}";
            }

            return LocalRedirect(destination);
        }

        await HttpContext.SignInAsync(
            MagicControlSecurity.UiCookieScheme,
            result.Principal,
            new AuthenticationProperties { IsPersistent = true });

        if (result.Principal.HasClaim(
                MagicControlClaimTypes.MustChangePassword,
                bool.TrueString))
        {
            return LocalRedirect("/change-password");
        }

        return LocalRedirect(IsSafeLocalUrl(returnUrl) ? returnUrl! : "/");
    }

    [HttpPost("change-password")]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(
        [FromForm] string currentPassword,
        [FromForm] string newPassword,
        [FromForm] string confirmPassword,
        CancellationToken cancellationToken)
    {
        var id = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(id, out var userId))
        {
            await HttpContext.SignOutAsync(MagicControlSecurity.UiCookieScheme);
            return LocalRedirect("/login");
        }

        var result = await authentication.ChangePasswordAsync(
            userId,
            currentPassword,
            newPassword,
            confirmPassword,
            cancellationToken);

        if (!result.Succeeded || result.Principal is null)
        {
            return LocalRedirect(
                $"/change-password?error={Uri.EscapeDataString(result.Error ?? "Password change failed.")}");
        }

        await HttpContext.SignInAsync(
            MagicControlSecurity.UiCookieScheme,
            result.Principal,
            new AuthenticationProperties { IsPersistent = true });

        return LocalRedirect("/");
    }

    [HttpPost("logout")]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(MagicControlSecurity.UiCookieScheme);
        return LocalRedirect("/login");
    }

    private bool IsSafeLocalUrl(string? url)
        => !string.IsNullOrWhiteSpace(url) && Url.IsLocalUrl(url);
}
