using System.Security.Claims;
using MagicControl.Shared.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MagicControl.Web.Controllers;

[ApiController]
[Route("api/v1/auth")]
public sealed class AuthenticationController : ControllerBase
{
    [HttpGet("me")]
    [Authorize]
    public IActionResult Me()
        => Ok(new
        {
            Id = User.FindFirstValue(ClaimTypes.NameIdentifier),
            Username = User.Identity?.Name,
            Roles = User.FindAll(ClaimTypes.Role).Select(x => x.Value).ToArray(),
            MustChangePassword = User.HasClaim(
                MagicControlClaimTypes.MustChangePassword,
                bool.TrueString)
        });
}
