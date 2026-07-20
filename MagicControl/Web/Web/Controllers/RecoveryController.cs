using System.Net;
using MagicControl.Web.Features.Recovery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MagicControl.Web.Controllers;

[ApiController]
[Route("api/v1/recovery")]
[AllowAnonymous]
public sealed class RecoveryController(RecoveryService recovery) : ControllerBase
{
    [HttpPost("reset-super-administrator")]
    public async Task<IActionResult> ResetSuperAdministrator(CancellationToken cancellationToken)
    {
        var remote = HttpContext.Connection.RemoteIpAddress;
        if (remote is null || !IPAddress.IsLoopback(remote))
        {
            return NotFound();
        }

        var token = Request.Headers["X-MagicControl-Recovery-Token"].ToString();
        if (!recovery.ValidateToken(token))
        {
            return NotFound();
        }

        if (!recovery.TryConsume())
        {
            return Conflict(new { error = "The recovery endpoint has already been used in this process." });
        }

        var result = await recovery.ResetSuperAdministratorAsync(cancellationToken);
        if (!result.Succeeded)
        {
            return Problem(result.Error, statusCode: StatusCodes.Status409Conflict);
        }

        Response.Headers["Cache-Control"] = "no-store";
        return Ok(new
        {
            result.Username,
            result.TemporaryPassword,
            MustChangePassword = true
        });
    }
}
