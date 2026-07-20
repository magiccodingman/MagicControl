using System.Security.Claims;
using MagicControl.Shared.Security;
using MagicControl.Web.Features.Users;
using Microsoft.AspNetCore.Mvc;

namespace MagicControl.Web.Controllers;

public sealed record CreateUserApiRequest(string Username, IReadOnlyList<string>? Roles);
public sealed record SetUserStatusApiRequest(bool Disabled);
public sealed record SetUserRolesApiRequest(IReadOnlyList<string> Roles);

[ApiController]
[Route("api/v1/users")]
[RequireMagicControlRole(MagicControlRoles.UserAdministrator)]
public sealed class UsersController(UserAdministrationService users) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
        => Ok(await users.GetUsersAsync(cancellationToken));

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(
        CreateUserApiRequest request,
        CancellationToken cancellationToken)
    {
        var result = await users.CreateAsync(
            new CreateUserRequest(request.Username, request.Roles ?? []),
            ActorId(),
            cancellationToken);

        Response.Headers["Cache-Control"] = "no-store";
        return Created($"/api/v1/users/{result.UserId}", result);
    }

    [HttpPost("{id:guid}/reset-password")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(
        Guid id,
        CancellationToken cancellationToken)
    {
        var result = await users.ResetPasswordAsync(id, ActorId(), cancellationToken);
        Response.Headers["Cache-Control"] = "no-store";
        return Ok(result);
    }

    [HttpPut("{id:guid}/status")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SetStatus(
        Guid id,
        SetUserStatusApiRequest request,
        CancellationToken cancellationToken)
    {
        await users.SetDisabledAsync(id, request.Disabled, ActorId(), cancellationToken);
        return NoContent();
    }

    [HttpPut("{id:guid}/roles")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SetRoles(
        Guid id,
        SetUserRolesApiRequest request,
        CancellationToken cancellationToken)
    {
        await users.SetRolesAsync(id, request.Roles, ActorId(), cancellationToken);
        return NoContent();
    }

    private Guid ActorId()
        => Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
}
