using MagicControl.Shared.Security;
using MagicControl.Web.Features.Enrollments;
using Microsoft.AspNetCore.Mvc;

namespace MagicControl.Web.Controllers;

[ApiController]
[Route("api/v1/instances")]
[Microsoft.AspNetCore.Authorization.Authorize]
public sealed class ManagedInstancesController(EnrollmentService enrollments) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
        => Ok(await enrollments.GetManagedInstancesAsync(cancellationToken));

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id, CancellationToken cancellationToken)
    {
        var instance = await enrollments.GetManagedInstanceAsync(id, cancellationToken);
        return instance is null ? NotFound() : Ok(instance);
    }
}
