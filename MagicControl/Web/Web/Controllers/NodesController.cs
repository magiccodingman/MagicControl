using MagicControl.Shared.Mesh;
using MagicControl.Web.Features.Nodes;
using MagicSettings.Share;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MagicControl.Web.Controllers;

[ApiController]
[Route("api/v1/nodes")]
public sealed class NodesController(MagicControlNodeSyncService nodes) : ControllerBase
{
    [HttpPost("sync")]
    [AllowAnonymous]
    public async ValueTask<ActionResult<MagicControlNodeSyncResponse>> Synchronize(
        MagicControlNodeSyncRequest request,
        CancellationToken cancellationToken)
        => Ok(await nodes.SynchronizeAsync(request, cancellationToken));

    [HttpPost("secrets")]
    [AllowAnonymous]
    public async ValueTask<ActionResult<MagicSecretResponse>> ResolveSecret(
        MagicControlNodeSecretRequest request,
        CancellationToken cancellationToken)
        => Ok(await nodes.ResolveSecretAsync(request, cancellationToken));
}
