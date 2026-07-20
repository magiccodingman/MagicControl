using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using MagicControl.Shared.Enrollments;
using MagicControl.Shared.Mesh;
using MagicControl.Shared.Security;
using MagicControl.Web.Data;
using MagicControl.Web.Features.Mesh;
using MagicSettings.Server;
using MagicSettings.Share;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Controllers;

[ApiController]
[Route("api/v1/mesh")]
public sealed class MeshControlPlaneController(
    MagicNodeProofVerifier proofVerifier,
    IDbContextFactory<MagicControlDbContext> dbFactory,
    MeshManifestService manifests,
    MagicControlAuthoritySigningService authority) : ControllerBase
{
    [HttpGet("authority")]
    [AllowAnonymous]
    public async Task<IActionResult> GetAuthority(CancellationToken cancellationToken)
        => Ok(await authority.GetAuthorityAsync(cancellationToken));

    [HttpGet("groups/{groupId:guid}/manifest")]
    [AllowAnonymous]
    public async Task<IActionResult> GetManifest(
        Guid groupId,
        CancellationToken cancellationToken)
    {
        var proof = DecodeProof();
        if (proof is null)
        {
            return Unauthorized();
        }

        var verification = await proofVerifier.VerifyAsync(
            new MagicProofVerificationRequest(
                proof,
                MagicControlMeshProtocol.MeshControlPlaneAudience,
                Request.Method,
                RequestUri(),
                EmptyBodyHash(),
                DateTimeOffset.UtcNow),
            cancellationToken);

        if (!verification.IsValid)
        {
            return Unauthorized();
        }

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var caller = await db.InstanceCredentials
            .Include(credential => credential.ManagedInstance)
            .SingleOrDefaultAsync(
                credential => credential.NodeId == proof.NodeId
                              && credential.CredentialId == proof.CredentialId,
                cancellationToken);

        if (caller?.ManagedInstance is null
            || caller.ManagedInstance.Kind != EnrollmentKind.MeshApi
            || caller.ManagedInstance.Status != ManagedInstanceStatus.Active)
        {
            return Forbid();
        }

        caller.ManagedInstance.LastSeenUtc = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);

        try
        {
            return Ok(await manifests.GetSignedManifestAsync(groupId, cancellationToken));
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
    }

    [HttpPut("groups/{groupId:guid}/policy")]
    [ValidateAntiForgeryToken]
    [RequireMagicControlRole(MagicControlRoles.SuperAdministrator)]
    public async Task<IActionResult> UpdatePolicy(
        Guid groupId,
        UpdateGroupMeshPolicyRequest request,
        CancellationToken cancellationToken)
    {
        var actorId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        try
        {
            await manifests.UpdatePolicyAsync(groupId, request, actorId, cancellationToken);
            return NoContent();
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
        catch (ArgumentOutOfRangeException exception)
        {
            return BadRequest(new { error = exception.Message });
        }
    }

    private MagicAuthenticationProof? DecodeProof()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authorization))
        {
            return null;
        }

        const string prefix = "MagicNode ";
        var value = authorization.ToString();
        if (!value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        try
        {
            return MagicNodeProofCodec.Decode(value[prefix.Length..].Trim());
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            return null;
        }
    }

    private Uri RequestUri()
        => new($"{Request.Scheme}://{Request.Host}{Request.PathBase}{Request.Path}{Request.QueryString}");

    private static string EmptyBodyHash()
        => Convert.ToHexString(SHA256.HashData([])).ToLowerInvariant();
}
