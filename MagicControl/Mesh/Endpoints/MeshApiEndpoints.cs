using System.Security.Claims;
using MagicControl.Client;
using MagicControl.Shared.Mesh;
using Microsoft.AspNetCore.Authentication;

namespace MagicControl.Mesh;

public static class MeshApiEndpoints
{
    public static IEndpointRouteBuilder MapMagicControlMeshApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/health/live", () => Results.Ok(new { status = "live" }));

        endpoints.MapGet("/health/ready", (
            MagicControlManifestCache cache,
            MeshControlPlaneStatus controlPlane) =>
        {
            var groups = cache.GetAll();
            return groups.Count > 0
                ? Results.Ok(new
                {
                    status = "ready",
                    cachedGroups = groups.Count,
                    controlPlane.LastSuccessUtc,
                    controlPlane.LastError
                })
                : Results.Json(
                    new
                    {
                        status = "not-ready",
                        cachedGroups = 0,
                        controlPlane.LastSuccessUtc,
                        controlPlane.LastError
                    },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
        });

        endpoints.MapGet("/api/v1/groups/{groupId:guid}/manifest", async (
            Guid groupId,
            HttpContext context,
            MagicControlManifestCache cache,
            IMagicControlAuthorizationService authorization) =>
        {
            var state = cache.Get(groupId);
            if (state is null)
            {
                return Results.NotFound();
            }

            var denied = await AuthorizeGroupAsync(context, state.Manifest, authorization);
            return denied ?? Results.Ok(state.Envelope);
        });

        endpoints.MapGet("/api/v1/groups/{groupId:guid}/directory", async (
            Guid groupId,
            string? applicationName,
            HttpContext context,
            MagicControlManifestCache cache,
            IMagicControlAuthorizationService authorization) =>
        {
            var state = cache.Get(groupId);
            if (state is null)
            {
                return Results.NotFound();
            }

            var denied = await AuthorizeGroupAsync(context, state.Manifest, authorization);
            if (denied is not null)
            {
                return denied;
            }

            var entries = string.IsNullOrWhiteSpace(applicationName)
                ? state.Manifest.Directory
                : authorization.ResolveAll(groupId, applicationName);
            return Results.Ok(entries);
        });

        endpoints.MapGet("/api/v1/groups/{groupId:guid}/settings", async (
            Guid groupId,
            HttpContext context,
            MagicControlManifestCache cache,
            IMagicControlAuthorizationService authorization) =>
        {
            var state = cache.Get(groupId);
            if (state is null)
            {
                return Results.NotFound();
            }

            var denied = await AuthorizeGroupAsync(context, state.Manifest, authorization);
            return denied ?? Results.Ok(state.Manifest.Settings);
        });

        return endpoints;
    }

    private static async ValueTask<IResult?> AuthorizeGroupAsync(
        HttpContext context,
        MagicControlGroupManifest manifest,
        IMagicControlAuthorizationService authorization)
    {
        if (manifest.SecurityMode == MagicControlGroupSecurityMode.Open)
        {
            return null;
        }

        var authentication = await context.AuthenticateAsync(
            MagicControlMeshProtocol.NodeAuthenticationScheme);
        if (!authentication.Succeeded || authentication.Principal is null)
        {
            return Results.Unauthorized();
        }

        var nodeValue = authentication.Principal.FindFirstValue(
            MagicControlMeshProtocol.NodeIdClaim);
        var credentialValue = authentication.Principal.FindFirstValue(
            MagicControlMeshProtocol.CredentialIdClaim);

        if (!Guid.TryParse(nodeValue, out var nodeId)
            || !Guid.TryParse(credentialValue, out var credentialId))
        {
            return Results.Forbid();
        }

        var decision = authorization.AuthorizeMember(
            manifest.GroupId,
            nodeId,
            credentialId);
        return decision.Allowed ? null : Results.Forbid();
    }
}
