using System.Net.Http.Json;
using System.Security.Claims;
using MagicControl.Client;
using MagicControl.Shared.Mesh;
using MagicSettings.Share;
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

        endpoints.MapPost("/api/v1/nodes/sync", RelayNodeSyncAsync);
        endpoints.MapPost("/api/v1/nodes/secrets", RelaySecretAsync);

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

            var denied = await AuthorizeGroupAsync(
                context,
                state.Manifest,
                authorization,
                allowOpen: true);
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

            var denied = await AuthorizeGroupAsync(
                context,
                state.Manifest,
                authorization,
                allowOpen: true);
            if (denied is not null)
            {
                return denied;
            }

            var entries = string.IsNullOrWhiteSpace(applicationName)
                ? state.Manifest.Directory
                : authorization.ResolveAll(groupId, applicationName);
            return Results.Ok(entries);
        });

        return endpoints;
    }

    private static async ValueTask<IResult> RelayNodeSyncAsync(
        MagicControlNodeSyncRequest request,
        IHttpClientFactory httpClientFactory,
        MeshNodeSyncRepository nodeCache,
        MeshManifestRepository manifests,
        MagicControlMeshDiscoveryService discovery,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        var logger = loggerFactory.CreateLogger("MagicControl.Mesh.NodeSync");
        try
        {
            var client = httpClientFactory.CreateClient(MeshHttpClients.ControlPlane);
            using var response = await client.PostAsJsonAsync(
                "api/v1/nodes/sync",
                request,
                cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var detail = await response.Content.ReadAsStringAsync(cancellationToken);
                throw new HttpRequestException(
                    $"MagicControl Web returned HTTP {(int)response.StatusCode}: {detail}");
            }

            var body = await response.Content.ReadFromJsonAsync<MagicControlNodeSyncResponse>(
                           cancellationToken: cancellationToken)
                       ?? throw new InvalidDataException(
                           "MagicControl Web returned an empty node synchronization response.");
            var advertised = discovery.ResolveAdvertisedEndpoint();
            if (advertised is not null)
            {
                body = body with
                {
                    MeshEndpoints = body.MeshEndpoints
                        .Append(advertised)
                        .DistinctBy(
                            candidate => candidate.AbsoluteUri.TrimEnd('/'),
                            StringComparer.OrdinalIgnoreCase)
                        .ToArray()
                };
            }

            if (body.Manifest is not null
                && body.EnrollmentState == MagicControlEnrollmentState.Approved)
            {
                await manifests.AcceptAuthoritativeAsync(
                    body.Manifest,
                    DateTimeOffset.UtcNow,
                    cancellationToken);
                await nodeCache.SaveAsync(request, body, cancellationToken);
            }

            return Results.Ok(body);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            var cached = await nodeCache.LoadAsync(request, cancellationToken);
            if (cached is not null)
            {
                logger.LogWarning(
                    exception,
                    "MagicControl Web is unavailable; returning cached approved node state.");
                return Results.Ok(cached);
            }

            logger.LogWarning(
                exception,
                "MagicControl Web is unavailable and no approved node cache exists.");
            return Results.Problem(
                "MagicControl Web is unavailable. Existing approved nodes may use cached state, but new enrollment and uncached settings require the authority.",
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static async ValueTask<IResult> RelaySecretAsync(
        MagicControlNodeSecretRequest request,
        IHttpClientFactory httpClientFactory,
        CancellationToken cancellationToken)
    {
        try
        {
            var client = httpClientFactory.CreateClient(MeshHttpClients.ControlPlane);
            using var response = await client.PostAsJsonAsync(
                "api/v1/nodes/secrets",
                request,
                cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return Results.StatusCode((int)response.StatusCode);
            }

            var body = await response.Content.ReadFromJsonAsync<MagicSecretResponse>(
                cancellationToken: cancellationToken);
            return body is null
                ? Results.Problem(
                    "MagicControl Web returned an empty secret response.",
                    statusCode: StatusCodes.Status502BadGateway)
                : Results.Ok(body);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return Results.Problem(
                "Live-only secrets require an online MagicControl authority.",
                statusCode: StatusCodes.Status503ServiceUnavailable,
                extensions: new Dictionary<string, object?>
                {
                    ["reason"] = exception.Message
                });
        }
    }

    private static async ValueTask<IResult?> AuthorizeGroupAsync(
        HttpContext context,
        MagicControlGroupManifest manifest,
        IMagicControlAuthorizationService authorization,
        bool allowOpen)
    {
        if (manifest.SecurityMode == MagicControlGroupSecurityMode.Open)
        {
            return allowOpen
                ? null
                : Results.Problem(
                    "MagicControl-distributed settings require a Secured group.",
                    statusCode: StatusCodes.Status409Conflict);
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
