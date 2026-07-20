using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using MagicControl.Shared.Mesh;
using MagicSettings.Server;
using MagicSettings.Share;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MagicControl.Client;

public sealed class MagicControlNodeAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> schemes,
    ILoggerFactory logger,
    UrlEncoder encoder,
    MagicNodeProofVerifier proofVerifier,
    IMagicControlAuthorizationService authorization)
    : AuthenticationHandler<AuthenticationSchemeOptions>(schemes, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authorizationHeader))
        {
            return AuthenticateResult.NoResult();
        }

        const string prefix = "MagicNode ";
        var header = authorizationHeader.ToString();
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        MagicAuthenticationProof proof;
        try
        {
            proof = MagicNodeProofCodec.Decode(header[prefix.Length..].Trim());
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            return AuthenticateResult.Fail("The MagicNode authorization proof is malformed.");
        }

        string bodyHash;
        try
        {
            bodyHash = await ComputeBodyHashAsync(Context.RequestAborted);
        }
        catch (InvalidDataException exception)
        {
            return AuthenticateResult.Fail(exception.Message);
        }

        var uri = new Uri(
            $"{Request.Scheme}://{Request.Host}{Request.PathBase}{Request.Path}{Request.QueryString}");
        var verification = await proofVerifier.VerifyAsync(
            new MagicProofVerificationRequest(
                proof,
                MagicControlMeshProtocol.MeshPeerAudience,
                Request.Method,
                uri,
                bodyHash,
                DateTimeOffset.UtcNow),
            Context.RequestAborted);

        if (!verification.IsValid)
        {
            return AuthenticateResult.Fail(verification.Error ?? "The MagicNode proof is invalid.");
        }

        var decision = authorization.AuthenticateCredential(
            proof.NodeId,
            proof.CredentialId);
        if (!decision.Allowed || decision.Member is null)
        {
            return AuthenticateResult.Fail(decision.Reason ?? "The caller is not authorized.");
        }

        var member = decision.Member;
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, member.ManagedInstanceId.ToString("D")),
            new(ClaimTypes.Name, member.DisplayName),
            new(MagicControlMeshProtocol.NodeIdClaim, member.NodeId.ToString("D")),
            new(MagicControlMeshProtocol.CredentialIdClaim, member.CredentialId.ToString("D"))
        };

        claims.AddRange(decision.GroupIds.Select(groupId =>
            new Claim(MagicControlMeshProtocol.GroupIdClaim, groupId.ToString("D"))));
        claims.AddRange(member.Roles.Select(role => new Claim(ClaimTypes.Role, role)));
        claims.AddRange(member.Capabilities.Select(capability =>
            new Claim(MagicControlMeshProtocol.CapabilityClaim, capability)));

        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(claims, MagicControlMeshProtocol.NodeAuthenticationScheme));
        return AuthenticateResult.Success(
            new AuthenticationTicket(principal, MagicControlMeshProtocol.NodeAuthenticationScheme));
    }

    private async ValueTask<string> ComputeBodyHashAsync(CancellationToken cancellationToken)
    {
        const long maximumBodyBytes = 4 * 1024 * 1024;
        if (Request.ContentLength is > maximumBodyBytes)
        {
            throw new InvalidDataException(
                "The authenticated request body exceeds the four-megabyte verification limit.");
        }

        Request.EnableBuffering();
        await using var buffer = new MemoryStream();
        await Request.Body.CopyToAsync(buffer, cancellationToken);
        Request.Body.Position = 0;

        if (buffer.Length > maximumBodyBytes)
        {
            throw new InvalidDataException(
                "The authenticated request body exceeds the four-megabyte verification limit.");
        }

        return Convert.ToHexString(SHA256.HashData(buffer.ToArray())).ToLowerInvariant();
    }
}

public static class MagicControlAuthorizationPolicies
{
    public const string Member = "MagicControl.Member";
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class RequireMagicControlMemberAttribute : AuthorizeAttribute
{
    public RequireMagicControlMemberAttribute()
    {
        AuthenticationSchemes = MagicControlMeshProtocol.NodeAuthenticationScheme;
        Policy = MagicControlAuthorizationPolicies.Member;
    }
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class RequireMagicControlCapabilityAttribute : AuthorizeAttribute
{
    public RequireMagicControlCapabilityAttribute(string capability)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(capability);
        AuthenticationSchemes = MagicControlMeshProtocol.NodeAuthenticationScheme;
        Policy = MagicControlMeshProtocol.CapabilityPolicyPrefix + capability;
    }
}

/// <summary>
/// Represents an endpoint that is open until a signed secured-group policy is accepted. Once
/// secured, it remains secured through outages, restarts, missing caches, and expired leases until
/// a validated authority manifest explicitly declares the group Open.
/// </summary>
public sealed record MagicControlAccessRequirement(string? Capability) : IAuthorizationRequirement;

public sealed class MagicControlAccessHandler(
    MagicControlManifestCache cache,
    MagicControlRuntimeSecurityState securityState)
    : AuthorizationHandler<MagicControlAccessRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MagicControlAccessRequirement requirement)
    {
        var states = cache.GetAll();
        var securedStates = states
            .Where(state => state.Manifest.SecurityMode == MagicControlGroupSecurityMode.Secured)
            .ToArray();

        // Before any authority has secured the application, MagicControl is additive. A signed
        // Open manifest also leaves these endpoints open. The persistent latch prevents absence
        // or corruption of the manifest cache from being interpreted as permission to reopen.
        if (!securityState.RequiresAuthorization && securedStates.Length == 0)
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        if (context.User.Identity?.IsAuthenticated != true)
        {
            return Task.CompletedTask;
        }

        var now = DateTimeOffset.UtcNow;
        var belongsToUsableSecuredGroup = securedStates.Any(state =>
            state.AllowsOfflineUse(now)
            && context.User.HasClaim(
                MagicControlMeshProtocol.GroupIdClaim,
                state.Manifest.GroupId.ToString("D")));
        if (!belongsToUsableSecuredGroup)
        {
            return Task.CompletedTask;
        }

        if (!string.IsNullOrWhiteSpace(requirement.Capability)
            && !context.User.HasClaim(
                MagicControlMeshProtocol.CapabilityClaim,
                requirement.Capability))
        {
            return Task.CompletedTask;
        }

        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}

public sealed class MagicControlCapabilityPolicyProvider(
    IOptions<AuthorizationOptions> options)
    : IAuthorizationPolicyProvider
{
    private readonly DefaultAuthorizationPolicyProvider _fallback = new(options);

    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (string.Equals(
                policyName,
                MagicControlAuthorizationPolicies.Member,
                StringComparison.Ordinal))
        {
            return Task.FromResult<AuthorizationPolicy?>(BuildPolicy(capability: null));
        }

        if (!policyName.StartsWith(
                MagicControlMeshProtocol.CapabilityPolicyPrefix,
                StringComparison.Ordinal))
        {
            return _fallback.GetPolicyAsync(policyName);
        }

        var capability = policyName[MagicControlMeshProtocol.CapabilityPolicyPrefix.Length..];
        return Task.FromResult<AuthorizationPolicy?>(BuildPolicy(capability));
    }

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
        => _fallback.GetDefaultPolicyAsync();

    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
        => _fallback.GetFallbackPolicyAsync();

    private static AuthorizationPolicy BuildPolicy(string? capability)
        => new AuthorizationPolicyBuilder(
                MagicControlMeshProtocol.NodeAuthenticationScheme)
            .AddRequirements(new MagicControlAccessRequirement(capability))
            .Build();
}
