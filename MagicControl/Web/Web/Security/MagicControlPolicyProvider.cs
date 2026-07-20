using MagicControl.Shared.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace MagicControl.Web.Security;

public sealed class MagicControlPolicyProvider(IOptions<AuthorizationOptions> options)
    : DefaultAuthorizationPolicyProvider(options)
{
    public override Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (policyName.StartsWith(MagicControlSecurity.RolePolicyPrefix, StringComparison.Ordinal))
        {
            var role = policyName[MagicControlSecurity.RolePolicyPrefix.Length..];
            return Task.FromResult<AuthorizationPolicy?>(
                new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .RequireAssertion(context =>
                        context.User.IsInRole(MagicControlRoles.SuperAdministrator)
                        || context.User.IsInRole(role))
                    .Build());
        }

        if (policyName.StartsWith(MagicControlSecurity.GroupPolicyPrefix, StringComparison.Ordinal))
        {
            var group = policyName[MagicControlSecurity.GroupPolicyPrefix.Length..];
            return Task.FromResult<AuthorizationPolicy?>(
                new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .RequireAssertion(context =>
                        context.User.IsInRole(MagicControlRoles.SuperAdministrator)
                        || context.User.HasClaim(MagicControlClaimTypes.Group, group))
                    .Build());
        }

        if (policyName.StartsWith(MagicControlSecurity.ApplicationRolePolicyPrefix, StringComparison.Ordinal))
        {
            var applicationRole = policyName[MagicControlSecurity.ApplicationRolePolicyPrefix.Length..];
            return Task.FromResult<AuthorizationPolicy?>(
                new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .RequireAssertion(context =>
                        context.User.IsInRole(MagicControlRoles.SuperAdministrator)
                        || context.User.HasClaim(MagicControlClaimTypes.ApplicationRole, applicationRole))
                    .Build());
        }

        return base.GetPolicyAsync(policyName);
    }
}
