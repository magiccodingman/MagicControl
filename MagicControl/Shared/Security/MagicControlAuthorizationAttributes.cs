using Microsoft.AspNetCore.Authorization;

namespace MagicControl.Shared.Security;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class RequireMagicControlRoleAttribute : Attribute, IAuthorizeData
{
    public RequireMagicControlRoleAttribute(string role)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(role);
        Policy = MagicControlSecurity.RolePolicyPrefix + role;
    }

    public string? Policy { get; set; }
    public string? Roles { get; set; }
    public string? AuthenticationSchemes { get; set; }
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class RequireMagicGroupAttribute : Attribute, IAuthorizeData
{
    public RequireMagicGroupAttribute(string group)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(group);
        Policy = MagicControlSecurity.GroupPolicyPrefix + group;
    }

    public string? Policy { get; set; }
    public string? Roles { get; set; }
    public string? AuthenticationSchemes { get; set; }
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class RequireMagicApplicationRoleAttribute : Attribute, IAuthorizeData
{
    public RequireMagicApplicationRoleAttribute(string applicationRole)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationRole);
        Policy = MagicControlSecurity.ApplicationRolePolicyPrefix + applicationRole;
    }

    public string? Policy { get; set; }
    public string? Roles { get; set; }
    public string? AuthenticationSchemes { get; set; }
}
