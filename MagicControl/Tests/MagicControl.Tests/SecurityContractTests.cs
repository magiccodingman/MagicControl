using MagicControl.Shared.Security;

namespace MagicControl.Tests;

public sealed class SecurityContractTests
{
    [Fact]
    public void Role_attribute_uses_stable_policy_prefix()
    {
        var attribute = new RequireMagicControlRoleAttribute(
            MagicControlRoles.EnrollmentAdministrator);

        Assert.Equal(
            MagicControlSecurity.RolePolicyPrefix + MagicControlRoles.EnrollmentAdministrator,
            attribute.Policy);
    }

    [Fact]
    public void Group_and_application_role_policies_are_distinct()
    {
        var group = new RequireMagicGroupAttribute("Production");
        var role = new RequireMagicApplicationRoleAttribute("primary-api");

        Assert.NotEqual(group.Policy, role.Policy);
        Assert.StartsWith(MagicControlSecurity.GroupPolicyPrefix, group.Policy);
        Assert.StartsWith(MagicControlSecurity.ApplicationRolePolicyPrefix, role.Policy);
    }
}
