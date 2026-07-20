namespace MagicControl.Shared.Security;

public static class MagicControlSecurity
{
    public const string UiCookieScheme = "MagicControl.UI";
    public const string NodeScheme = "MagicControl.Node";
    public const string BootstrapScheme = "MagicControl.Bootstrap";

    public const string EnrollmentAudience = "MagicControl.Enrollment";

    public const string RolePolicyPrefix = "MagicControl.Role:";
    public const string GroupPolicyPrefix = "MagicControl.Group:";
    public const string ApplicationRolePolicyPrefix = "MagicControl.ApplicationRole:";

    public static string RolePolicy(string role) => RolePolicyPrefix + role;
    public static string GroupPolicy(string group) => GroupPolicyPrefix + group;
    public static string ApplicationRolePolicy(string role) => ApplicationRolePolicyPrefix + role;

    public static string UserAdministrationPolicy => RolePolicy(MagicControlRoles.UserAdministrator);
    public static string EnrollmentAdministrationPolicy => RolePolicy(MagicControlRoles.EnrollmentAdministrator);
}

public static class MagicControlRoles
{
    public const string SuperAdministrator = "SuperAdministrator";
    public const string UserAdministrator = "UserAdministrator";
    public const string EnrollmentAdministrator = "EnrollmentAdministrator";
    public const string Viewer = "Viewer";

    public static readonly IReadOnlyList<string> BuiltIn =
    [
        SuperAdministrator,
        UserAdministrator,
        EnrollmentAdministrator,
        Viewer
    ];
}

public static class MagicControlClaimTypes
{
    public const string SecurityStamp = "magiccontrol:security_stamp";
    public const string MustChangePassword = "magiccontrol:must_change_password";
    public const string Group = "magiccontrol:group";
    public const string ApplicationRole = "magiccontrol:application_role";
    public const string InstanceId = "magiccontrol:instance_id";
    public const string InstanceKind = "magiccontrol:instance_kind";
}
