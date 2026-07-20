using MagicControl.Shared.Security;
using MagicControl.Web.Data.Entities;
using MagicControl.Web.Features.Authentication;
using MagicControl.Web.Features.Common;
using MagicControl.Web.Features.Enrollments;
using MagicControl.Web.Features.Recovery;
using MagicControl.Web.Features.Setup;
using MagicControl.Web.Features.Users;
using MagicSettings.Server;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace MagicControl.Web.Security;

public static class SecurityServiceExtensions
{
    public static IServiceCollection AddMagicControlSecurity(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddScoped<IPasswordHasher<ControlUser>, PasswordHasher<ControlUser>>();
        services.AddScoped<MagicControlCookieEvents>();

        services.AddAuthentication(MagicControlSecurity.UiCookieScheme)
            .AddCookie(MagicControlSecurity.UiCookieScheme, options =>
            {
                options.Cookie.Name = "__Host-MagicControl";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.LoginPath = "/login";
                options.AccessDeniedPath = "/access-denied";
                options.SlidingExpiration = true;
                options.ExpireTimeSpan = TimeSpan.FromHours(
                    Math.Max(1, configuration.GetValue("Security:CookieLifetimeHours", 12)));
                options.EventsType = typeof(MagicControlCookieEvents);
            });

        services.AddAuthorization(options =>
        {
            options.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
        });

        services.AddSingleton<IAuthorizationPolicyProvider, MagicControlPolicyProvider>();

        services.AddScoped<SetupService>();
        services.AddScoped<ISetupState>(sp => sp.GetRequiredService<SetupService>());
        services.AddScoped<UserAuthenticationService>();
        services.AddScoped<UserAdministrationService>();
        services.AddScoped<EnrollmentService>();
        services.AddScoped<RecoveryService>();
        services.AddScoped<AuditService>();
        services.AddSingleton<TemporaryPasswordGenerator>();

        services.AddScoped<IMagicCredentialRegistry, EfMagicCredentialRegistry>();
        services.AddScoped<IMagicReplayCache, EfMagicReplayCache>();
        services.AddScoped<MagicNodeProofVerifier>();

        return services;
    }
}
