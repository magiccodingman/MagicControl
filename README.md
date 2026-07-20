# MagicControl

MagicControl is a lightweight application control plane for managing users, application identities, Mesh API enrollment, service discovery, cached authorization, and MagicSettings configuration distribution.

## MagicControl.Client

`MagicControl.Client` is the application-side NuGet package. It initializes MagicSettings, maintains the application's MagicControl identity, discovers ordinary applications directly, refreshes signed group manifests when a control plane is available, authorizes peer requests from local cached state, and resolves service instances without placing Mesh in the application request path.

Install the package:

```bash
dotnet add package MagicControl.Client
```

Register MagicSettings and MagicControl together during startup:

```csharp
var magicControl = await builder.AddMagicControlClientAsync<MyApplicationSettings>(
    args,
    configureSettings: settings =>
    {
        settings.Template = new MyApplicationSettings();
    },
    configureClient: client =>
    {
        client.GroupId = Guid.Parse("00000000-0000-0000-0000-000000000000");
        client.ApplicationName = "Orders";
        client.AdvertiseEndpoint(
            "https://orders.internal.example:7443",
            isLan: true);
    });

if (magicControl.ShouldExit)
{
    return;
}
```

`GroupId` and `ApplicationName` are intentionally configured. Mesh endpoints are discovered automatically on ordinary LANs; `AddMeshEndpointOverride(...)` is available only when a routed or multicast-restricted environment needs an explicit seed.

Even with no MagicControl Web deployment, no Mesh API, and no cached signed directory, applications can discover one another through identity-signed direct peer advertisements. Resolver results expose whether a route is merely `IdentityVerified` or is `AuthorityApproved` by a secured cached manifest.

Applications can protect ASP.NET Core endpoints with `[RequireMagicControlMember]` or `[RequireMagicControlCapability("capability.name")]`. Direct discovery never grants these authority-backed permissions. `IMagicControlAuthorizationService` is available for manual authorization, and `IMagicControlServiceResolver` handles signed-directory and direct-peer route selection.

Offline trust is infinite by default. A secured group may instead configure a finite offline trust period from the MagicControl Web control pane.

## Current foundation

- SQLite by default with optional PostgreSQL.
- First-run creation of a fixed `admin` primary account with no default password.
- Permanent protection against disabling or demoting the primary administrator.
- Cookie authentication, forced password changes, and local-only administrator recovery.
- User, role, enrollment, managed-instance, and group-policy administration.
- Signed application and Mesh API enrollment using MagicSettings node identities.
- Direct identity-signed application discovery without Web or Mesh.
- Signed multi-group manifests and encrypted last-known-good caches.
- Open directory discovery and secured-only distributed settings.
- Local cached peer authentication and capability authorization.
- Audit records and health checks.

MagicControl Web remains the durable control-plane authority. Mesh distributes and caches signed state but is not a required application traffic proxy or a prerequisite for ordinary direct LAN discovery.

See [`docs/client-platform.md`](docs/client-platform.md), [`docs/foundation.md`](docs/foundation.md), and [`docs/mesh-architecture.md`](docs/mesh-architecture.md) for setup, security, and architecture details.
