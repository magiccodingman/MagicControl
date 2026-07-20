# MagicControl

MagicControl is a lightweight application control plane for managing users, application identities, Mesh API enrollment, service discovery, cached authorization, and MagicSettings configuration distribution.

## MagicControl.Client

`MagicControl.Client` is the application-side NuGet package. It initializes MagicSettings, maintains the application's MagicControl identity, refreshes signed group manifests in the background, authorizes peer requests from local cached state, and resolves known service instances without placing the Mesh API in the request path.

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
        settings.ApplicationId = "Orders";
        settings.Template = new MyApplicationSettings();
    },
    configureClient: client =>
    {
        client.GroupId = Guid.Parse("00000000-0000-0000-0000-000000000000");
        client.ApplicationName = "Orders";
        client.AddMeshEndpoint("https://magic-control-mesh.example.local");
    });

if (magicControl.ShouldExit)
{
    return;
}
```

Applications can protect ASP.NET Core endpoints with `[RequireMagicControlMember]` or `[RequireMagicControlCapability("capability.name")]`. `IMagicControlAuthorizationService` is available for manual authorization and directory resolution.

Offline trust is infinite by default. A secured group may instead configure a finite offline trust period from the MagicControl Web control pane.

## Current foundation

- SQLite by default with optional PostgreSQL.
- First-run creation of a fixed `admin` primary account with no default password.
- Permanent protection against disabling or demoting the primary administrator.
- Cookie authentication, forced password changes, and local-only administrator recovery.
- User, role, enrollment, managed-instance, and group-policy administration.
- Signed application and Mesh API enrollment using MagicSettings node identities.
- Signed multi-group manifests and encrypted last-known-good caches.
- Open directory discovery and secured-only distributed settings.
- Local cached peer authentication and capability authorization.
- Audit records and health checks.

MagicControl Web remains the durable control-plane authority. The Mesh API distributes and caches signed state but is not a required application traffic proxy.

See [`docs/foundation.md`](docs/foundation.md) and [`docs/mesh-architecture.md`](docs/mesh-architecture.md) for setup, security, and architecture details.
