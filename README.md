# MagicControl

MagicControl is a lightweight application control plane for managing users, application identities, Mesh API enrollment, service discovery, cached authorization, and MagicSettings configuration distribution.

## MagicControl.Client

`MagicControl.Client` is the application-side NuGet package. It initializes MagicSettings, maintains the application's MagicControl identity, discovers ordinary applications directly on the LAN, refreshes signed group manifests in the background, authorizes peer requests from local cached state, and resolves known service instances without placing the Mesh API in the request path.

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
        client.AdvertiseEndpoint("https://orders.local:7443", isLan: true);
    });

if (magicControl.ShouldExit)
{
    return;
}
```

A Mesh URL is optional. Before an application has accepted a signed Secured policy, MagicControl-protected endpoints remain open and direct LAN peers are available as identity-verified routes. Approval can switch the running application to secured behavior without a restart.

Once secured, the client writes a non-secret sticky security marker. Outages, missing manifests, expired leases, restarts, or corrupt ordinary cache files cannot reopen the application or restore identity-only routing. Only a successfully validated authority manifest explicitly publishing `Open` may clear that latch.

Applications can protect ASP.NET Core endpoints with `[RequireMagicControlMember]` or `[RequireMagicControlCapability("capability.name")]`. `IMagicControlAuthorizationService` is available for manual authorization, and `IMagicControlServiceResolver` combines signed directory entries with directly discovered application peers.

Offline trust is infinite by default. A secured group may instead configure a finite offline trust period from the MagicControl Web control pane; expiration remains fail-closed.

## Current foundation

- SQLite by default with optional PostgreSQL.
- First-run creation of a fixed `admin` primary account with no default password.
- Permanent protection against disabling or demoting the primary administrator.
- Cookie authentication, forced password changes, and local-only administrator recovery.
- User, role, enrollment, managed-instance, and group-policy administration.
- Signed application and Mesh API enrollment using MagicSettings node identities.
- Automatic Mesh discovery plus direct application-to-application LAN discovery.
- Signed multi-group manifests and encrypted last-known-good caches.
- Sticky open-to-secured runtime transitions that never downgrade during outages.
- Open directory discovery and secured-only distributed settings.
- Local cached peer authentication and capability authorization.
- Audit records and health checks.

MagicControl Web remains the durable control-plane authority. The Mesh API distributes and caches signed state but is not a required application traffic proxy.

See [`docs/client-platform.md`](docs/client-platform.md), [`docs/foundation.md`](docs/foundation.md), and [`docs/mesh-architecture.md`](docs/mesh-architecture.md) for setup, security, and architecture details.
