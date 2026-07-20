# MagicControl

MagicControl is an application control plane for MagicSettings configuration, node enrollment, local authorization, service discovery, and outage-tolerant application-to-application communication.

MagicControl Web is the durable authority. Mesh APIs discover and cache authority state near applications. `MagicControl.Client` integrates directly into applications while keeping ordinary application traffic peer-to-peer rather than proxying it through Mesh.

## Application quick start

Install the client package:

```bash
dotnet add package MagicControl.Client
```

Register MagicSettings and MagicControl together:

```csharp
var builder = WebApplication.CreateBuilder(args);

var magic = await builder.AddMagicControlClientAsync<AppSettings>(
    args,
    configureSettings: settings =>
    {
        settings.Template = AppSettings.CreateDefaults();
        settings.SchemaVersion = 4;
    },
    configureClient: client =>
    {
        client.GroupId = GroupIds.Primary;
        client.ApplicationName = "Orders";

        client.RequestedCapabilities.Add("orders.read");
        client.AdvertiseEndpoint(
            "https://orders.internal.example:7443",
            isLan: true);
    });

if (magic.ShouldExit)
{
    return;
}
```

`GroupId` and `ApplicationName` are the durable application identity facts and are intentionally configured in code. A Mesh URL is **not** normally required.

## SDK-only local mode

`MagicControl.Client` remains useful when no MagicControl Web or Mesh deployment exists.

- MagicSettings generates and maintains the local settings document normally.
- Local environment variables and custom providers continue working.
- The client performs opportunistic Mesh discovery without making platform availability a startup requirement.
- When no approved cached state and no Mesh are available, the application reports local-only status and continues normally.

Use `RequireApprovedState` only for applications that must refuse startup without previously approved MagicControl state.

## Automatic discovery and endpoint overrides

On ordinary IPv4 LANs, Mesh APIs advertise themselves through the built-in multicast discovery protocol. Clients combine:

1. explicit endpoint seeds or overrides;
2. previously validated Mesh endpoints stored in the encrypted client state;
3. live LAN discovery results.

An explicit URL is primarily for routed networks, restricted multicast environments, public domains, or testing:

```csharp
client.AddMeshEndpointOverride("https://control.example.com");
```

It supplements discovery rather than disabling it.

## Secured enrollment

For a secured group, first startup works without a manually pasted authority key:

1. MagicSettings creates or loads the application's persistent node identity.
2. The client discovers Mesh and submits a proof-bound enrollment/synchronization request.
3. MagicControl Web displays the node fingerprint, pairing code, configured group, application schema, and requested capabilities.
4. An enrollment administrator approves that exact credential and nonce.
5. The running application automatically receives the initial signed group manifest, installs the Web authority pin, receives its node-specific settings snapshot, and begins normal refresh.

Discovery identifies candidates; it does not establish trust. Administrator approval of the proof-bound request establishes the first authority relationship.

MagicSettings credential rotation preserves the logical node and approval through its continuity proof. A destructive identity reset creates a new node and requires approval again.

## MagicSettings ownership and remote overrides

The application remains the owner of:

- its strongly typed settings classes;
- defaults and generated persistent JSON;
- schema version and migrations;
- sensitive-path declarations;
- whether a path allows remote override.

During synchronization, the client sends the real MagicSettings schema manifest and migration-review report. Web stores that metadata for administration but does not edit or migrate the application's local file.

The **Application settings** control-pane page supports scoped overrides:

1. application defaults;
2. site overrides;
3. instance-role overrides;
4. individual instance overrides.

The most specific matching scope wins. MagicSettings applies the resulting node-specific snapshot as its highest-priority in-memory provider. Remote values are never written into the application's persistent `appsettings.json`.

Paths marked `RemoteOverrideAllowed = false` are rejected by Web. Paths marked sensitive are always treated as live-only secrets.

## Offline settings and secrets

Ordinary remote values may be marked for encrypted offline persistence. The approved node snapshot is cached by Mesh and Client and remains usable according to the group's offline trust policy.

Secrets are different:

- they are not included in the signed group manifest;
- they are not included in Mesh or Client disk caches;
- they are fetched explicitly through `IMagicSecretProvider`;
- the request proof is bound to the exact node, secret name, audience, method, and logical endpoint;
- live secret retrieval requires an online MagicControl authority.

```csharp
var secrets = app.Services.GetRequiredService<IMagicSecretProvider>();
await using var password = await secrets.GetAsync<string>("Database:Password");
```

## Local authorization

Approved applications authenticate peer requests with fresh MagicNode proofs. Receiving APIs verify them from signed cached group state without calling Web or Mesh in the request path.

```csharp
[RequireMagicControlMember]
[HttpGet("status")]
public IActionResult Status() => Ok();

[RequireMagicControlCapability("orders.write")]
[HttpPost("orders")]
public IActionResult CreateOrder() => Ok();
```

`IMagicControlAuthorizationService` remains available for manual checks and complete directory lookup.

## Service discovery and routing

Applications announce their reachable endpoints during node synchronization. The signed directory includes endpoint priority, loopback/LAN classification, sequence, observation time, and expiration.

`IMagicControlServiceResolver` provides normal route selection:

```csharp
var target = resolver.Resolve("Inventory");
if (target is null)
{
    // No trusted live instance is currently known.
}
```

Route preference is loopback, LAN, private routed address, then public address. Applications may report failures so an endpoint is temporarily quarantined and another trusted instance can be selected. Round-robin selection is optional. `ResolveAll` remains available when the caller needs complete policy control.

## Outage behavior

- Web owns approval, settings publication, revocation, and signatures.
- Mesh caches signed manifests and approved offline-safe node snapshots.
- Clients keep encrypted last-known-good authorization and permitted settings.
- Existing approved applications continue communicating directly when Web is unavailable.
- Existing approved applications can recover cached state through Mesh when Web is unavailable.
- New enrollment and live-only secret retrieval require Web.
- A finite group offline lease expires from the authority-signed manifest issue time; reaching a stale Mesh cannot extend it.
- Infinite offline trust remains the default for availability-first installations.

## Deployable components

- **MagicControl Web** — administrative control pane and durable authority.
- **MagicControl Mesh** — LAN discovery, Web relay, signed-state distribution, and outage cache.
- **MagicControl.Client** — application SDK for MagicSettings integration, enrollment, cached authorization, discovery, routing, and endpoint announcements.

Web supports SQLite by default and optional PostgreSQL. It includes first-run administrator setup, protected primary-administrator semantics, users and roles, enrollment review, groups, managed instances, application settings, audit records, and health checks.

See [`docs/foundation.md`](docs/foundation.md) and [`docs/mesh-architecture.md`](docs/mesh-architecture.md) for the detailed security and ownership boundaries.
