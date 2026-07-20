# MagicConnect and Mesh architecture

## Authority and availability

MagicControl Web is the durable control-plane authority. A Mesh API is a preferred distributor of signed group state, not a required data proxy. Applications communicate directly and use `MagicControl.Client` to cache the last signed authority manifest, authenticate peers locally, and resolve every matching service instance.

The authority order is:

1. MagicControl Web owns group membership, security mode, settings, and revocation state.
2. Approved Mesh APIs retrieve signed manifests from Web with MagicNode proof-of-possession authentication.
3. Clients retrieve those manifests from Mesh and perform request-time authorization entirely in process.
4. During outages, clients and Mesh continue using the last valid signed manifest according to the group's offline trust policy.

## Offline trust

Offline trust is infinite by default. A null `MaximumOfflineSeconds` means that a valid signed manifest remains usable until a newer authority manifest replaces it. This favors homelab and availability-oriented installations where an unnoticed control-plane outage must not eventually stop unrelated applications.

Administrators may configure a finite offline duration per group from the Groups page. Finite leases trade availability for faster eventual enforcement of revocations made while a node is disconnected. The lease is anchored to the authority-signed manifest issue time; repeatedly reaching a Mesh that is itself offline from Web cannot extend the lease.

The last-known-good manifest is retained even while Web and Mesh are healthy. Refresh replaces it atomically; successful reconnection does not delete the fallback required by a later outage or restart.

Client and Mesh manifest caches are encrypted at rest with ASP.NET Core Data Protection and additionally restricted to the current Unix account. The authority signature is still verified after decryption. Settings marked as non-persistable are rejected from the fallback manifest and must use a future live-only settings channel.

## Open and secured groups

A group has one security mode:

- `Open`: directory and manifest discovery may be read without membership authentication. MagicNode identities may still be used for continuity. MagicControl-distributed settings are unavailable.
- `Secured`: every caller must present a fresh MagicNode request proof whose credential exists in the cached signed manifest for that group. Distributed settings are available only in this mode.

Changing security mode rotates the group security epoch and advances the manifest revision. The control pane permits switching a secured group back to open only after an explicit warning acknowledgment because admission control is removed.

## Request authentication

`MagicControl.Client` uses the MagicSettings node identity for outbound proof-of-possession authentication. Inbound ASP.NET Core requests use the `MagicControl.Node` authentication scheme.

The handler verifies locally:

- proof audience, method, URI, body hash, lifetime, and nonce;
- ECDSA signature;
- cached credential status;
- signed group membership;
- optional capability requirements.

No Web or Mesh HTTP request occurs during controller authorization. Background refresh is allowed to lag revocation briefly according to refresh timing and offline policy.

Applications may use:

- `[RequireMagicControlMember]` for an approved caller;
- `[RequireMagicControlCapability("capability.name")]` for a cached capability;
- `IMagicControlAuthorizationService` for manual authorization and directory resolution.

## Duplicate application names

Directory lookup returns every matching instance. The low-level resolver never silently selects one instance when several applications share a name. Higher-level routing policies may later select loopback-first, LAN-first, round-robin, sticky, same-site, or lowest-latency candidates.

## MagicSettings startup

`AddMagicControlClientAsync<TSettings>` is the preferred application registration. It initializes MagicSettings first, establishes the persistent node identity, and then registers MagicControl caching, background refresh, inbound authentication, and local authorization. This avoids relying on incidental hosted-service registration order.

The signed manifest already reserves an offline-safe settings snapshot. The initial Mesh slice transports, encrypts, and persists that snapshot. Applying those values to MagicSettings' remote provider and delivering non-persistable live settings are the next settings layer.

## Current first slice

Implemented:

- signed group manifests using a persisted MagicControl Web authority key;
- authenticated Web-to-Mesh synchronization;
- multi-group Mesh caching and outage operation;
- infinite offline trust by default and optional finite group leases;
- authority-time lease enforcement and manifest rollback prevention;
- encrypted client and Mesh last-known-good caches;
- open directory discovery and secured-only settings endpoints;
- control-pane group security and offline trust configuration;
- explicit warning acknowledgment when downgrading Secured to Open;
- NuGet-ready `MagicControl.Client` project;
- local ASP.NET Core node authentication and capability authorization;
- duplicate-preserving directory resolution;
- one-call MagicSettings plus MagicControl registration.

Still intentionally deferred:

- mDNS/DNS-SD discovery and endpoint announcements;
- peer anti-entropy and signed endpoint-record relaying;
- enrollment delivery of the authority pin and initial secured manifest;
- applying remote settings snapshots into MagicSettings;
- live-only delivery of non-persistable settings;
- advanced endpoint health scoring and load-balancing policies.
