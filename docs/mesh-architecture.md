# MagicConnect and Mesh architecture

## Authority and availability

MagicControl Web is the durable authority. Mesh APIs are nearby discovery, relay, distribution, and outage-cache nodes. They do not become an authority and they are not application traffic proxies.

Applications communicate directly and use `MagicControl.Client` to:

- initialize MagicSettings and preserve local-only operation;
- discover Mesh APIs;
- establish secured enrollment after administrator approval;
- cache signed authorization state and offline-safe settings;
- authenticate peers locally;
- advertise service endpoints;
- resolve and select trusted application instances.

The authority order is:

1. MagicControl Web owns group membership, approved credentials, capabilities, settings publication, security epochs, and revocation state.
2. Approved Mesh APIs retrieve signed manifests from Web and relay proof-bound node synchronization.
3. Clients verify signed manifests and perform request-time authorization entirely in process.
4. During outages, clients and Mesh continue using last-known-good approved state according to the authority-signed offline policy.

## SDK-only local operation

MagicControl connectivity is additive. `AddMagicControlClientAsync<TSettings>` always initializes the ordinary MagicSettings local document, migrations, environment variables, providers, and node identity.

If no Mesh endpoint is discovered and no approved cache exists, synchronization returns `Disconnected`, the remote layer remains empty, and the application continues using local MagicSettings. This is normal SDK-only mode rather than a startup fault.

Applications may choose stricter startup behavior:

- `CachedFirst` starts from local or cached state and refreshes in the background;
- `PreferConnected` attempts a connected refresh before startup completes but tolerates local/offline operation;
- `RequireApprovedState` requires either a fresh approval or valid approved cached state.

## Mesh discovery

The normal LAN path does not require a configured Mesh URL. Mesh advertises a reachable endpoint using MagicControl's versioned IPv4 multicast discovery protocol. Clients send a short discovery query and merge the responses with:

1. explicit endpoint seeds or overrides;
2. previously validated Mesh endpoints stored in encrypted client state;
3. current LAN advertisements.

Explicit endpoints are for routed networks, multicast restrictions, public domains, or tests. They supplement discovery rather than disabling it.

Discovery is not trust. An untrusted responder is only a candidate transport. Secured state is accepted only after proof-bound approval and authority-signature validation.

## Secured bootstrap and authority pinning

A newly generated credential cannot fetch an ordinary secured group manifest because it is not yet a member. MagicControl therefore has a dedicated bootstrap synchronization channel.

1. MagicSettings creates or loads an ECDSA P-256 node identity.
2. The client sends its identity, request-bound proof, configured `GroupId`, `ApplicationName`, bootstrap nonce, requested capabilities, schema manifest, migration report, and endpoint announcements.
3. Web verifies proof possession against the submitted public identity and creates or updates one pending request.
4. The control pane displays the node fingerprint and a pairing code derived from the nonce, fingerprint, and group.
5. Administrator approval attaches the credential to the exact configured group and approves the displayed capability requests.
6. The same credential and nonce poll the bootstrap channel.
7. Web returns the initial signed manifest and node-specific settings snapshot.
8. Client verifies that the manifest contains its exact credential, persists the Web authority key, stores the manifest, and transitions to approved operation.

After pinning, a different authority key is rejected. `AllowAuthorityTrustOnFirstUse` remains only as an explicit unsafe compatibility escape hatch; normal secured enrollment does not require it.

MagicSettings credential rotation carries an identity continuity proof. Web verifies the previous approved credential, marks it retiring, attaches the new approved credential to the same managed instance, and advances the group manifest revision. A destructive identity reset has no continuity claim and must be approved as a new node.

## MagicSettings synchronization

MagicControl uses MagicSettings' actual control-plane contracts rather than a parallel configuration model:

- `MagicSettingsSyncRequest` carries identity, proof, schema, last revision, migration report, and optional continuity proof;
- `MagicSettingsSyncResponse` returns the complete node-specific `MagicRemoteSnapshot`;
- MagicSettings applies that snapshot as its highest-priority in-memory provider;
- remote values are never serialized into the client's persistent JSON file.

MagicControl uses a logical proof target under `https://magiccontrol.local/groups/{groupId}/`. The custom client transport sends the signed request through whichever validated Mesh endpoint is currently available. This keeps proof binding stable across route changes and prevents a discovered endpoint from redefining the authority relationship.

## Schema ownership and Web overrides

The application owns its schema, defaults, migrations, sensitivity declarations, and `RemoteOverrideAllowed` decisions. Web stores the reported `MagicSettingsSchemaManifest` and migration-review items for administration but never rewrites the client's local document.

Remote overrides are scoped and merged per node in this order:

1. application;
2. site;
3. instance role;
4. individual managed instance.

The most specific matching value wins. Saving or deleting an override increments the application's settings revision and is audited.

A path with `RemoteOverrideAllowed = false` cannot be overridden. Sensitive paths are always treated as live-only secrets, regardless of the administrator's offline checkbox.

## Offline settings and secrets

The group authorization manifest and node settings are deliberately separate:

- the signed group manifest is shared authorization and directory state;
- the MagicSettings snapshot is specific to one approved application instance.

Web computes both a full effective snapshot and an offline-safe subset. Mesh stores only the offline-safe subset in its encrypted node cache. Client stores the same subset in encrypted local state. During an authority outage, approved nodes receive or load that subset while MagicSettings preserves lower local layers for omitted paths.

Secrets never enter group manifests, node disk caches, logs, or the persistent client settings file. `IMagicSecretProvider` creates a fresh request bound to the exact secret name and logical target. Web verifies the approved credential and returns the protected scoped secret only while online. Mesh relays secret requests but never caches their values.

## Offline trust

Offline trust is infinite by default. A null `MaximumOfflineSeconds` means that a valid signed manifest remains usable until a newer authority manifest replaces it. This favors homelab and availability-oriented installations where an unnoticed control-plane outage must not eventually stop unrelated applications.

Administrators may configure a finite duration per group. The lease is anchored to the authority-signed manifest issue time. Repeatedly contacting an offline Mesh cannot extend the lease.

Client and Mesh cache files are encrypted with ASP.NET Core Data Protection and restricted to the current Unix account. Authority signatures and membership are revalidated after decryption.

## Open and secured groups

A group has one security mode:

- `Open`: directory and manifest discovery may be read without membership authentication. MagicControl-distributed settings are unavailable.
- `Secured`: callers use approved MagicNode credentials. Node-specific settings and secrets are available only after approval.

Changing security mode rotates the group security epoch and advances the manifest revision. The control pane requires explicit warning acknowledgment before removing admission control by changing Secured to Open.

## Request authentication

`MagicControl.Client` uses the MagicSettings node identity for outbound proof-of-possession authentication. Inbound ASP.NET Core requests use the `MagicControl.Node` authentication scheme.

The handler verifies locally:

- proof audience, method, normalized URI, body hash, lifetime, and nonce;
- ECDSA signature;
- cached credential status;
- signed group membership;
- optional capability requirements.

No Web or Mesh request occurs during controller authorization. Applications may use:

- `[RequireMagicControlMember]`;
- `[RequireMagicControlCapability("capability.name")]`;
- `IMagicControlAuthorizationService` for manual authorization;
- `IMagicControlServiceResolver` for route selection.

## Endpoint announcements and routing

Approved applications include signed endpoint announcements in normal synchronization. Web records endpoint priority, transport, loopback/LAN classification, sequence, and last-seen time. The signed directory gives records a finite expiration so crashed or disconnected instances age out.

The high-level resolver prefers:

1. loopback;
2. LAN;
3. private routed addresses;
4. public addresses.

It then applies configured priority and stable instance ordering. Round-robin is optional. Applications can report route failures to quarantine an endpoint temporarily. `ResolveAll` remains available for custom policies and always preserves duplicate application instances.

## Mesh outage cache

Mesh relays node synchronization to Web while the authority is available. For approved responses it stores:

- the signed group manifest;
- the node's offline-safe MagicSettings snapshot;
- known Mesh endpoint information.

When Web is unavailable, Mesh may return that cached approved state only if:

- the manifest signature is valid;
- the exact node and credential are members;
- the group offline trust lease still permits use.

Pending enrollment, a new node, uncached settings, and live-only secrets require Web.

## Final security boundaries

- Mesh discovery identifies routes, never trust.
- Administrator approval establishes the first secured authority relationship.
- Web alone signs authoritative group state and publishes settings revisions.
- Applications own their local schema and migrations.
- Remote snapshots are complete replacement layers; omitted paths reveal lower MagicSettings providers.
- Secrets are explicit, asynchronous, live-only values.
- Direct application traffic remains peer-to-peer and is locally authorized from signed cached state.
