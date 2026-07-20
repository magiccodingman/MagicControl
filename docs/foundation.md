# Foundation architecture

## Runtime shape

MagicControl currently deploys as one ASP.NET Core Blazor Web App. The Web process owns:

- the administrative UI;
- REST controllers;
- authentication;
- Entity Framework Core;
- SQLite or PostgreSQL;
- enrollment review;
- MagicSettings proof verification.

`MagicControl.Shared` is the only reusable library introduced in the foundation. It contains stable role, claim, policy, attribute, and enrollment contracts. Database entities, cookie handlers, controllers, and UI implementation remain in the Web project.

## Configuration

MagicControl has no source-controlled `appsettings.json` or `appsettings.Development.json`. `AddMagicSettingsAsync` generates and maintains the single persistent configuration document at `state/appsettings.json`.

The initial template includes the ordinary ASP.NET Core host settings alongside MagicControl's own settings. Development starts with `Information` logging for ASP.NET Core and Entity Framework Core database commands. Every non-development environment starts those categories at `Warning`. General application logging remains at `Information`, and `AllowedHosts` defaults to `*`.

MagicSettings chooses those defaults when it first generates a settings document. After that, the persistent document is operator-owned and reconciliation preserves existing values. Environment variables, local providers, and future control-plane values can override the persistent values without creating separate environment-specific JSON files.

## First-run setup

A new database has no default administrator or password. Requests to the administrative UI are redirected to `/setup` until the first administrator is created.

The setup operation is transactional and inserts a fixed setup-complete record. Concurrent setup attempts cannot create multiple first administrators. Loopback setup requires no additional token. A setup submitted from another machine requires `Setup:RemoteSetupToken`, which should be supplied through a local environment override rather than committed configuration.

## Password handling

Passwords and temporary passwords are never stored in plaintext or reversible form. ASP.NET Core's password hasher stores only password hashes. Temporary passwords are generated with a cryptographic random-number generator, returned once, and immediately discarded by the server.

Password reset rotates the user's security stamp and invalidates existing sessions. Users created by an administrator and users recovered through the local recovery endpoint must replace their temporary password before normal access.

## Local administrator recovery

Recovery is disabled by default. When explicitly enabled, `POST /api/v1/recovery/reset-super-administrator`:

- accepts only loopback requests;
- requires `X-MagicControl-Recovery-Token`;
- works once per process;
- returns a newly generated temporary password once;
- stores only its password hash;
- forces password replacement;
- rotates the administrator security stamp.

The recovery token must be supplied through a local environment override or another protected local configuration source. Never place it in source control.

## Database providers

Set `Database:Provider` to `Sqlite` or `PostgreSql`.

SQLite is the zero-configuration default:

```json
{
  "Database": {
    "Provider": "Sqlite",
    "SqliteConnectionString": "Data Source=state/magic-control.db"
  }
}
```

PostgreSQL uses `Database:PostgreSqlConnectionString`. The schema uses provider-neutral migrations and GUID keys. If future features require provider-specific migration operations, provider-specific migration tracks can be split at that point rather than pre-creating extra projects now.

## Data protection and sensitive values

ASP.NET Core Data Protection protects authentication cookies. Its key ring is persisted beneath the configured state directory. MagicControl restricts that directory to the current user on Unix-like systems. Operators should also apply appropriate host filesystem ACLs and may add certificate-backed key encryption in a deployment-hardening pass.

Public node keys, certificates, and SHA-256 fingerprints are public identity material and may be stored in the database. Incoming private keys must never be accepted or stored.

Passwords are hashed. Future retrievable secrets will use a dedicated envelope-encryption service with a key-encryption key held outside the database; Data Protection is not the long-term database secret format.

## Enrollment

`POST /api/v1/enrollments` accepts a JSON `EnrollmentSubmission` and a MagicSettings `MagicNode` authorization proof.

The proof is verified against:

- the supplied public identity;
- audience `MagicControl.Enrollment`;
- HTTP method;
- exact request URI;
- complete request-body hash;
- proof lifetime;
- one-time nonce.

Valid unknown identities become pending requests. Invalid proofs never enter the review queue. The database-backed replay cache prevents nonce reuse across processes sharing the same database.

Application and Mesh requests share one review pipeline but have different validation and approval semantics. Mesh APIs are infrastructure participants and are never silently treated as ordinary application group members.

## Deferred intentionally

This foundation does not yet provide mDNS discovery, Mesh-to-Web polling, settings editing, secret distribution, signed membership grants, or app-to-app service resolution. The database and public contracts provide attachment points for those follow-up features without pretending their protocol is already final.
