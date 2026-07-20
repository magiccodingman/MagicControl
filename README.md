# MagicControl

MagicControl is a lightweight application control plane for managing users, application identities, Mesh API enrollment, and future MagicSettings configuration distribution.

## Current foundation

The first foundation includes:

- SQLite by default with optional PostgreSQL.
- MagicSettings-backed local configuration with generated environment-appropriate logging defaults.
- First-run creation of a fixed `admin` primary account with no default password.
- Permanent protection against disabling or demoting the primary administrator.
- Cookie authentication, forced password changes, and local-only administrator recovery.
- User and role administration.
- Cryptographically signed enrollment requests using MagicSettings node identities.
- Separate enrollment handling for application instances and Mesh APIs.
- Managed instance and public credential records.
- Audit records and health checks.

The Web application remains the deployable unit. `MagicControl.Shared` contains only stable contracts and authorization vocabulary intended for reuse by future Mesh and client packages.

See [`docs/foundation.md`](docs/foundation.md) for setup and security details.
