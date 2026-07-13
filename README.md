# AsterDriveMigration

Database migration tool for moving a Cloudreve v4 installation to AsterDrive (AD).

## Supported data

- Cloudreve groups to AD storage policy groups
- users and profiles, including quotas and disabled status
- local, S3, OSS, KS3, OBS and Tencent COS storage policies
- folders, files, physical entities/blobs and version history
- file metadata and public shares

Cloudreve password hashes are not compatible with AD. The migration assigns the supplied temporary password to every migrated user and sets `must_change_password = true`. Passkeys, WebDAV credentials, two-factor secrets, OAuth grants, sessions, tasks and filesystem events are not migrated.

The tool reuses existing storage objects. For local storage, pass the directory from which Cloudreve entity paths should be resolved. Object-storage policies keep their existing bucket, endpoint, credentials and object keys.

## Prerequisites

1. Stop writes to Cloudreve and back up both databases.
2. Create an empty AD database and run the AD database migrations against it.
3. Do not start the AD application against the target database until this migration completes.

## Check compatibility

```powershell
cargo run -- check `
  --source-url "sqlite://C:/cloudreve/cloudreve.db?mode=ro" `
  --target-url "sqlite://C:/asterdrive/asterdrive.db"
```

The URLs can also be provided through `CLOUDREVE_DATABASE_URL` and `ASTERDRIVE_DATABASE_URL`. SQLite, MySQL and PostgreSQL URLs supported by SeaORM can be used.

## Run migration

```powershell
$env:ASTER_MIGRATION_DEFAULT_PASSWORD = "replace-with-a-strong-temporary-password"

cargo run -- migrate `
  --source-url "sqlite://C:/cloudreve/cloudreve.db?mode=ro" `
  --target-url "sqlite://C:/asterdrive/asterdrive.db" `
  --local-base-path "C:/cloudreve"
```

Use `--dry-run` to perform preflight checks without writing the target. The target core tables must be empty by default. `--allow-non-empty-target` disables that guard but may still fail on unique values or conflicting data.

Cloudreve Qiniu, Upyun, remote-node, OneDrive and encrypted storage policies cannot be reused safely by AD. The migration stops when they are present. `--skip-unsupported-policies` explicitly omits those policies and all dependent files.
