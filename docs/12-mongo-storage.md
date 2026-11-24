# 12 — MongoDB storage (Beanie)

`tenantkit.storage.beanie` is an optional storage adapter for MongoDB built on **Beanie 2.x** (the PyMongo async client). Install it with `pip install tenantkit[mongo]`. It passes the same contract suite as the in-memory and SQLAlchemy adapters.

## Purpose and responsibilities

- Implement the `Storage` protocol (including sessions, audit events and `in_transaction()`) on MongoDB.
- Keep Beanie documents internal: repositories map them to and from the domain dataclasses.
- Leave client creation and `init_beanie` to the host.

Requires MongoDB 6.0+ running as a **replica set** or behind **mongos**, because multi-step operations use transactions. Beanie 2.x only; Motor and MongoEngine are not supported.

## Host integration

```python
from pymongo import AsyncMongoClient
from beanie import init_beanie
from tenantkit.storage.beanie import BeanieStorage, document_models

client = AsyncMongoClient(MONGO_URL, uuidRepresentation="standard", tz_aware=True)
db = client["app"]

tk_models = document_models(prefix="mt_")                 # once per process
await init_beanie(database=db, document_models=[*app_models, *tk_models.all])

storage = BeanieStorage(database=db, models=tk_models)    # transactions=True by default
kit = await TenantKit.create(config=config, storage=storage)
```

- `document_models(prefix="mt_")` builds the Document classes, with `Settings.name = prefix + "<collection>"`, and caches them. The same prefix returns the same object; a different prefix in the same process raises `ConfigError`. The prefix follows the SQL table-prefix rules and an invalid one raises `ConfigError`. `BeanieModels` has one attribute per collection plus `all`.
- `BeanieStorage(*, database, models, transactions=True)` never creates a client and never calls `init_beanie`.
- `health_check()` fails fast: `ConfigError` if the client's UUID representation is not `standard` or the models are not initialised against this database; `StorageUnavailableError` if the server is unreachable or, with `transactions=True`, is neither a replica set (`setName`) nor mongos (`msg == "isdbgrid"`).
- `transactions=False` is an escape hatch for standalone servers. It logs a warning once: multi-step operations are not atomic and **audit writes are no longer fail-closed** (a change can persist without its audit event). Use it only for development.

## Collections and indexes

| Collection | Fields | Indexes |
| --- | --- | --- |
| `{p}admins` | `_id` (UUID), email, password_hash, roles, impersonation_mode, impersonation_tenants, is_active, timestamps | unique email |
| `{p}tenants` | `_id`, slug, attributes (subdocument), login_policy (subdocument), is_active, timestamps | unique slug |
| `{p}tenant_users` | `_id`, tenant_id, email, password_hash, roles, is_active, timestamps | unique email (global); tenant_id |
| `{p}login_attempts` | `_id`, subject_type, subject_id, failed_count, locked_until | unique (subject_type, subject_id) |
| `{p}sessions` | see [10](10-sessions-revocation.md) | (kind, subject_id, created_at desc); tenant_id; parent_id; expires_at |
| `{p}audit_events` | see [11](11-audit.md) | (occurred_at desc, _id desc); (tenant_id, occurred_at desc); actor_id; target_id; action |

Indexes are declared on the Document classes, so the host's `init_beanie` creates them.

## Adapter rules

- **UUIDs and datetimes.** `_id`s are UUIDs stored with the standard representation. BSON keeps milliseconds, so the adapter truncates datetimes to millisecond precision and always returns timezone-aware UTC values, whatever the client's `tz_aware` setting.
- **Transactions.** `transaction()` keeps the active `AsyncClientSession` in a per-instance `ContextVar`; an inner call joins the outer transaction, and every repository call passes `session=` while one is active.
- **Errors.** `DuplicateKeyError` becomes `AlreadyExistsError`; any other `PyMongoError` becomes `StorageError` with the original chained and no connection string in the message. `TenantUser.create` checks the tenant exists inside the transaction because MongoDB has no foreign keys.
- **Atomic lockout.** `record_failure` is a single `find_one_and_update` upsert with an aggregation-pipeline update that increments `failed_count`, keeps an existing lock, and sets `locked_until` when the count reaches `max_attempts`. The document `_id` is derived deterministically from (subject_type, subject_id) so concurrent first failures cannot create two rows.
- **Session rotation.** `find_one_and_update` with `_id`, `revoked_at: None` and `current_jti == expected` in the filter.
- **Revocation and purges.** `update_many` / `delete_many`; the only hard deletes are `audit.purge` and `sessions.purge_expired`.

## Errors

| Error | When |
| --- | --- |
| `ConfigError` | Different prefix in one process, invalid prefix, non-standard UUID representation, models not initialised |
| `StorageUnavailableError` | Server unreachable, or transactions required on a standalone server |
| `AlreadyExistsError` | Duplicate key |
| `StorageError` | Any other driver failure |

## Test cases

`StorageContract` runs against a replica set when `TENANTKIT_TEST_MONGO_URL` is set (it skips otherwise), and the session and audit service tests run on MongoDB too, including the end-to-end login, refresh, impersonate, revoke and audit flow. Server-free tests cover `document_models` caching, prefix validation and `health_check` with a faked `hello` reply. CI starts a single-node replica set:

```bash
docker run -d --name mongo -p 27017:27017 mongo:7 --replSet rs0 --bind_ip_all
docker exec mongo mongosh --quiet --eval 'rs.initiate({_id:"rs0",members:[{_id:0,host:"localhost:27017"}]})'
export TENANTKIT_TEST_MONGO_URL='mongodb://localhost:27017/?replicaSet=rs0&directConnection=true'
```

## Decisions

1. Beanie `>=2.0,<3` on the PyMongo async client; the extra is named `mongo`.
2. Initialisation of Beanie is owned by the host; one prefix per process.
3. Transactions are required by default; `transactions=False` is documented as unsafe.
4. Documents are adapter-internal; repositories return domain dataclasses.
