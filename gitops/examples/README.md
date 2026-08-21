# GitOps example manifests

A complete, internally-consistent manifest set exercising **every GitOps kind**.
Apply the whole folder with [`../gitops_apply.py`](../gitops_apply.py):

```bash
# fromEnv secrets are read from your shell — set them first:
export GEMINI_EMBED_KEY="AIza...REPLACE_ME"
export AWS_BLOB_CREDENTIALS='{"accessKeyId":"...","secretAccessKey":"..."}'
export WAREHOUSE_PG_DSN="postgresql://user:pass@host:5432/db"

export RAGNEROCK_API_TOKEN=rgnk_...           # or use --email/--password
../gitops_apply.py .                          # apply this folder
../gitops_apply.py . --dry-run                # preview the upload (secret values elided)
```

Secret values are encrypted to the instance's public key before upload, so nothing
recoverable crosses the wire. That happens automatically and changes nothing about
how these manifests are written. Against an instance with no sealing key configured
(`GITOPS_SEALING_PRIVATE_KEY`), pass `--no-seal` to upload plaintext instead — the
applier fails rather than downgrading on its own.

Only documents whose `apiVersion` is in the `ragnerock.com/` group are applied, so
these files can sit anywhere in a repo alongside unrelated YAML.

Files are numbered by **apply rank** for readability only — the server sorts every
document by rank before applying, so file order and filenames don't affect the
result. One kind per file (a couple of files carry two closely-related objects).

| File | Kind(s) | Rank | Scope |
| --- | --- | --- | --- |
| `00-secrets.yaml` | Secret ×3 | 15 | account |
| `10-project.yaml` | Project | 10 | account |
| `20-ai-config.yaml` | AIProviderConfig ×2 | 20 | account |
| `20-blob-config.yaml` | BlobProviderConfig | 20 | account |
| `20-db-config.yaml` | DBProviderConfig ×2 (BigQuery + Postgres) | 20 | account |
| `30-role.yaml` | Role | 30 | account |
| `32-role-assignment.yaml` | RoleAssignment | 32 | account |
| `40-policy.yaml` | Policy | 40 | account |
| `42-policy-assignment.yaml` | PolicyAssignment | 42 | account |
| `50-schema.yaml` | Schema | 50 | project |
| `60-agent.yaml` | Agent | 60 | project |
| `70-workflow.yaml` | Workflow | 70 | project |
| `85-snapshot.yaml` | Snapshot | 85 | project |
| `90-endpoint.yaml` | Endpoint | 90 | project |
| `95-ingest-config.yaml` | IngestConfig | 95 | project |

## Secret sources demonstrated

`00-secrets.yaml` exercises all three secret sources:

- **`stringData`** — inline plaintext (`llm-credentials.anthropicApiKey`)
- **`data`** — inline base64 (`db-credentials.credentials.json`)
- **`fromEnv`** — resolved from **your** environment client-side and sealed into
  the upload (`llm-credentials.geminiEmbedKey`, `blob-credentials.aws`,
  `db-credentials.pgDsn`). Pass `--no-resolve-env` to instead ship `fromEnv`
  as-is and let the server resolve it from its own environment, so the value
  never leaves the deployment at all.

Every secret-bearing config references these by `secretKeyRef: {name, key}`.

## Values you must replace before a real apply

Placeholders are marked `REPLACE_ME`. Nothing here validates a live connection on
apply (values are just encrypted and stored), so the manifest applies as-is — but
the credentials won't *work* until you substitute real ones:

- `llm-credentials.anthropicApiKey` (stringData) and `GEMINI_EMBED_KEY` (env)
- the cloud references themselves: the GCP `project`, the Azure `vaultUrl`, and
  the AWS `secretId`/`region` all point at placeholders
- `db-credentials.credentials.json` (base64 of a real GCP service-account JSON)
- `10-project.yaml` `owner`, role/policy member emails
- `sentiment-api` `ipWhitelist`

## Notes / gotchas

- **`Default` project**: drop the `ragnerock.com/project` annotation from any
  project-scoped kind to target the account's `Default` project instead.
- **`Agent.template`** is omitted — set it only if a matching `OperatorTemplate`
  already exists, or apply fails resolving the reference.
- **Cross-scope secret**: `95-ingest-config.yaml` (project-scoped) references the
  account-scoped `blob-credentials` Secret — intended per design.
- **Bindings are always separate documents**: a `Role`/`Policy` never carries its
  own members/principals. `32-role-assignment.yaml` and `42-policy-assignment.yaml`
  are where the grants live, and a `spec` that inlines them on the role or policy
  is rejected as a structural error. Assignments are additive — applying one never
  removes a binding it omits.
- **Prereq**: the `Secret` table + IAM-noun-grant migrations must be applied to the
  target DB (`uv run alembic upgrade head` from `packages/core`) or secret applies
  fail. The applying user needs `create` on every kind's IAM noun.
