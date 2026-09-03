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
| `50-schema.yaml` | Schema ×3 (output schemas + a memory schema) | 50 | project |
| `55-skill.yaml` | Skill | 55 | project |
| `60-agent.yaml` | Agent ×2 (LLM + code) | 60 | project |
| `70-workflow.yaml` | Workflow | 70 | project |
| `90-endpoint.yaml` | Endpoint | 90 | project |
| `95-ingest-config.yaml` | IngestConfig | 95 | project |

## Secret sources demonstrated

`00-secrets.yaml` exercises all six secret sources:

| Source | Example key | Value comes from |
| --- | --- | --- |
| `stringData` | `llm_credentials.anthropicApiKey` | inline plaintext |
| `data` | `db_credentials.credentials.json` | inline base64 |
| `fromEnv` | `llm_credentials.geminiEmbedKey` | your shell / a CI secret |
| `fromGcpSecretManager` | `db_credentials.pgDsn` | GCP Secret Manager |
| `fromAwsSecretsManager` | `blob_credentials.aws` | AWS Secrets Manager |
| `fromAzureKeyVault` | `llm_credentials.openaiApiKey` | Azure Key Vault (via `jsonField`) |

All six resolve **client-side**, in the applier, and are then sealed to the
instance's public key. The server resolves none of them — posting a manifest that
still carries one of these sources directly to `/api/gitops/apply` is refused with
a pointer back to the applier.

Every secret-bearing config references these by `secretKeyRef: {name, key}`, and
every key above has a consumer somewhere in the set.

## Values you must replace before a real apply

Placeholders are marked `REPLACE_ME`. Nothing here validates a live connection on
apply (values are just encrypted and stored), so the manifest applies as-is — but
the credentials won't *work* until you substitute real ones:

- `llm_credentials.anthropicApiKey` (stringData) and `GEMINI_EMBED_KEY` (env)
- the cloud references themselves: the GCP `project`, the Azure `vaultUrl`, and
  the AWS `secretId`/`region` all point at placeholders
- `db_credentials.credentials.json` (base64 of a real GCP service-account JSON)
- `10-project.yaml` `owner`, role/policy member emails
- `sentiment_api` `ipWhitelist`

## Notes / gotchas

- **`Default` project**: drop the `ragnerock.com/project` annotation from any
  project-scoped kind to target the account's `Default` project instead.
- **`Agent.template`** is omitted — set it only if a matching `OperatorTemplate`
  already exists, or apply fails resolving the reference.
- **Agent kinds**: `60-agent.yaml` shows both an LLM agent (a `generationPrompt`,
  optionally a `model` block) and a code agent (`operatorKind: code` plus a
  `codeSource` snippet). `operatorKind` is explicit — absent means `llm` — and the
  two payloads are mutually exclusive, so a code agent with a prompt (or an LLM
  agent with a snippet) is rejected. A code agent's snippet is security-reviewed on
  apply, so keep credentials out of it and reference a `Secret` instead.
- **Cross-scope secret**: `95-ingest-config.yaml` (project-scoped) references the
  account-scoped `blob_credentials` Secret — intended per design.
- **Bindings are always separate documents**: a `Role`/`Policy` never carries its
  own members/principals. `32-role-assignment.yaml` and `42-policy-assignment.yaml`
  are where the grants live, and a `spec` that inlines them on the role or policy
  is rejected as a structural error. Assignments are additive — applying one never
  removes a binding it omits.
- **`Schema.isMemory`** targets a different namespace, not just a different flag:
  the row becomes one of the project's `mem_*` memory tables. It is import-only
  (export never emits memory schemas), it takes no folder, re-applying may only
  add optional fields to a schema that already holds records, and it needs
  `create` on the `memory` noun on top of `schema`.
- The applying user needs `create` on every kind's IAM noun.
