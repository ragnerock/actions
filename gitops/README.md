# Ragnerock GitOps Apply — GitHub Action

A composite action that discovers Ragnerock GitOps manifests in a repository (or a
directory within it) and applies them to a Ragnerock instance via
`POST /api/gitops/apply`. Secret values are resolved **in the workflow** — from the
job environment, or straight out of GCP Secret Manager, AWS Secrets Manager, or
Azure Key Vault — so credentials are applied without ever touching the deployed
server's configuration. They are then encrypted to the target instance's public
key before they are sent — see [Secrets](#secrets).

## What it does

- Walks the target for `.yaml`/`.yml` files and keeps only **Ragnerock manifests**
  (documents whose `apiVersion` is in the `ragnerock.com/` group). All other YAML
  in the tree is ignored, so it is safe to point at a whole repo.
- Gathers every matched document into one multi-document upload, so the server's
  rank-based apply ordering and same-manifest `secretKeyRef` resolution work across
  files.
- Resolves every `Secret` source — `fromEnv` from the job environment, and cloud
  references with the job's ambient cloud identity — then encrypts each value to
  the instance's public key so the upload carries no plaintext.
- Upserts by name — existing resources are updated, new ones created, nothing is
  deleted. Exits non-zero if any object fails.

## Two modes

**Walk the whole repo** — apply every Ragnerock manifest found:

```yaml
- uses: ragnerock/actions/gitops@v1
  with:
    repository: my-org/infra-manifests
    url: https://app.ragnerock.com
    token: ${{ secrets.RAGNEROCK_API_TOKEN }}
  env:
    # every fromEnv-referenced var the manifests use
    GEMINI_EMBED_KEY: ${{ secrets.GEMINI_EMBED_KEY }}
    WAREHOUSE_PG_DSN: ${{ secrets.WAREHOUSE_PG_DSN }}
```

**Scope to a directory within the repo**:

```yaml
- uses: ragnerock/actions/gitops@v1
  with:
    repository: my-org/infra-manifests
    ref: main
    directory: environments/prod
    url: https://app.ragnerock.com
    token: ${{ secrets.RAGNEROCK_API_TOKEN }}
```

**Apply from the current checkout** — omit `repository` and run `actions/checkout`
yourself first:

```yaml
- uses: actions/checkout@v4
- uses: ragnerock/actions/gitops@v1
  with:
    directory: manifests
    url: https://app.ragnerock.com
    token: ${{ secrets.RAGNEROCK_API_TOKEN }}
```

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `url` | yes | — | Base URL of the target Ragnerock instance. |
| `token` | — | `''` | Personal API token (`rgnk_…`) for Bearer auth. Provide this, or `email` + `password`. |
| `email` | — | `''` | Login email (with `password`) when no token is given. |
| `password` | — | `''` | Login password (with `email`). |
| `repository` | — | `''` | Repo (`owner/name`) to check out and apply from. Omit to use the current workspace. |
| `ref` | — | `''` | Git ref to check out when `repository` is set. |
| `github-token` | — | `${{ github.token }}` | Token to check out a private `repository`. |
| `directory` | — | `.` | Directory within the repo to scope to (repo root walks everything). |
| `dry-run` | — | `false` | Print the manifest that would be applied (secret values elided) and exit without contacting the server. |
| `seal` | — | `true` | Encrypt secret values to the instance's public key before uploading. |
| `sealing-public-key` | — | `''` | PEM public key to seal to, instead of fetching it from the instance. |

## Secrets

Write `Secret` manifests the way you always would. Six sources are available, and
**all of them resolve here, in the workflow** — the server resolves none of them:

| Source | Value comes from |
| --- | --- |
| `stringData` | inline plaintext in the manifest |
| `data` | inline base64 in the manifest |
| `fromEnv` | an environment variable of this job |
| `fromGcpSecretManager` | GCP Secret Manager |
| `fromAwsSecretsManager` | AWS Secrets Manager |
| `fromAzureKeyVault` | Azure Key Vault |

For each `fromEnv: {someKey: SOME_ENV_VAR}`, set `SOME_ENV_VAR` in the step's
`env:` from a GitHub secret; a referenced variable that is unset fails the run
before anything is sent. See [`examples/`](examples/) for a manifest set
exercising every kind and every source.

Before upload the action resolves every value and encrypts it to a public key that
only the target instance can open, so the request body contains no recoverable
plaintext. This is automatic and changes nothing about how you write manifests — the
`encryptedData` block that appears on the wire is a transport format you never
author. Resolved values are also registered as GitHub log masks, and `dry-run`
prints the upload shape with the values elided.

### Cloud secret managers

Reference a secret where it already lives, and rotation there is the only step —
the next apply picks it up. Authenticate the job first with the provider's own
login action; the applier uses whatever ambient credentials that leaves behind
(ADC, the boto3 chain, `DefaultAzureCredential`).

```yaml
- uses: google-github-actions/auth@v2          # or aws-actions/configure-aws-credentials
  with:
    workload_identity_provider: projects/.../providers/github
    service_account: gitops@my-proj.iam.gserviceaccount.com

- uses: ragnerock/actions/gitops@v1
  with:
    url: https://app.ragnerock.com
    token: ${{ secrets.RAGNEROCK_API_TOKEN }}
```

```yaml
apiVersion: ragnerock.com/v1alpha1
kind: Secret
metadata:
  name: llm-credentials
spec:
  fromGcpSecretManager:
    anthropicApiKey:
      secret: anthropic-api-key      # short ID, or a full projects/.../secrets/... name
      project: my-gcp-project        # optional; defaults to the ADC project
      version: latest                # optional
      jsonField: apiKey              # optional; pull one field out of a JSON secret
  fromAwsSecretsManager:
    pgDsn:
      secretId: prod/warehouse-dsn   # name or ARN
      region: us-east-1              # optional; defaults to the ambient region
      versionStage: AWSCURRENT       # optional; or versionId, not both
      jsonField: password            # optional
  fromAzureKeyVault:
    geminiEmbedKey:
      vaultUrl: https://my-vault.vault.azure.net   # full URL, so sovereign clouds work
      secret: gemini-embed-key
      version: 4f1c...               # optional; defaults to the current version
      jsonField: key                 # optional
```

`jsonField` is what makes AWS's multi-field secrets usable directly — an
RDS-managed credential holds `{"username": ..., "password": ...}`, and you want
one of them. Secrets stored as binary are rejected: Ragnerock secrets hold text.

**Why client-side.** A server-side resolver would dereference manifest-supplied
names using the *deployment's* identity, so on a multi-tenant instance any account
could name any secret the platform can read. Resolving here keeps the trust
boundary where it already is: the job that holds the credentials is the job that
reads them.

### Sealing

**What sealing protects against depends on where the key comes from.** By default the
action fetches it from the instance, which keeps secrets out of request logs, traces,
and APM captures. That fetch travels over the same connection it is protecting, so it
does not stop an attacker who already terminates TLS in front of the instance — they
could serve their own key. If that is in your threat model, pin the key instead:

```yaml
- uses: ragnerock/actions/gitops@v1
  with:
    url: https://app.ragnerock.com
    token: ${{ secrets.RAGNEROCK_API_TOKEN }}
    # Fetched once from GET /api/gitops/sealing-key and committed or stored as a
    # variable. The action will not ask the server for a key when this is set.
    sealing-public-key: ${{ vars.RAGNEROCK_SEALING_PUBLIC_KEY }}
```

Two caveats worth knowing. Sealing protects the value *in transit* — the server still
decrypts it to store it under its own key and to use the credential, so this narrows
the window rather than closing it. And it does nothing for a plaintext value committed
to your repo in `stringData`; use `fromEnv` or a cloud source for anything real.

Set `seal: false` only for an instance with no sealing key configured
(`GITOPS_SEALING_PRIVATE_KEY`). The action fails rather than silently downgrading to
plaintext, and warns in the run summary when sealing is off with secrets present.

## Notes

- `@v1` is a floating major that moves with every Ragnerock release; pin to a
  release tag (`@v2026.08.17`) to hold a version. See the
  [repository README](../README.md#versioning).
- The applier ([`gitops_apply.py`](gitops_apply.py)) is a self-contained
  [uv](https://docs.astral.sh/uv/) script (PEP-723 inline deps); the action installs
  uv and runs it. It can also be run directly for local testing — see
  [`examples/README.md`](examples/README.md).
- The applying user (token owner) needs `create` on each kind's IAM noun. The target
  instance must have the GitOps `Secret` table and IAM-noun-grant migrations applied.
- Finding no Ragnerock manifests is a clean no-op (exit 0), so the action is safe to
  run on pushes that don't touch manifests.
