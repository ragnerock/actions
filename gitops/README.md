# Ragnerock GitOps Apply — GitHub Action

A composite action that discovers Ragnerock GitOps manifests in a repository and applies them to a Ragnerock instance. For information about secrets management, see the [Secrets](#Secrets) section.

## Quickstart

Walk the repo and apply every Ragnerock manifest found

```yaml
- uses: actions/checkout@v4
- uses: ragnerock/actions/gitops@v1
  with:
    directory: manifests
    url: https://app.ragnerock.com
    token: ${{ secrets.RAGNEROCK_API_TOKEN }}
```

Scope to a specific directory

```yaml
- uses: ragnerock/actions/gitops@v1
  with:
    ref: main
    directory: environments/prod
    url: https://app.ragnerock.com
    token: ${{ secrets.RAGNEROCK_API_TOKEN }}
```

Additionally, if you want to apply manifests from a different directory, set the `repository` input to that repo. You will need to ensure that your job has permissions to access said repo.

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
| `dry-run` | — | `false` | Print the manifest that would be applied (secret values elided) and exit without contacting the server. Answers "what would be uploaded". |
| `plan` | — | `false` | Upload and report what would change, then have the server roll it back. Answers "what would change" — validated against the real account, so a bad reference fails here rather than on the merge. |
| `seal` | — | `true` | Encrypt secret values to the instance's public key before uploading. |
| `sealing-public-key` | — | `''` | PEM public key to seal to, instead of fetching it from the instance. |

## Secrets

Six secrets sources are available, and all of them resolve client-side before the actual apply.

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

Before upload, the action resolves every value and encrypts it to a public key that
only the target instance can open.

### Cloud secret managers

First, authenticate the job first with the provider's own
login action, then run the Ragnerock gitops action.

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

### Sealing

```yaml
- uses: ragnerock/actions/gitops@v1
  with:
    url: https://app.ragnerock.com
    token: ${{ secrets.RAGNEROCK_API_TOKEN }}
    # Fetched once from GET /api/gitops/sealing-key and committed or stored as a
    # variable. The action will not ask the server for a key when this is set.
    # Otherwise it will grab the key from the instance on apply
    sealing-public-key: ${{ vars.RAGNEROCK_SEALING_PUBLIC_KEY }}
```

Set `seal: false` only for an instance with no sealing key configured
(`GITOPS_SEALING_PRIVATE_KEY`). The action fails rather than silently downgrading to
plaintext, and warns in the run summary when sealing is off with secrets present.

## Notes

- `@v1` is a floating major that moves with every Ragnerock release; pin to a
  release tag (`@v2026.08.17`) to hold a version. See the
  [repository README](../README.md#versioning).
- The applier ([`gitops_apply.py`](gitops_apply.py)) is a self-contained
  [uv](https://docs.astral.sh/uv/) script (PEP-723 inline deps); the action installs
  uv and runs it. Every dependency it declares comes from PyPI, so the file stands
  on its own: copy it into a pipeline that does not use GitHub Actions at all, or
  read it end to end to see exactly what happens to your secrets. It can also be run
  directly for local testing — see [`examples/README.md`](examples/README.md).
- The applying user (token owner) needs `create` on each kind's IAM noun to add an
  object, and `update` to change one that already exists. Apply is an upsert, so it
  asks for the permission it is actually about to use.
- Finding no Ragnerock manifests is a clean no-op (exit 0), so the action is safe to
  run on pushes that don't touch manifests.
- Existing resources are upserted by name; resources absent from the manifest are
  never deleted.
- An object that already matches the manifest reports `unchanged` and is left
  untouched, so a workflow that applies on every push shows `0 changed` when nothing
  moved.
- Warnings are printed per object and, under Actions, raised as annotations. They
  mean the object applied but something about it will bite at run time — an agent
  whose model binding did not resolve in the target account, a workflow node nothing
  feeds. Read them; they do not fail the run.
- An `Endpoint` this action creates gets a server-generated API key that is **not**
  returned in the report — key material never travels back over an apply. Rotate it
  from the endpoint's page (or `POST /api/endpoints/{id}/regenerate-key`) to get a
  usable key.
