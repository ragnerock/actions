# Ragnerock Actions

GitHub Actions published by Ragnerock, for driving a Ragnerock instance from your
own workflows.

Every action lives in its own top-level directory and is referenced by that path:

| Action | Reference | What it does |
| --- | --- | --- |
| [GitOps Apply](gitops/) | `ragnerock/actions/gitops@v1` | Discovers Ragnerock GitOps manifests in a repository and applies them to an instance. |

## Versioning

Pin to the floating major tag unless you have a reason not to:

```yaml
- uses: ragnerock/actions/gitops@v1
```

`v1` moves forward with every Ragnerock release and stays on the same input
contract. When an action takes a breaking change the major is bumped and `v1`
stops moving, so a workflow pinned to it keeps working.

Each release is also tagged with the Ragnerock version it shipped with —
`v2026.08.17` and the like — so you can pin exactly:

```yaml
- uses: ragnerock/actions/gitops@v2026.08.17
```

An action is only guaranteed to work against a Ragnerock instance at or newer
than the release it was tagged with. Pinning to a version older than your
instance is safe; pinning to a newer one is not.

## Contributing

This repository is a mirror. Its contents are generated from the `actions/`
directory of the Ragnerock monorepo on every release and a pull request opened
here will be overwritten by the next sync — including anything added under
`.github/workflows/`. Open issues here; send changes to Ragnerock.
