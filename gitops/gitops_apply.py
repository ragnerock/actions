#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "httpx>=0.27",
#   "pyyaml>=6.0",
#   "cryptography>=45.0.0",
#   # Supplies ragnerock.sealing, the one definition of the sealed-blob format.
#   # Sharing it with the server is what keeps the two ends from drifting.
#   "ragnerock>=0.1.2",
#   # Cloud secret-manager SDKs. Imported lazily, inside the fetch functions, so
#   # a manifest set that uses none of them pays only the (uv-cached) install.
#   "google-cloud-secret-manager>=2.20",
#   "boto3>=1.42",
#   "azure-keyvault-secrets>=4.8",
#   "azure-identity>=1.17",
# ]
# ///
"""Discover and apply Ragnerock GitOps manifests to a running instance.

Point this at a single ``.yaml``/``.yml`` file or a directory. Directories are
walked **recursively**, and only documents that are Ragnerock manifests (those
whose ``apiVersion`` starts with ``ragnerock.com/``) are applied — any other YAML
in the tree (CI configs, Kubernetes manifests, etc.) is skipped. This lets the
tool be pointed at a whole repository, or scoped to a subdirectory within it.

Matched documents are gathered into a single multi-document upload to
``POST /api/gitops/apply``, so the server's rank-based apply ordering and
same-manifest ``secretKeyRef`` resolution work across files — e.g. a ``Secret``
in ``secrets.yaml`` resolves for an ``AIProviderConfig`` in ``configs.yaml`` even
though they are separate files.

Authentication (pick one):
  * Personal API token — ``--token`` or ``RAGNEROCK_API_TOKEN``. Sent as
    ``Authorization: Bearer``.
  * Email + password — ``--email``/``--password`` (or ``RAGNEROCK_EMAIL`` /
    ``RAGNEROCK_PASSWORD``); the tool logs in via ``POST /api/auth/login`` and
    uses the returned JWT.

Secrets: include ``Secret`` objects in your manifests and write them the way you
always would — ``stringData``, ``data``, ``fromEnv``, or a cloud secret-manager
source (``fromGcpSecretManager``, ``fromAwsSecretsManager``,
``fromAzureKeyVault``). Every source is resolved **here**: ``data`` decoded,
``fromEnv`` read from this process's environment, and cloud references fetched
with this runner's ambient cloud identity (ADC, the boto3 chain,
``DefaultAzureCredential``). Resolution happens client-side by design — a
server-side resolver would dereference manifest-supplied names using the
deployment's identity, which on a multi-tenant instance lets any account read
any secret the platform can.

Resolved values are then **sealed** to the target instance's public key, fetched
from ``GET /api/gitops/sealing-key``, so the request body carries no recoverable
plaintext. Sealing is automatic; ``encryptedData`` is a wire format you never
author.

Pass ``--sealing-public-key`` to pin the key instead of fetching it, which is
what protects against an intermediary that terminates TLS. Pass ``--no-seal``
to upload plaintext against an instance that has no sealing key configured.

Examples:
    ./gitops_apply.py ./manifests/
    ./gitops_apply.py ./secret.yaml --url https://ragnerock.example.com
    RAGNEROCK_API_TOKEN=rgnk_... ./gitops_apply.py path/to/repo
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import NamedTuple, NoReturn

import httpx
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from ragnerock.sealing import (
    SealingError,
    key_fingerprint,
    load_public_key,
    seal,
)

_YAML_SUFFIXES = (".yaml", ".yml")
_RAGNEROCK_API_GROUP = "ragnerock.com/"
_ACTION_COLORS = {
    "created": "\033[32m",  # green
    "updated": "\033[34m",  # blue
    "unchanged": "\033[90m",  # grey
    "error": "\033[31m",  # red
}
_RESET = "\033[0m"

# Stand-in for secret material in --dry-run output.
_REDACTED = "<redacted>"

# Shortest value worth registering as a log mask. GitHub refuses to mask very
# short strings anyway, and masking a common short token would blank unrelated
# log text without protecting anything.
_MIN_MASK_LENGTH = 4


class SecretValue(NamedTuple):
    """A resolved secret value and the environment variable it came from.

    Attributes:
        value (str): The resolved plaintext.
        from_env (str | None): The source environment variable for ``fromEnv``
            keys, or ``None`` for inline ones. Carried through to the upload so
            the server can still round-trip the binding on export — the variable
            name is not secret, only its value is.
    """

    value: str
    from_env: str | None


# Applied to every secret value on its way into the upload: seals it, or elides
# it for --dry-run.
Transform = Callable[[str], str]


def _collect_files(path: Path) -> list[Path]:
    """Return the YAML files under a path, sorted for a stable order.

    A directory is walked recursively so a whole repository (or a subdirectory
    within it) can be scanned in one call.

    Args:
        path (Path): A single file or a directory.

    Returns:
        list[Path]: Matching ``.yaml``/``.yml`` files (possibly empty).

    Raises:
        SystemExit: If the path does not exist.
    """
    if not path.exists():
        sys.exit(f"error: path does not exist: {path}")
    if path.is_file():
        return [path]
    return sorted(
        p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in _YAML_SUFFIXES
    )


def _is_ragnerock_doc(doc: object) -> bool:
    """Return whether a parsed YAML document is a Ragnerock manifest.

    A Ragnerock manifest is a mapping whose ``apiVersion`` is a string in the
    ``ragnerock.com/`` API group (e.g. ``ragnerock.com/v1alpha1``). Everything
    else encountered while walking a repository is ignored.

    Args:
        doc (object): A parsed YAML document.

    Returns:
        bool: True if the document should be applied.
    """
    return (
        isinstance(doc, dict)
        and isinstance(doc.get("apiVersion"), str)
        and doc["apiVersion"].startswith(_RAGNEROCK_API_GROUP)
    )


def _load_documents(files: list[Path]) -> list[tuple[Path, dict]]:
    """Parse every YAML document from the given files, tagged by source file.

    Args:
        files (list[Path]): Files to load, in scan order.

    Returns:
        list[tuple[Path, dict]]: ``(file, document)`` for every non-empty
            document across all files.

    Raises:
        SystemExit: If a file contains invalid YAML.
    """
    out: list[tuple[Path, dict]] = []
    for f in files:
        try:
            for doc in yaml.safe_load_all(f.read_text()):
                if doc is not None:
                    out.append((f, doc))
        except yaml.YAMLError as e:
            sys.exit(f"error: invalid YAML in {f}: {e}")
    return out


def _mask(value: str) -> None:
    """Register a secret value for masking in GitHub Actions logs.

    Emits an ``::add-mask::`` workflow command for the whole value and for each
    of its lines. The per-line masks matter because GitHub does not reliably
    redact a multi-line secret from a single mask, and multi-line secrets
    (service-account JSON, PEM keys) are exactly what this tool carries.

    A no-op outside GitHub Actions.

    Args:
        value (str): The secret value to mask.
    """
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    for candidate in {value, *value.splitlines()}:
        stripped = candidate.strip()
        if len(stripped) >= _MIN_MASK_LENGTH:
            print(f"::add-mask::{stripped}", flush=True)


def _secret_specs(docs: list[dict]) -> list[tuple[str, dict]]:
    """Return ``(name, spec)`` for every ``Secret`` document with a spec.

    Args:
        docs (list[dict]): Parsed Ragnerock manifest documents.

    Returns:
        list[tuple[str, dict]]: The name and mutable spec of each Secret.
    """
    out: list[tuple[str, dict]] = []
    for doc in docs:
        if not isinstance(doc, dict) or doc.get("kind") != "Secret":
            continue
        spec = doc.get("spec")
        if isinstance(spec, dict):
            out.append(((doc.get("metadata") or {}).get("name", "<unnamed>"), spec))
    return out


class CloudProvider(StrEnum):
    """A cloud secret manager a ``Secret`` key can be sourced from.

    The member value is the ``spec`` field carrying that provider's references,
    so the enum doubles as the list of cloud source fields.
    """

    GCP = "fromGcpSecretManager"
    AWS = "fromAwsSecretsManager"
    AZURE = "fromAzureKeyVault"

    @property
    def packages(self) -> str:
        """Return the PyPI package(s) supplying this provider's SDK."""
        match self:
            case CloudProvider.GCP:
                return "google-cloud-secret-manager"
            case CloudProvider.AWS:
                return "boto3"
            case CloudProvider.AZURE:
                return "azure-keyvault-secrets azure-identity"


# Every source a human authors. All of them resolve here, so all of them are
# stripped from the spec before upload.
_AUTHORED_SOURCE_FIELDS = (
    "stringData",
    "data",
    "fromEnv",
    *(provider.value for provider in CloudProvider),
)

# GCP's default version alias when a reference does not pin one.
_GCP_DEFAULT_VERSION = "latest"
_GCP_RESOURCE_PREFIX = "projects/"


@dataclass(frozen=True)
class GcpRef:
    """A GCP Secret Manager secret version.

    Attributes:
        project (str | None): Project ID, or ``None`` to take the ADC default.
        secret (str): The secret's short ID.
        version (str): Version number or alias.
    """

    project: str | None
    secret: str
    version: str


@dataclass(frozen=True)
class AwsRef:
    """An AWS Secrets Manager secret value.

    Attributes:
        secret_id (str): Secret name or ARN (``GetSecretValue`` accepts both).
        region (str | None): Region, or ``None`` to take the ambient config.
        version_stage (str | None): Staging label, or ``None``.
        version_id (str | None): Version ID, or ``None``.
    """

    secret_id: str
    region: str | None
    version_stage: str | None
    version_id: str | None


@dataclass(frozen=True)
class AzureRef:
    """An Azure Key Vault secret.

    Attributes:
        vault_url (str): Full vault URL, e.g. ``https://v.vault.azure.net``.
        secret (str): The secret's name.
        version (str | None): Version, or ``None`` for the current one.
    """

    vault_url: str
    secret: str
    version: str | None


CloudRef = GcpRef | AwsRef | AzureRef


class CloudBinding(NamedTuple):
    """One manifest key bound to a cloud reference.

    ``json_field`` is kept beside the reference rather than inside it so the
    reference alone is the fetch-cache key: two keys reading different fields of
    the same remote secret still share one API call.

    Attributes:
        key (str): The key within the ``Secret``.
        ref (CloudRef): What to fetch.
        json_field (str | None): Field to extract from a JSON secret, or ``None``.
    """

    key: str
    ref: CloudRef
    json_field: str | None


def _check_fields(raw: object, allowed: set[str], where: str) -> dict:
    """Validate a reference block is a mapping carrying only known fields.

    Args:
        raw (object): The parsed reference block.
        allowed (set[str]): Field names this provider accepts.
        where (str): Human location, for error messages.

    Returns:
        dict: ``raw``, narrowed to a mapping.

    Raises:
        SystemExit: If the block is not a mapping or carries unknown fields.
    """
    if not isinstance(raw, dict):
        sys.exit(f"error: {where} must be a mapping of reference fields")
    unknown = sorted(set(raw) - allowed)
    if unknown:
        sys.exit(
            f"error: {where} has unknown field(s) {', '.join(unknown)}; "
            f"allowed: {', '.join(sorted(allowed))}"
        )
    return raw


def _required_str(block: dict, field: str, where: str) -> str:
    """Return a required non-empty string field.

    Args:
        block (dict): The reference block.
        field (str): Field name.
        where (str): Human location, for error messages.

    Returns:
        str: The field value.

    Raises:
        SystemExit: If the field is missing, not a string, or empty.
    """
    value = block.get(field)
    if not isinstance(value, str) or not value:
        sys.exit(f"error: {where} requires a non-empty string '{field}'")
    return value


def _optional_str(block: dict, field: str, where: str) -> str | None:
    """Return an optional non-empty string field, or ``None`` if absent.

    Args:
        block (dict): The reference block.
        field (str): Field name.
        where (str): Human location, for error messages.

    Returns:
        str | None: The field value, or ``None``.

    Raises:
        SystemExit: If the field is present but not a non-empty string.
    """
    if field not in block:
        return None
    value = block[field]
    if not isinstance(value, str) or not value:
        sys.exit(f"error: {where} field '{field}' must be a non-empty string")
    return value


def _split_gcp_resource_name(name: str, where: str) -> GcpRef:
    """Split a full GCP resource name into a reference.

    Args:
        name (str): A ``projects/<p>/secrets/<s>[/versions/<v>]`` name.
        where (str): Human location, for error messages.

    Returns:
        GcpRef: The parsed reference.

    Raises:
        SystemExit: If the name is not one of the two complete forms. A partial
            path is an error rather than a short ID that happens to have slashes.
    """
    match name.split("/"):
        case ["projects", project, "secrets", secret] if project and secret:
            return GcpRef(project, secret, _GCP_DEFAULT_VERSION)
        case ["projects", project, "secrets", secret, "versions", version] if (
            project and secret and version
        ):
            return GcpRef(project, secret, version)
    sys.exit(
        f"error: {where} 'secret' is not a complete resource name; expected "
        f"'projects/<project>/secrets/<secret>' with an optional "
        f"'/versions/<version>'"
    )


def _parse_gcp_ref(raw: object, where: str) -> tuple[GcpRef, str | None]:
    """Parse a ``fromGcpSecretManager`` reference.

    ``secret`` takes either a short ID or a full resource name — the latter is
    what the console and ``gcloud secrets describe`` hand you, so rejecting it
    would turn a paste into a manual disassembly. The ``projects/`` prefix
    discriminates, and combining a full name with ``project``/``version`` is an
    error rather than a silent precedence rule.

    Args:
        raw (object): The parsed reference block.
        where (str): Human location, for error messages.

    Returns:
        tuple[GcpRef, str | None]: The reference and its ``jsonField``.

    Raises:
        SystemExit: On any malformed or contradictory reference.
    """
    block = _check_fields(raw, {"secret", "project", "version", "jsonField"}, where)
    secret = _required_str(block, "secret", where)
    project = _optional_str(block, "project", where)
    version = _optional_str(block, "version", where)
    json_field = _optional_str(block, "jsonField", where)

    if secret.startswith(_GCP_RESOURCE_PREFIX):
        if project is not None or version is not None:
            sys.exit(
                f"error: {where} gives 'secret' as a full resource name, so "
                f"'project'/'version' must not also be set — the name already "
                f"carries them"
            )
        return _split_gcp_resource_name(secret, where), json_field
    if "/" in secret:
        sys.exit(
            f"error: {where} 'secret' must be a short secret ID or a full "
            f"'projects/<project>/secrets/<secret>[/versions/<version>]' name"
        )
    return GcpRef(project, secret, version or _GCP_DEFAULT_VERSION), json_field


def _parse_aws_ref(raw: object, where: str) -> tuple[AwsRef, str | None]:
    """Parse a ``fromAwsSecretsManager`` reference.

    Args:
        raw (object): The parsed reference block.
        where (str): Human location, for error messages.

    Returns:
        tuple[AwsRef, str | None]: The reference and its ``jsonField``.

    Raises:
        SystemExit: On a malformed reference, or both version fields set.
    """
    block = _check_fields(
        raw, {"secretId", "region", "versionStage", "versionId", "jsonField"}, where
    )
    secret_id = _required_str(block, "secretId", where)
    region = _optional_str(block, "region", where)
    version_stage = _optional_str(block, "versionStage", where)
    version_id = _optional_str(block, "versionId", where)
    json_field = _optional_str(block, "jsonField", where)
    if version_stage is not None and version_id is not None:
        sys.exit(
            f"error: {where} sets both 'versionStage' and 'versionId'; set one "
            f"or neither"
        )
    return AwsRef(secret_id, region, version_stage, version_id), json_field


def _parse_azure_ref(raw: object, where: str) -> tuple[AzureRef, str | None]:
    """Parse a ``fromAzureKeyVault`` reference.

    Args:
        raw (object): The parsed reference block.
        where (str): Human location, for error messages.

    Returns:
        tuple[AzureRef, str | None]: The reference and its ``jsonField``.

    Raises:
        SystemExit: On a malformed reference or a non-HTTPS vault URL.
    """
    block = _check_fields(raw, {"vaultUrl", "secret", "version", "jsonField"}, where)
    vault_url = _required_str(block, "vaultUrl", where)
    if not vault_url.startswith("https://"):
        sys.exit(
            f"error: {where} 'vaultUrl' must be the full https:// vault URL, "
            f"e.g. https://my-vault.vault.azure.net"
        )
    secret = _required_str(block, "secret", where)
    version = _optional_str(block, "version", where)
    json_field = _optional_str(block, "jsonField", where)
    return AzureRef(vault_url.rstrip("/"), secret, version), json_field


def _parse_ref(
    provider: CloudProvider, raw: object, where: str
) -> tuple[CloudRef, str | None]:
    """Parse one reference for a provider.

    Args:
        provider (CloudProvider): Which provider's grammar to apply.
        raw (object): The parsed reference block.
        where (str): Human location, for error messages.

    Returns:
        tuple[CloudRef, str | None]: The reference and its ``jsonField``.

    Raises:
        ValueError: On an unhandled provider.
        SystemExit: On a malformed reference.
    """
    match provider:
        case CloudProvider.GCP:
            return _parse_gcp_ref(raw, where)
        case CloudProvider.AWS:
            return _parse_aws_ref(raw, where)
        case CloudProvider.AZURE:
            return _parse_azure_ref(raw, where)
    raise ValueError(f"unsupported cloud provider: {provider}")


def _parse_refs(
    provider: CloudProvider, block: object, name: str
) -> list[CloudBinding]:
    """Parse every reference in one provider's source block.

    Args:
        provider (CloudProvider): The provider whose block this is.
        block (object): The parsed ``key -> reference`` mapping.
        name (str): The secret's name, for error messages.

    Returns:
        list[CloudBinding]: One binding per key.

    Raises:
        SystemExit: If the block is not a mapping, or any reference is malformed.
    """
    if not isinstance(block, dict):
        sys.exit(
            f"error: Secret '{name}' {provider.value} must be a mapping of "
            f"key -> reference"
        )
    bindings: list[CloudBinding] = []
    for key, raw in block.items():
        ref, json_field = _parse_ref(
            provider, raw, f"Secret '{name}' {provider.value} key '{key}'"
        )
        bindings.append(CloudBinding(key, ref, json_field))
    return bindings


def _exit_missing_sdk(provider: CloudProvider) -> NoReturn:
    """Exit explaining which SDK to install for a provider.

    Reachable only when the script runs outside ``uv`` (a vendored copy), since
    the inline dependency block installs all four SDKs.

    Args:
        provider (CloudProvider): The provider whose SDK is missing.

    Raises:
        SystemExit: Always.
    """
    sys.exit(
        f"error: {provider.value} needs the {provider.packages} package(s), "
        f"which are not installed. Run this script with `uv run` (which installs "
        f"them from its inline dependency block) or install them yourself."
    )


def _decode_payload(payload: bytes, where: str) -> str:
    """Decode a secret payload as UTF-8 text.

    Args:
        payload (bytes): The raw payload.
        where (str): Human location, for error messages.

    Returns:
        str: The decoded text.

    Raises:
        SystemExit: If the payload is not valid UTF-8. Ragnerock secrets hold
            text, so there is nowhere for binary material to go.
    """
    try:
        return payload.decode()
    except UnicodeDecodeError:
        sys.exit(
            f"error: {where} is not valid UTF-8 text; Ragnerock secrets hold "
            f"text values only"
        )


def _fetch_gcp(ref: GcpRef) -> str:
    """Fetch a secret version's payload from GCP Secret Manager.

    Args:
        ref (GcpRef): The reference to read.

    Returns:
        str: The secret payload.

    Raises:
        SystemExit: If the SDK is absent, no credentials or default project are
            available, or the API call fails.
    """
    try:
        import google.auth
        from google.api_core import exceptions as gcp_exceptions
        from google.auth import exceptions as gcp_auth_exceptions
        from google.cloud import secretmanager
    except ImportError:
        _exit_missing_sdk(CloudProvider.GCP)

    project = ref.project
    if project is None:
        try:
            _, project = google.auth.default()
        except gcp_auth_exceptions.DefaultCredentialsError as e:
            sys.exit(f"error: no Google credentials are available: {e}")
        if not project:
            sys.exit(
                f"error: secret '{ref.secret}' gives no 'project' and the "
                f"ambient Google credentials carry no default project; set "
                f"'project' on the reference"
            )

    path = f"projects/{project}/secrets/{ref.secret}/versions/{ref.version}"
    try:
        client = secretmanager.SecretManagerServiceClient()
        response = client.access_secret_version(name=path)
    except gcp_auth_exceptions.GoogleAuthError as e:
        sys.exit(f"error: could not authenticate to GCP Secret Manager: {e}")
    except gcp_exceptions.GoogleAPIError as e:
        sys.exit(f"error: could not read {path} from GCP Secret Manager: {e}")
    return _decode_payload(response.payload.data, path)


def _fetch_aws(ref: AwsRef) -> str:
    """Fetch a secret value from AWS Secrets Manager.

    Args:
        ref (AwsRef): The reference to read.

    Returns:
        str: The secret string.

    Raises:
        SystemExit: If the SDK is absent, no region is configured, the API call
            fails, or the secret holds binary rather than string material.
    """
    try:
        import boto3
        from botocore import exceptions as boto_exceptions
    except ImportError:
        _exit_missing_sdk(CloudProvider.AWS)

    try:
        client = boto3.client("secretsmanager", region_name=ref.region)
    except boto_exceptions.BotoCoreError as e:
        sys.exit(
            f"error: could not create an AWS Secrets Manager client for secret "
            f"'{ref.secret_id}': {e}"
        )

    request: dict[str, str] = {"SecretId": ref.secret_id}
    if ref.version_stage is not None:
        request["VersionStage"] = ref.version_stage
    if ref.version_id is not None:
        request["VersionId"] = ref.version_id
    try:
        response = client.get_secret_value(**request)
    except (boto_exceptions.BotoCoreError, boto_exceptions.ClientError) as e:
        sys.exit(f"error: could not read AWS secret '{ref.secret_id}': {e}")

    secret_string = response.get("SecretString")
    if secret_string is None:
        sys.exit(
            f"error: AWS secret '{ref.secret_id}' is stored as SecretBinary; "
            f"Ragnerock secrets hold text values only"
        )
    return secret_string


def _fetch_azure(ref: AzureRef) -> str:
    """Fetch a secret from Azure Key Vault.

    Args:
        ref (AzureRef): The reference to read.

    Returns:
        str: The secret value.

    Raises:
        SystemExit: If the SDK is absent, the API call fails, or the secret has
            no value.
    """
    try:
        from azure.core import exceptions as azure_exceptions
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
    except ImportError:
        _exit_missing_sdk(CloudProvider.AZURE)

    try:
        client = SecretClient(
            vault_url=ref.vault_url, credential=DefaultAzureCredential()
        )
        secret = client.get_secret(ref.secret, version=ref.version)
    except azure_exceptions.AzureError as e:
        sys.exit(
            f"error: could not read secret '{ref.secret}' from {ref.vault_url}: {e}"
        )

    if secret.value is None:
        sys.exit(f"error: secret '{ref.secret}' in {ref.vault_url} has no value")
    return secret.value


def _fetch(ref: CloudRef) -> str:
    """Fetch one cloud reference's raw payload.

    Args:
        ref (CloudRef): The reference to read.

    Returns:
        str: The payload, before any ``jsonField`` extraction.

    Raises:
        ValueError: On an unhandled reference type.
        SystemExit: If the fetch fails.
    """
    match ref:
        case GcpRef():
            return _fetch_gcp(ref)
        case AwsRef():
            return _fetch_aws(ref)
        case AzureRef():
            return _fetch_azure(ref)
    raise ValueError(f"unsupported cloud reference: {type(ref).__name__}")


def _extract_json_field(payload: str, field: str, where: str) -> str:
    """Extract one field from a JSON-object secret.

    Args:
        payload (str): The fetched secret payload.
        field (str): The field to extract.
        where (str): Human location, for error messages.

    Returns:
        str: The field's value, with numbers and booleans rendered as JSON.

    Raises:
        SystemExit: If the payload is not a JSON object, the field is absent, or
            the field holds something that is not a scalar.
    """
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        sys.exit(f"error: {where} sets 'jsonField', but the secret is not JSON")
    if not isinstance(parsed, dict):
        sys.exit(
            f"error: {where} sets 'jsonField', but the secret is not a JSON object"
        )
    if field not in parsed:
        sys.exit(f"error: {where} secret has no JSON field '{field}'")
    value = parsed[field]
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return json.dumps(value)
    sys.exit(
        f"error: {where} JSON field '{field}' must hold a string, number, or boolean"
    )


class CloudSecretFetcher:
    """Reads cloud secret-manager values, once per distinct reference.

    Two manifest keys naming the same remote secret cost one API call, including
    across different ``Secret`` documents, because the cache is keyed on the
    reference itself and ``jsonField`` is applied afterwards.
    """

    def __init__(self) -> None:
        """Initialize an empty per-run cache."""
        self._cache: dict[CloudRef, str] = {}

    def resolve(self, binding: CloudBinding, where: str) -> str:
        """Resolve one binding to its plaintext value.

        Args:
            binding (CloudBinding): The key, reference, and optional field.
            where (str): Human location, for error messages.

        Returns:
            str: The resolved value.

        Raises:
            SystemExit: If the fetch or the field extraction fails.
        """
        payload = self._cache.get(binding.ref)
        if payload is None:
            payload = _fetch(binding.ref)
            self._cache[binding.ref] = payload
        if binding.json_field is None:
            return payload
        return _extract_json_field(payload, binding.json_field, where)


def _resolve_values(
    name: str, spec: dict, fetcher: CloudSecretFetcher
) -> dict[str, SecretValue]:
    """Resolve one ``Secret``'s sources to plaintext, without mutating the spec.

    Every authored source resolves here: ``data`` is base64-decoded with the same
    strictness the server applies, ``fromEnv`` is read from this process's
    environment, and cloud references are fetched with this runner's ambient
    cloud identity. A key may appear in only one source. Validating here means a
    malformed manifest fails before anything is uploaded rather than after.

    Args:
        name (str): The secret's name, for error messages.
        spec (dict): The ``Secret`` spec.
        fetcher (CloudSecretFetcher): Shared cloud-fetch cache for this run.

    Returns:
        dict[str, SecretValue]: Resolved values by key.

    Raises:
        SystemExit: On a key in multiple sources, invalid base64, an unset
            environment variable, or an unreadable cloud reference.
    """
    string_data = spec.get("stringData") or {}
    data = spec.get("data") or {}
    from_env = spec.get("fromEnv") or {}

    values: dict[str, SecretValue] = {}

    def claim(key: str) -> None:
        if key in values:
            sys.exit(
                f"error: Secret '{name}' key '{key}' is defined in more than one "
                f"source ({'/'.join(_AUTHORED_SOURCE_FIELDS)})"
            )

    for key, value in string_data.items():
        claim(key)
        values[key] = SecretValue(value, None)

    for key, value in data.items():
        claim(key)
        try:
            decoded = base64.b64decode(value, validate=True).decode()
        except (binascii.Error, ValueError, UnicodeDecodeError):
            sys.exit(f"error: Secret '{name}' data key '{key}' is not valid base64")
        values[key] = SecretValue(decoded, None)

    for key, env_var in from_env.items():
        claim(key)
        if env_var not in os.environ:
            sys.exit(
                f"error: Secret '{name}' key '{key}' -> environment variable "
                f"${env_var} is not set"
            )
        values[key] = SecretValue(os.environ[env_var], env_var)

    # Parse every reference before fetching any, so a typo in the last block
    # fails the run without having reached out to a cloud provider first.
    bindings: list[tuple[CloudProvider, CloudBinding]] = []
    for provider in CloudProvider:
        block = spec.get(provider.value)
        if not block:
            continue
        for binding in _parse_refs(provider, block, name):
            claim(binding.key)
            # Placeholder: reserves the key so a later source collides, and is
            # overwritten with the fetched value below.
            values[binding.key] = SecretValue("", None)
            bindings.append((provider, binding))

    for provider, binding in bindings:
        where = f"Secret '{name}' {provider.value} key '{binding.key}'"
        values[binding.key] = SecretValue(fetcher.resolve(binding, where), None)

    return values


def _write_sealed(
    spec: dict, values: dict[str, SecretValue], transform: Transform
) -> None:
    """Replace a Secret's resolved sources with an ``encryptedData`` block.

    Every authored source is consumed and removed: they all resolved here, so
    none of them should reach the server.

    Args:
        spec (dict): The ``Secret`` spec, mutated in place.
        values (dict[str, SecretValue]): Resolved values for this secret.
        transform (Transform): Seals a value, or elides it for a dry run.
    """
    for field in _AUTHORED_SOURCE_FIELDS:
        spec.pop(field, None)

    encrypted: dict[str, dict[str, str]] = {}
    for key, resolved in values.items():
        entry: dict[str, str] = {"ciphertext": transform(resolved.value)}
        if resolved.from_env:
            entry["fromEnv"] = resolved.from_env
        encrypted[key] = entry
    if encrypted:
        spec["encryptedData"] = encrypted


def _write_inline(
    spec: dict, values: dict[str, SecretValue], transform: Transform
) -> None:
    """Fold a Secret's resolved sources into plaintext ``stringData``.

    The unsealed path, used only when ``--no-seal`` is given. Note that
    ``stringData`` has nowhere to record provenance, so a ``fromEnv`` binding
    resolved this way is not reproducible on export — an argument for leaving
    sealing on.

    Args:
        spec (dict): The ``Secret`` spec, mutated in place.
        values (dict[str, SecretValue]): Resolved values for this secret.
        transform (Transform): Identity, or elides the value for a dry run.
    """
    for field in _AUTHORED_SOURCE_FIELDS:
        spec.pop(field, None)
    if values:
        spec["stringData"] = {k: transform(v.value) for k, v in values.items()}


def _fetch_sealing_key(base_url: str, token: str) -> str:
    """Fetch the instance's sealing public key.

    Args:
        base_url (str): The instance base URL (no trailing slash).
        token (str): Bearer token.

    Returns:
        str: The PEM-encoded public key.

    Raises:
        SystemExit: If the instance has no sealing key, or the request fails.
            Never falls back to uploading plaintext — that decision is the
            caller's to make explicitly with ``--no-seal``.
    """
    try:
        resp = httpx.get(
            f"{base_url}/api/gitops/sealing-key",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )
    except httpx.HTTPError as e:
        sys.exit(f"error: could not reach {base_url}: {e}")
    if resp.status_code == 404:
        sys.exit(
            "error: this instance does not have secret sealing configured, so "
            "secret values cannot be encrypted before upload. Configure "
            "GITOPS_SEALING_PRIVATE_KEY on the instance, or re-run with "
            "`seal: false` (--no-seal) to upload them as plaintext."
        )
    if resp.status_code != 200:
        sys.exit(
            f"error: could not fetch sealing key ({resp.status_code}): {resp.text}"
        )
    return resp.json()["public_key"]


def _resolve_sealing_key(
    pinned_pem: str, base_url: str, token: str
) -> rsa.RSAPublicKey:
    """Return the public key to seal with, pinned or fetched.

    A pinned key is never reconciled against the server: pinning exists precisely
    so that what the server says cannot influence the outcome.

    Args:
        pinned_pem (str): A pinned PEM public key, or empty to fetch.
        base_url (str): The instance base URL (no trailing slash).
        token (str): Bearer token, used only when fetching.

    Returns:
        rsa.RSAPublicKey: The sealing key.

    Raises:
        SystemExit: If a pinned key is malformed, or fetching fails.
    """
    source = "pinned" if pinned_pem else "fetched from the instance"
    pem = pinned_pem or _fetch_sealing_key(base_url, token)
    try:
        public_key = load_public_key(pem)
    except SealingError as e:
        sys.exit(f"error: {e}")
    print(
        f"Sealing secrets to key {key_fingerprint(public_key)} ({source}).",
        file=sys.stderr,
    )
    if not pinned_pem:
        print(
            "  note: the key was fetched over the same connection it protects. "
            "Pin it with `sealing-public-key` to also defend against an "
            "intermediary that terminates TLS.",
            file=sys.stderr,
        )
    return public_key


def _seal_transform(public_key: rsa.RSAPublicKey) -> Transform:
    """Build a transform that seals values to a public key.

    Args:
        public_key (rsa.RSAPublicKey): The instance's sealing key.

    Returns:
        Transform: Seals one value, exiting on an unusable key.
    """

    def transform(value: str) -> str:
        try:
            return seal(value, public_key)
        except SealingError as e:
            sys.exit(f"error: could not seal secret value: {e}")

    return transform


def _resolve_token(args: argparse.Namespace, base_url: str) -> str:
    """Obtain a bearer token from an API token or an email/password login.

    Args:
        args (argparse.Namespace): Parsed CLI args.
        base_url (str): The instance base URL (no trailing slash).

    Returns:
        str: A bearer token to send in the ``Authorization`` header.

    Raises:
        SystemExit: If no credentials are supplied or login fails.
    """
    token = args.token or os.environ.get("RAGNEROCK_API_TOKEN")
    if token:
        return token

    email = args.email or os.environ.get("RAGNEROCK_EMAIL")
    password = args.password or os.environ.get("RAGNEROCK_PASSWORD")
    if not (email and password):
        sys.exit(
            "error: no credentials. Provide --token/RAGNEROCK_API_TOKEN, or "
            "--email/--password (RAGNEROCK_EMAIL/RAGNEROCK_PASSWORD)."
        )
    try:
        resp = httpx.post(
            f"{base_url}/api/auth/login",
            data={"username": email, "password": password},
            timeout=30.0,
        )
    except httpx.HTTPError as e:
        sys.exit(f"error: could not reach {base_url}: {e}")
    if resp.status_code != 200:
        sys.exit(f"error: login failed ({resp.status_code}): {resp.text}")
    return resp.json()["access_token"]


def _apply(base_url: str, token: str, manifest: str) -> dict:
    """Upload the manifest to ``/api/gitops/apply`` and return the JSON report.

    Args:
        base_url (str): The instance base URL (no trailing slash).
        token (str): Bearer token.
        manifest (str): The multi-document YAML to apply.

    Returns:
        dict: The parsed ``ApplyResponse`` body.

    Raises:
        SystemExit: On transport error or a non-200 response.
    """
    try:
        resp = httpx.post(
            f"{base_url}/api/gitops/apply",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("manifest.yaml", manifest, "application/x-yaml")},
            timeout=120.0,
        )
    except httpx.HTTPError as e:
        sys.exit(f"error: could not reach {base_url}: {e}")
    if resp.status_code != 200:
        sys.exit(f"error: apply failed ({resp.status_code}): {resp.text}")
    return resp.json()


def _print_report(report: dict, use_color: bool) -> bool:
    """Print the per-object summary and return whether the apply was clean.

    Args:
        report (dict): The ``ApplyResponse`` body.
        use_color (bool): Whether to colorize the action column.

    Returns:
        bool: ``report["ok"]`` — True when there were no errors.
    """
    for err in report.get("structural_errors", []):
        print(f"  structural error: {err}", file=sys.stderr)

    results = report.get("results", [])
    if results:
        width = max(len(r["kind"]) for r in results)
        for r in results:
            action = r["action"]
            color = _ACTION_COLORS.get(action, "") if use_color else ""
            reset = _RESET if use_color and color else ""
            print(f"  {r['kind']:<{width}}  {r['name']}  {color}{action}{reset}")
            for err in r.get("errors", []):
                print(f"      ↳ {err}", file=sys.stderr)

    ok = report.get("ok", False)
    changed = sum(1 for r in results if r["action"] in ("created", "updated"))
    summary = (
        f"{'OK' if ok else 'FAILED'} — {changed} changed, {len(results)} object(s)"
    )
    print(f"\n{summary}")
    return ok


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        argparse.Namespace: The parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Discover and apply Ragnerock GitOps manifests to an instance.",
    )
    parser.add_argument(
        "path",
        type=Path,
        help="A manifest file, or a directory to walk recursively.",
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("RAGNEROCK_API_URL", "http://localhost:8080"),
        help="Instance base URL (default: $RAGNEROCK_API_URL or http://localhost:8080).",
    )
    parser.add_argument("--token", help="Personal API token (Bearer auth).")
    parser.add_argument("--email", help="Login email (with --password).")
    parser.add_argument("--password", help="Login password (with --email).")
    parser.add_argument(
        "--no-seal",
        action="store_true",
        help=(
            "Upload secret values as plaintext instead of encrypting them to the "
            "instance's public key. Only for instances with no sealing key."
        ),
    )
    parser.add_argument(
        "--sealing-public-key",
        default=os.environ.get("RAGNEROCK_SEALING_PUBLIC_KEY", ""),
        help=(
            "PEM public key to seal to, instead of fetching it from the instance. "
            "Pinning is what protects against a TLS-terminating intermediary."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the manifest that would be uploaded, with secret values elided.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point: discover manifests, seal secrets, apply, set exit code."""
    args = _parse_args()
    base_url = args.url.rstrip("/")

    files = _collect_files(args.path)
    loaded = _load_documents(files)
    kept = [(f, d) for (f, d) in loaded if _is_ragnerock_doc(d)]
    docs = [d for (_, d) in kept]

    if not docs:
        print(f"No Ragnerock manifests found under {args.path} — nothing to apply.")
        return

    contributing = sorted({f for (f, _) in kept})
    print(
        f"Discovered {len(docs)} Ragnerock manifest document(s) "
        f"in {len(contributing)} file(s) under {args.path}:",
        file=sys.stderr,
    )
    for f in contributing:
        print(f"  • {f}", file=sys.stderr)
    if len(loaded) > len(docs):
        print(
            f"Skipped {len(loaded) - len(docs)} non-Ragnerock document(s).",
            file=sys.stderr,
        )

    # Resolve and mask before anything else can echo a value into the log.
    specs = _secret_specs(docs)
    cloud_count = sum(
        len(spec.get(provider.value) or {})
        for _, spec in specs
        for provider in CloudProvider
    )
    fetcher = CloudSecretFetcher()
    secrets = [
        (name, spec, _resolve_values(name, spec, fetcher)) for name, spec in specs
    ]
    for _, _, values in secrets:
        for resolved in values.values():
            _mask(resolved.value)

    key_count = sum(len(values) for _, _, values in secrets)
    env_count = sum(
        1 for _, _, values in secrets for v in values.values() if v.from_env
    )
    if env_count:
        print(f"Resolved {env_count} fromEnv secret key(s) locally.", file=sys.stderr)
    if cloud_count:
        print(
            f"Resolved {cloud_count} secret key(s) from cloud secret managers.",
            file=sys.stderr,
        )

    if args.no_seal and key_count and os.environ.get("GITHUB_ACTIONS") == "true":
        print(
            f"::warning::Sealing is disabled, so {key_count} secret value(s) will "
            f"be uploaded as plaintext in the request body. Remove `seal: false` "
            f"to encrypt them to the instance's public key.",
            flush=True,
        )

    # A dry run never contacts the server, so it never has a key to seal with —
    # and must never print material either. Eliding the values gives the real
    # upload shape without the secrets, and keeps dry runs credential-free.
    if args.dry_run:
        write = _write_inline if args.no_seal else _write_sealed
        for _, spec, values in secrets:
            write(spec, values, lambda _: _REDACTED)
        print("\n--- manifest to upload (dry run; secret values elided) ---\n")
        print(yaml.safe_dump_all(docs, sort_keys=False, default_flow_style=False))
        return

    token = _resolve_token(args, base_url)

    if args.no_seal:
        for _, spec, values in secrets:
            _write_inline(spec, values, lambda v: v)
    else:
        public_key = _resolve_sealing_key(args.sealing_public_key, base_url, token)
        transform = _seal_transform(public_key)
        for _, spec, values in secrets:
            _write_sealed(spec, values, transform)

    manifest = yaml.safe_dump_all(docs, sort_keys=False, default_flow_style=False)
    report = _apply(base_url, token, manifest)
    ok = _print_report(report, use_color=sys.stdout.isatty())
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
