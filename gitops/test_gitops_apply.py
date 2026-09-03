"""Tests for the GitOps action's applier script.

The applier is a standalone PEP-723 script rather than a package module, so it is
loaded here by path. Its cloud SDK imports are lazy, which is what lets these
tests stub the fetch seam without any cloud credentials in the environment.

Three properties matter most. First, **every authored source resolves here**,
before upload — ``stringData``/``data``/``fromEnv`` and the three cloud secret
managers — because the server resolves none of them; a reference that survives
into the manifest is a bug. Second, the fold into the wire-only
``encryptedData`` block must preserve every value, keep ``fromEnv`` provenance,
and never leave plaintext anywhere it could be uploaded or logged. Third, the
script carries its **own** copy of the wire contract so it can run against
nothing but PyPI, so that copy has to keep agreeing with the server's
(``ragnerock.sealing`` / ``ragnerock.gitops``) — the last section here is what
holds it there.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import patch

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from ragnerock import gitops as sdk_gitops
from ragnerock import sealing as sdk_sealing
from ragnerock.sealing import generate_sealing_key, is_sealed, unseal

_SCRIPT = Path(__file__).parent / "gitops_apply.py"


def _load_applier() -> ModuleType:
    """Import ``gitops_apply.py`` by path, since it is a script, not a module."""
    spec = importlib.util.spec_from_file_location("gitops_apply", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


applier = _load_applier()

# The applier's own wire models, not the SDK's — these tests exercise the copy
# that actually ships in the script. The SDK side is imported above only to
# check the two still agree, and to unseal the way the server does.
SecretSource = applier.SecretSource
SecretSourceType = applier.SecretSourceType

# Provenance for a value pasted straight into the manifest.
_INLINE = SecretSource(type=SecretSourceType.INLINE)


# RSA-4096 generation is slow; share one key across the module.
@pytest.fixture(scope="module")
def key() -> rsa.RSAPrivateKey:
    """Return the sealing key these tests seal to."""
    return generate_sealing_key()


def _secret_doc(spec: dict[str, Any]) -> dict[str, Any]:
    """Build a ``Secret`` manifest document around a spec."""
    return {
        "apiVersion": "ragnerock.com/v1alpha1",
        "kind": "Secret",
        "metadata": {"name": "creds"},
        "spec": spec,
    }


def _resolve(spec: dict[str, Any], name: str = "creds") -> dict[str, Any]:
    """Resolve a spec's sources with a fresh cloud-fetch cache."""
    return applier._resolve_values(name, spec, applier.CloudSecretFetcher())


def _gcp(**fields) -> tuple:
    """Parse a GCP reference, returning ``(GcpRef, json_field)``."""
    return applier._parse_gcp_ref(fields, "where")


def _aws(**fields) -> tuple:
    """Parse an AWS reference, returning ``(AwsRef, json_field)``."""
    return applier._parse_aws_ref(fields, "where")


def _azure(**fields) -> tuple:
    """Parse an Azure reference, returning ``(AzureRef, json_field)``."""
    return applier._parse_azure_ref(fields, "where")


# --------------------------------------------------------------------------- #
# Cloud reference parsing
# --------------------------------------------------------------------------- #


def test_gcp_short_id_defaults_version_and_project() -> None:
    """A short secret ID leaves the project to ADC and defaults the version."""
    ref, json_field = _gcp(secret="anthropic-api-key")
    assert ref == applier.GcpRef(None, "anthropic-api-key", "latest")
    assert json_field is None


def test_gcp_short_id_with_explicit_project_and_version() -> None:
    """Explicit project/version are carried through verbatim."""
    ref, _ = _gcp(secret="k", project="my-proj", version="3")
    assert ref == applier.GcpRef("my-proj", "k", "3")


def test_gcp_full_resource_name_without_version() -> None:
    """A resource name with no version pins the ``latest`` alias."""
    ref, _ = _gcp(secret="projects/p/secrets/s")
    assert ref == applier.GcpRef("p", "s", "latest")


def test_gcp_full_resource_name_with_version() -> None:
    """A fully-qualified resource name is decomposed into its parts.

    Accepting this form is what stops a console paste from needing manual
    disassembly.
    """
    ref, _ = _gcp(secret="projects/p/secrets/s/versions/7")
    assert ref == applier.GcpRef("p", "s", "7")


def test_gcp_full_resource_name_rejects_redundant_project() -> None:
    """Combining a resource name with `project` errors, rather than one winning."""
    with pytest.raises(SystemExit, match="already carries them"):
        _gcp(secret="projects/p/secrets/s", project="other")


def test_gcp_partial_resource_path_rejected() -> None:
    """A truncated resource name is an error, not a short ID with slashes."""
    with pytest.raises(SystemExit, match="complete resource name"):
        _gcp(secret="projects/p/secrets")


def test_gcp_short_id_with_slash_rejected() -> None:
    """A slash outside the ``projects/`` form cannot be a valid GCP secret ID."""
    with pytest.raises(SystemExit, match="short secret ID"):
        _gcp(secret="some/thing")


def test_gcp_unknown_field_rejected() -> None:
    """A misspelled field fails loudly rather than being silently dropped."""
    with pytest.raises(SystemExit, match=r"unknown field\(s\) jsonfield"):
        _gcp(secret="k", jsonfield="oops")


def test_gcp_requires_secret() -> None:
    """``secret`` is required."""
    with pytest.raises(SystemExit, match="requires a non-empty string 'secret'"):
        _gcp(project="p")


def test_aws_minimal_reference() -> None:
    """Only ``secretId`` is required; everything else defers to the environment."""
    ref, json_field = _aws(secretId="prod/db")
    assert ref == applier.AwsRef("prod/db", None, None, None)
    assert json_field is None


def test_aws_accepts_arn_and_json_field() -> None:
    """An ARN is accepted verbatim, because ``GetSecretValue`` accepts one."""
    arn = "arn:aws:secretsmanager:us-east-1:1:secret:prod/db-AbCdEf"
    ref, json_field = _aws(secretId=arn, region="us-east-1", jsonField="password")
    assert ref == applier.AwsRef(arn, "us-east-1", None, None)
    assert json_field == "password"


def test_aws_version_fields_are_mutually_exclusive() -> None:
    """Setting both version selectors is an error rather than one winning."""
    with pytest.raises(SystemExit, match="set one or neither"):
        _aws(secretId="s", versionStage="AWSCURRENT", versionId="abc")


def test_aws_either_version_field_alone_is_fine() -> None:
    """Each version selector is valid on its own."""
    staged, _ = _aws(secretId="s", versionStage="AWSPREVIOUS")
    pinned, _ = _aws(secretId="s", versionId="abc")
    assert staged.version_stage == "AWSPREVIOUS"
    assert pinned.version_id == "abc"


def test_azure_reference_normalizes_trailing_slash() -> None:
    """A pasted vault URL with a trailing slash still matches an unslashed one."""
    ref, _ = _azure(vaultUrl="https://v.vault.azure.net/", secret="k")
    assert ref == applier.AzureRef("https://v.vault.azure.net", "k", None)


def test_azure_rejects_non_https_vault_url() -> None:
    """A bare vault name is rejected in favour of the full URL."""
    with pytest.raises(SystemExit, match="full https:// vault URL"):
        _azure(vaultUrl="my-vault", secret="k")


def test_azure_sovereign_cloud_url_accepted() -> None:
    """Taking the full URL is what makes sovereign clouds work without a knob."""
    ref, _ = _azure(vaultUrl="https://v.vault.usgovcloudapi.net", secret="k")
    assert ref.vault_url == "https://v.vault.usgovcloudapi.net"


def test_reference_block_must_be_a_mapping() -> None:
    """A bare string where a reference belongs names the structured form."""
    with pytest.raises(SystemExit, match="must be a mapping"):
        applier._parse_gcp_ref("just-a-string", "where")


def test_parse_refs_rejects_non_mapping_block() -> None:
    """A provider block that is not a key→reference mapping fails loudly."""
    with pytest.raises(SystemExit, match="mapping of key -> reference"):
        applier._parse_refs(applier.CloudProvider.GCP, ["nope"], "s")


# --------------------------------------------------------------------------- #
# jsonField extraction
# --------------------------------------------------------------------------- #


def test_json_field_extracts_string() -> None:
    """The common case: one field out of an RDS-style credentials blob."""
    payload = json.dumps({"username": "u", "password": "p"})
    assert applier._extract_json_field(payload, "password", "where") == "p"


@pytest.mark.parametrize(
    ("value", "expected"),
    [(5432, "5432"), (1.5, "1.5"), (True, "true"), (False, "false")],
)
def test_json_field_renders_scalars_as_json(value: object, expected: str) -> None:
    """Numbers and booleans render as JSON, so ``true`` does not become ``True``."""
    payload = json.dumps({"f": value})
    assert applier._extract_json_field(payload, "f", "where") == expected


@pytest.mark.parametrize("value", [{"nested": 1}, [1, 2], None])
def test_json_field_rejects_non_scalar(value: object) -> None:
    """A non-scalar field has no unambiguous string form, so it is refused."""
    payload = json.dumps({"f": value})
    with pytest.raises(SystemExit, match="string, number, or boolean"):
        applier._extract_json_field(payload, "f", "where")


def test_json_field_absent_field() -> None:
    """A missing field names itself, so the typo is obvious."""
    with pytest.raises(SystemExit, match="no JSON field 'b'"):
        applier._extract_json_field('{"a": 1}', "b", "where")


def test_json_field_on_non_json_payload() -> None:
    """Asking for a field of a plain-string secret is a configuration error."""
    with pytest.raises(SystemExit, match="not JSON"):
        applier._extract_json_field("sk-plain-value", "f", "where")


def test_json_field_on_json_array() -> None:
    """A JSON array has no fields to extract."""
    with pytest.raises(SystemExit, match="not a JSON object"):
        applier._extract_json_field("[1, 2]", "f", "where")


def test_json_field_error_never_echoes_the_payload() -> None:
    """A failed extraction must not spill the secret it failed to parse."""
    with pytest.raises(SystemExit) as exc:
        applier._extract_json_field("sk-super-secret-value", "f", "where")
    assert "sk-super-secret-value" not in str(exc.value)


# --------------------------------------------------------------------------- #
# Cloud fetch caching
# --------------------------------------------------------------------------- #


def test_fetcher_caches_by_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two keys naming one remote secret cost one API call.

    The cache is keyed on the reference alone, so differing ``jsonField``
    extractions of the same secret still share the fetch.
    """
    calls: list[object] = []

    def fake_fetch(ref: object) -> str:
        calls.append(ref)
        return json.dumps({"user": "u", "pass": "p"})

    monkeypatch.setattr(applier, "_fetch", fake_fetch)
    fetcher = applier.CloudSecretFetcher()
    ref = applier.AwsRef("prod/db", None, None, None)

    user = fetcher.resolve(applier.CloudBinding("u", ref, "user", {}), "where")
    password = fetcher.resolve(applier.CloudBinding("p", ref, "pass", {}), "where")

    assert (user, password) == ("u", "p")
    assert len(calls) == 1


def test_fetcher_does_not_conflate_distinct_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Differing versions of one secret are different fetches."""
    calls: list[object] = []

    def fake_fetch(ref: object) -> str:
        calls.append(ref)
        return "value"

    monkeypatch.setattr(applier, "_fetch", fake_fetch)
    fetcher = applier.CloudSecretFetcher()
    fetcher.resolve(
        applier.CloudBinding("a", applier.GcpRef("p", "s", "1"), None, {}), "where"
    )
    fetcher.resolve(
        applier.CloudBinding("b", applier.GcpRef("p", "s", "2"), None, {}), "where"
    )
    assert len(calls) == 2


def test_missing_sdk_names_the_package() -> None:
    """A vendored copy without the SDKs says exactly what to install."""
    with pytest.raises(SystemExit, match="azure-keyvault-secrets azure-identity"):
        applier._exit_missing_sdk(applier.CloudProvider.AZURE)


# --------------------------------------------------------------------------- #
# Source resolution
# --------------------------------------------------------------------------- #


@pytest.fixture
def stub_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the cloud fetch seam with a deterministic per-reference value."""
    monkeypatch.setattr(
        applier, "_fetch", lambda ref: f"value-for-{type(ref).__name__}"
    )


@pytest.mark.usefixtures("stub_fetch")
def test_resolves_every_source(monkeypatch: pytest.MonkeyPatch) -> None:
    """All six authored sources resolve, with provenance only where it exists."""
    monkeypatch.setenv("SOME_VAR", "from-the-environment")
    spec: dict[str, Any] = {
        "stringData": {"a": "inline"},
        # base64 of "decoded"
        "data": {"b": "ZGVjb2RlZA=="},
        "fromEnv": {"c": "SOME_VAR"},
        "fromGcpSecretManager": {"d": {"secret": "s", "project": "p"}},
        "fromAwsSecretsManager": {"e": {"secretId": "s"}},
        "fromAzureKeyVault": {
            "f": {"vaultUrl": "https://v.vault.azure.net", "secret": "s"}
        },
    }

    values = _resolve(spec)

    assert values["a"] == ("inline", _INLINE)
    assert values["b"] == ("decoded", _INLINE)
    assert values["c"] == (
        "from-the-environment",
        SecretSource(type=SecretSourceType.FROM_ENV, env="SOME_VAR"),
    )
    # Cloud keys carry the authored reference verbatim, so an export re-emits
    # exactly what was written.
    assert values["d"] == (
        "value-for-GcpRef",
        SecretSource(
            type=SecretSourceType.FROM_GCP_SECRET_MANAGER,
            ref={"secret": "s", "project": "p"},
        ),
    )
    assert values["e"] == (
        "value-for-AwsRef",
        SecretSource(
            type=SecretSourceType.FROM_AWS_SECRETS_MANAGER, ref={"secretId": "s"}
        ),
    )
    assert values["f"] == (
        "value-for-AzureRef",
        SecretSource(
            type=SecretSourceType.FROM_AZURE_KEY_VAULT,
            ref={"vaultUrl": "https://v.vault.azure.net", "secret": "s"},
        ),
    )
    # Resolution reads the spec; rewriting it is the write step's job.
    assert set(spec) == set(applier._AUTHORED_SOURCE_FIELDS)


def test_key_in_two_sources_is_rejected() -> None:
    """One source per key, matching the rule the server enforces."""
    spec: dict[str, Any] = {"stringData": {"a": "inline"}, "fromEnv": {"a": "SOME_VAR"}}
    with pytest.raises(SystemExit, match="more than one source"):
        _resolve(spec)


@pytest.mark.usefixtures("stub_fetch")
def test_cloud_source_collides_with_inline_source() -> None:
    """The one-source rule covers cloud sources too, not just the authored three."""
    spec: dict[str, Any] = {
        "stringData": {"k": "inline"},
        "fromGcpSecretManager": {"k": {"secret": "s", "project": "p"}},
    }
    with pytest.raises(SystemExit, match="more than one source"):
        _resolve(spec)


@pytest.mark.usefixtures("stub_fetch")
def test_cloud_sources_collide_with_each_other() -> None:
    """The collision check spans providers, not just cloud-versus-inline."""
    spec: dict[str, Any] = {
        "fromGcpSecretManager": {"k": {"secret": "s", "project": "p"}},
        "fromAwsSecretsManager": {"k": {"secretId": "s"}},
    }
    with pytest.raises(SystemExit, match="more than one source"):
        _resolve(spec)


def test_malformed_reference_fails_before_any_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every reference is parsed before the first one is fetched.

    A typo in the last block must not leave earlier secrets already pulled out of
    a cloud provider.
    """
    fetched: list[object] = []
    monkeypatch.setattr(applier, "_fetch", lambda ref: fetched.append(ref) or "v")
    spec: dict[str, Any] = {
        "fromAwsSecretsManager": {"good": {"secretId": "s"}},
        "fromAzureKeyVault": {"bad": {"vaultUrl": "not-a-url", "secret": "s"}},
    }
    with pytest.raises(SystemExit):
        _resolve(spec)
    assert fetched == []


def test_invalid_base64_is_rejected() -> None:
    """Malformed ``data`` fails before upload rather than at the server."""
    with pytest.raises(SystemExit, match="not valid base64"):
        _resolve({"data": {"a": "!!!not base64!!!"}})


def test_unset_environment_variable_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing variable fails the run before anything is sent.

    The server no longer resolves ``fromEnv`` at all, so this is the only place
    the check exists.
    """
    monkeypatch.delenv("MISSING_VAR", raising=False)
    with pytest.raises(SystemExit, match="MISSING_VAR"):
        _resolve({"fromEnv": {"a": "MISSING_VAR"}})


# --------------------------------------------------------------------------- #
# Sealing the upload
# --------------------------------------------------------------------------- #


def test_sealed_upload_carries_no_plaintext(
    monkeypatch: pytest.MonkeyPatch, key: rsa.RSAPrivateKey
) -> None:
    """The serialized manifest contains no secret value, only sealed blobs."""
    monkeypatch.setenv("SOME_VAR", "env-secret-value")
    spec: dict[str, Any] = {
        "stringData": {"a": "inline-secret-value"},
        "data": {"b": "ZGVjb2RlZA=="},
        "fromEnv": {"c": "SOME_VAR"},
    }
    doc = _secret_doc(spec)
    values = _resolve(spec)

    applier._write_sealed(spec, values, applier._seal_transform(key.public_key()))
    manifest = yaml.safe_dump_all([doc])

    for plaintext in ("inline-secret-value", "decoded", "env-secret-value"):
        assert plaintext not in manifest
    # The authored sources are gone; only the wire block remains.
    assert set(spec) == {"encryptedData"}
    assert all(is_sealed(e["ciphertext"]) for e in spec["encryptedData"].values())


def test_sealed_values_unseal_to_the_originals(
    monkeypatch: pytest.MonkeyPatch, key: rsa.RSAPrivateKey
) -> None:
    """Round trip: what the server unseals is what the manifest meant."""
    monkeypatch.setenv("SOME_VAR", "env-secret-value")
    spec: dict[str, Any] = {
        "stringData": {"a": "inline-secret-value"},
        "data": {"b": "ZGVjb2RlZA=="},
        "fromEnv": {"c": "SOME_VAR"},
    }
    values = _resolve(spec)

    applier._write_sealed(spec, values, applier._seal_transform(key.public_key()))

    opened = {k: unseal(e["ciphertext"], key) for k, e in spec["encryptedData"].items()}
    assert opened == {
        "a": "inline-secret-value",
        "b": "decoded",
        "c": "env-secret-value",
    }


@pytest.mark.usefixtures("stub_fetch")
def test_cloud_values_are_sealed_like_any_other(key: rsa.RSAPrivateKey) -> None:
    """A cloud-fetched value reaches the wire sealed, not inlined.

    Cloud sources resolve to ordinary material, so they ride the same transport
    as everything else rather than needing a path of their own.
    """
    spec: dict[str, Any] = {
        "fromGcpSecretManager": {"d": {"secret": "s", "project": "p"}}
    }
    values = _resolve(spec)

    applier._write_sealed(spec, values, applier._seal_transform(key.public_key()))

    assert set(spec) == {"encryptedData"}
    assert unseal(spec["encryptedData"]["d"]["ciphertext"], key) == "value-for-GcpRef"


def test_from_env_provenance_survives_sealing(
    monkeypatch: pytest.MonkeyPatch, key: rsa.RSAPrivateKey
) -> None:
    """The binding is carried alongside the blob so export still round-trips it."""
    monkeypatch.setenv("SOME_VAR", "env-secret-value")
    spec: dict[str, Any] = {"stringData": {"a": "inline"}, "fromEnv": {"c": "SOME_VAR"}}
    values = _resolve(spec)

    applier._write_sealed(spec, values, applier._seal_transform(key.public_key()))

    assert spec["encryptedData"]["c"]["source"] == {
        "type": "fromEnv",
        "env": "SOME_VAR",
    }
    assert spec["encryptedData"]["a"]["source"] == {"type": "inline"}


@pytest.mark.usefixtures("stub_fetch")
def test_write_sealed_strips_every_authored_source(key: rsa.RSAPrivateKey) -> None:
    """No authored source may survive into the upload — the server rejects them."""
    spec: dict[str, Any] = {
        "description": "kept",
        "stringData": {"a": "x"},
        "data": {"b": "eQ=="},
        "fromEnv": {"c": "SOME_VAR"},
        "fromGcpSecretManager": {"d": {"secret": "s", "project": "p"}},
        "fromAwsSecretsManager": {"e": {"secretId": "s"}},
        "fromAzureKeyVault": {
            "f": {"vaultUrl": "https://v.vault.azure.net", "secret": "s"}
        },
    }
    values = {"a": applier.SecretValue("x", _INLINE)}

    applier._write_sealed(spec, values, applier._seal_transform(key.public_key()))

    assert set(spec) == {"description", "encryptedData"}


def test_offline_fetcher_parses_references_without_contacting_a_provider() -> None:
    """A dry run validates cloud references but reaches nothing.

    Fetching would demand a GCP, an AWS, and an Azure identity to render a
    manifest nobody uploads — and the dry run elides every value anyway. The
    grammar check is the part worth keeping, so it stays.
    """
    calls: list[object] = []

    def _explode(ref: object) -> str:
        calls.append(ref)
        raise AssertionError("a dry run must not fetch")

    spec: dict[str, Any] = {
        "fromAzureKeyVault": {
            "k": {"vaultUrl": "https://unreachable.vault.azure.net", "secret": "s"}
        }
    }
    with patch.object(applier, "_fetch", _explode):
        values = applier._resolve_values(
            "s", spec, applier.CloudSecretFetcher(offline=True)
        )

    assert calls == []
    assert values["k"].source.type is SecretSourceType.FROM_AZURE_KEY_VAULT
    assert values["k"].source.ref == {
        "vaultUrl": "https://unreachable.vault.azure.net",
        "secret": "s",
    }


def test_offline_fetcher_still_rejects_a_malformed_reference() -> None:
    """Skipping the fetch does not skip the grammar."""
    spec: dict[str, Any] = {"fromAzureKeyVault": {"k": {"vaultUrl": "http://insecure"}}}
    with pytest.raises(SystemExit, match="https://"):
        applier._resolve_values("s", spec, applier.CloudSecretFetcher(offline=True))


def test_authored_source_fields_match_the_cloud_providers() -> None:
    """The strip list and the provider enum cannot drift apart."""
    assert set(applier._AUTHORED_SOURCE_FIELDS) == {
        "stringData",
        "data",
        "fromEnv",
    } | {p.value for p in applier.CloudProvider}


# --------------------------------------------------------------------------- #
# The unsealed path and dry runs
# --------------------------------------------------------------------------- #


def test_unsealed_path_inlines_into_string_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--no-seal`` reproduces the pre-sealing behaviour."""
    monkeypatch.setenv("SOME_VAR", "env-secret-value")
    spec: dict[str, Any] = {"data": {"b": "ZGVjb2RlZA=="}, "fromEnv": {"c": "SOME_VAR"}}
    values = _resolve(spec)

    applier._write_inline(spec, values, lambda v: v)

    assert spec == {"stringData": {"b": "decoded", "c": "env-secret-value"}}


@pytest.mark.usefixtures("stub_fetch")
def test_unsealed_path_strips_cloud_sources() -> None:
    """The ``--no-seal`` path consumes the same sources the sealed one does."""
    spec: dict[str, Any] = {
        "fromGcpSecretManager": {"d": {"secret": "s", "project": "p"}}
    }
    values = _resolve(spec)

    applier._write_inline(spec, values, lambda v: v)

    assert spec == {"stringData": {"d": "value-for-GcpRef"}}


@pytest.mark.parametrize("write", ["_write_sealed", "_write_inline"])
def test_dry_run_elides_values(monkeypatch: pytest.MonkeyPatch, write: str) -> None:
    """A dry run prints the upload shape without any secret material.

    This is the leak the previous implementation had: it resolved ``fromEnv`` and
    printed the result straight into the workflow log.
    """
    monkeypatch.setenv("SOME_VAR", "env-secret-value")
    spec: dict[str, Any] = {
        "stringData": {"a": "inline-secret-value"},
        "fromEnv": {"c": "SOME_VAR"},
    }
    doc = _secret_doc(spec)
    values = _resolve(spec)

    getattr(applier, write)(spec, values, lambda _: applier._REDACTED)
    printed = yaml.safe_dump_all([doc])

    assert "inline-secret-value" not in printed
    assert "env-secret-value" not in printed
    assert applier._REDACTED in printed


# --------------------------------------------------------------------------- #
# Log masking
# --------------------------------------------------------------------------- #


def test_mask_covers_each_line_of_a_multiline_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Multi-line secrets need per-line masks; a single mask does not cover them."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    applier._mask("-----BEGIN KEY-----\nsecretline\n-----END KEY-----")

    emitted = capsys.readouterr().out
    assert "::add-mask::secretline" in emitted
    assert "::add-mask::-----BEGIN KEY-----" in emitted


def test_mask_skips_short_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Masking a very short string would blank unrelated log text."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    applier._mask("ab")

    assert capsys.readouterr().out == ""


def test_mask_is_a_noop_outside_actions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Workflow commands are meaningless on a developer's terminal."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    applier._mask("a-real-looking-secret")

    assert capsys.readouterr().out == ""


# --------------------------------------------------------------------------- #
# Document discovery and CLI surface
# --------------------------------------------------------------------------- #


def test_only_secret_documents_are_rewritten() -> None:
    """Other kinds reference secrets by name and carry no material."""
    docs = [
        _secret_doc({"stringData": {"a": "v"}}),
        {
            "apiVersion": "ragnerock.com/v1alpha1",
            "kind": "Agent",
            "metadata": {"name": "scorer"},
            "spec": {"generationPrompt": "go"},
        },
        {"kind": "Secret", "spec": None},
    ]

    found = applier._secret_specs(docs)

    assert [name for name, _ in found] == ["creds"]


def test_manifest_without_secret_values_never_asks_for_a_sealing_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sealing is only a requirement when there is something to seal.

    Fetching the key unconditionally made every apply depend on the instance
    having ``GITOPS_SEALING_PRIVATE_KEY`` set, so a manifest set with no
    ``Secret`` in it — the common case — failed on an instance that had no use
    for sealing at all.
    """
    (tmp_path / "manifest.yaml").write_text(
        yaml.safe_dump(
            {
                "apiVersion": "ragnerock.com/v1alpha1",
                "kind": "Agent",
                "metadata": {"name": "scorer"},
                "spec": {"generationPrompt": "go"},
            }
        )
    )
    monkeypatch.setattr(sys, "argv", ["gitops_apply.py", str(tmp_path)])
    monkeypatch.setattr(applier, "_resolve_token", lambda *_: "token")
    monkeypatch.setattr(
        applier,
        "_fetch_sealing_key",
        lambda *_: pytest.fail("asked for a sealing key with nothing to seal"),
    )
    applied: dict[str, Any] = {}

    def fake_apply(base_url: str, token: str, manifest: str, dry_run: bool) -> dict:
        applied["manifest"] = manifest
        return {"ok": True, "results": [], "dry_run": dry_run}

    monkeypatch.setattr(applier, "_apply", fake_apply)

    with pytest.raises(SystemExit) as exc:
        applier.main()

    assert exc.value.code == 0
    assert "scorer" in applied["manifest"]


def test_no_resolve_env_flag_is_gone(monkeypatch: pytest.MonkeyPatch) -> None:
    """Server-side ``fromEnv`` resolution is removed, so its flag must be too.

    It let any account with `create` on the secret noun read arbitrary process
    environment off the API pod. Silently accepting the flag would leave callers
    believing they still had that behaviour.
    """
    monkeypatch.setattr(sys, "argv", ["gitops_apply.py", ".", "--no-resolve-env"])
    with pytest.raises(SystemExit) as exc:
        applier._parse_args()
    assert exc.value.code == 2


# --------------------------------------------------------------------------- #
# The vendored wire contract
#
# The applier ships standalone, so it carries its own copy of the seal format
# and the encryptedData models rather than importing them from the SDK. Nothing
# at run time notices when the two diverge: the wire format has no version
# negotiation, and the applier would happily seal blobs the target instance
# cannot open. These tests are the check that does notice.
# --------------------------------------------------------------------------- #


def test_secret_source_type_matches_the_sdk() -> None:
    """The provenance tokens the server stores are the ones the applier writes."""
    assert {m.name: m.value for m in applier.SecretSourceType} == {
        m.name: m.value for m in sdk_gitops.SecretSourceType
    }


def _contract(schema: object) -> object:
    """Strip docstring-derived prose from a JSON schema, recursively.

    Both copies document themselves for their own reader, so the descriptions
    are expected to differ. What has to match is the shape.

    Args:
        schema (object): A JSON schema fragment.

    Returns:
        object: The fragment without any ``description`` keys.
    """
    if isinstance(schema, dict):
        return {k: _contract(v) for k, v in schema.items() if k != "description"}
    if isinstance(schema, list):
        return [_contract(v) for v in schema]
    return schema


@pytest.mark.parametrize("model", ["SecretSource", "SealedSecretEntry"])
def test_wire_models_match_the_sdk(model: str) -> None:
    """Same fields, same types, same optionality, same extra-field policy."""
    assert _contract(getattr(applier, model).model_json_schema()) == _contract(
        getattr(sdk_gitops, model).model_json_schema()
    )


def test_seal_format_tokens_match_the_sdk() -> None:
    """The prefix and version the server dispatches on."""
    assert applier.SEALED_PREFIX == sdk_sealing.SEALED_PREFIX
    assert applier.SEALED_VERSION == sdk_sealing.SEALED_VERSION


def test_fingerprint_matches_the_sdk(key: rsa.RSAPrivateKey) -> None:
    """A pinned key's fingerprint must be the one the instance reports for it.

    The fingerprint is what an operator compares across the two sides, so a
    difference in how it is computed would read as a swapped key.
    """
    public_key = key.public_key()
    assert applier.key_fingerprint(public_key) == sdk_sealing.key_fingerprint(
        public_key
    )


def test_applier_imports_nothing_from_the_ragnerock_packages() -> None:
    """The script must run against PyPI alone, in a repo-free pipeline.

    An import of a Ragnerock package works in this repository and fails for
    every customer, which is not something to leave to review to catch. The
    whole module is walked rather than just its header, since the applier does
    use function-local imports for the cloud SDKs.
    """
    imported: set[str] = set()
    for node in ast.walk(ast.parse(_SCRIPT.read_text())):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)

    roots = {name.split(".")[0] for name in imported}
    assert "ragnerock" not in roots
    assert "core" not in roots
