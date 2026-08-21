"""Tests for the GitOps applier's secret resolution.

The applier (``actions/gitops/gitops_apply.py``) is a standalone PEP-723 script
rather than a package module, so it is loaded here by path. Its cloud SDK
imports are lazy, which is what lets these tests stub the fetch seam without any
cloud credentials in the environment.

The property under test throughout is that **every authored source resolves
here**, before upload: the server resolves none of them, so a reference that
survives into the manifest is a bug, and a value that reaches the log is a leak.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "gitops_apply.py"


def _load_applier() -> ModuleType:
    """Import the standalone applier script as a module.

    Returns:
        ModuleType: The loaded module.

    Raises:
        ImportError: If the script cannot be loaded from disk.
    """
    spec = importlib.util.spec_from_file_location("gitops_apply", _SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


applier = _load_applier()


def _gcp(**fields) -> tuple:
    """Parse a GCP reference, returning ``(ref, json_field)``.

    Args:
        **fields: Reference block fields.

    Returns:
        tuple: The ``(GcpRef, json_field)`` tuple.
    """
    return applier._parse_gcp_ref(fields, "where")


def _aws(**fields) -> tuple:
    """Parse an AWS reference, returning ``(ref, json_field)``.

    Args:
        **fields: Reference block fields.

    Returns:
        tuple: The ``(AwsRef, json_field)`` tuple.
    """
    return applier._parse_aws_ref(fields, "where")


def _azure(**fields) -> tuple:
    """Parse an Azure reference, returning ``(ref, json_field)``.

    Args:
        **fields: Reference block fields.

    Returns:
        tuple: The ``(AzureRef, json_field)`` tuple.
    """
    return applier._parse_azure_ref(fields, "where")


# --------------------------------------------------------------------------
# Reference parsing
# --------------------------------------------------------------------------


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
    """A fully-qualified resource name is decomposed into its parts."""
    ref, _ = _gcp(secret="projects/p/secrets/s/versions/7")
    assert ref == applier.GcpRef("p", "s", "7")


def test_gcp_full_resource_name_rejects_redundant_project() -> None:
    """Combining a resource name with `project` is an error, not a precedence rule."""
    with pytest.raises(SystemExit) as exc:
        _gcp(secret="projects/p/secrets/s", project="other")
    assert "already carries them" in str(exc.value)


def test_gcp_partial_resource_path_rejected() -> None:
    """A truncated resource name is an error rather than a slashed short ID."""
    with pytest.raises(SystemExit) as exc:
        _gcp(secret="projects/p/secrets")
    assert "complete resource name" in str(exc.value)


def test_gcp_short_id_with_slash_rejected() -> None:
    """A slash outside the ``projects/`` form cannot be a valid GCP secret ID."""
    with pytest.raises(SystemExit) as exc:
        _gcp(secret="some/thing")
    assert "short secret ID" in str(exc.value)


def test_gcp_unknown_field_rejected() -> None:
    """A misspelled field fails loudly rather than being silently dropped."""
    with pytest.raises(SystemExit) as exc:
        _gcp(secret="k", jsonfield="oops")
    assert "unknown field(s) jsonfield" in str(exc.value)


def test_gcp_requires_secret() -> None:
    """``secret`` is required."""
    with pytest.raises(SystemExit) as exc:
        _gcp(project="p")
    assert "requires a non-empty string 'secret'" in str(exc.value)


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
    with pytest.raises(SystemExit) as exc:
        _aws(secretId="s", versionStage="AWSCURRENT", versionId="abc")
    assert "set one or neither" in str(exc.value)


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
    with pytest.raises(SystemExit) as exc:
        _azure(vaultUrl="my-vault", secret="k")
    assert "full https:// vault URL" in str(exc.value)


def test_azure_sovereign_cloud_url_accepted() -> None:
    """Taking the full URL is what makes sovereign clouds work without a knob."""
    ref, _ = _azure(vaultUrl="https://v.vault.usgovcloudapi.net", secret="k")
    assert ref.vault_url == "https://v.vault.usgovcloudapi.net"


def test_reference_block_must_be_a_mapping() -> None:
    """A bare string where a reference belongs names the structured form."""
    with pytest.raises(SystemExit) as exc:
        applier._parse_gcp_ref("just-a-string", "where")
    assert "must be a mapping" in str(exc.value)


def test_parse_refs_rejects_non_mapping_block() -> None:
    """A provider block that is not a key→reference mapping fails loudly."""
    with pytest.raises(SystemExit) as exc:
        applier._parse_refs(applier.CloudProvider.GCP, ["nope"], "s")
    assert "mapping of key -> reference" in str(exc.value)


# --------------------------------------------------------------------------
# jsonField extraction
# --------------------------------------------------------------------------


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


def test_json_field_rejects_non_scalar() -> None:
    """A nested object has no unambiguous string form, so it is refused."""
    payload = json.dumps({"f": {"nested": 1}})
    with pytest.raises(SystemExit) as exc:
        applier._extract_json_field(payload, "f", "where")
    assert "string, number, or boolean" in str(exc.value)


def test_json_field_rejects_null() -> None:
    """A null field is an absent value, not an empty string."""
    payload = json.dumps({"f": None})
    with pytest.raises(SystemExit) as exc:
        applier._extract_json_field(payload, "f", "where")
    assert "string, number, or boolean" in str(exc.value)


def test_json_field_absent_field() -> None:
    """A missing field names itself, so the typo is obvious."""
    with pytest.raises(SystemExit) as exc:
        applier._extract_json_field('{"a": 1}', "b", "where")
    assert "no JSON field 'b'" in str(exc.value)


def test_json_field_on_non_json_payload() -> None:
    """Asking for a field of a plain-string secret is a configuration error."""
    with pytest.raises(SystemExit) as exc:
        applier._extract_json_field("sk-plain-value", "f", "where")
    assert "not JSON" in str(exc.value)


def test_json_field_on_json_array() -> None:
    """A JSON array has no fields to extract."""
    with pytest.raises(SystemExit) as exc:
        applier._extract_json_field("[1, 2]", "f", "where")
    assert "not a JSON object" in str(exc.value)


def test_json_field_error_never_echoes_the_payload() -> None:
    """A failed extraction must not spill the secret it failed to parse."""
    with pytest.raises(SystemExit) as exc:
        applier._extract_json_field("sk-super-secret-value", "f", "where")
    assert "sk-super-secret-value" not in str(exc.value)


# --------------------------------------------------------------------------
# Fetch caching
# --------------------------------------------------------------------------


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

    user = fetcher.resolve(applier.CloudBinding("u", ref, "user"), "where")
    password = fetcher.resolve(applier.CloudBinding("p", ref, "pass"), "where")

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
        applier.CloudBinding("a", applier.GcpRef("p", "s", "1"), None), "where"
    )
    fetcher.resolve(
        applier.CloudBinding("b", applier.GcpRef("p", "s", "2"), None), "where"
    )
    assert len(calls) == 2


def test_missing_sdk_names_the_package() -> None:
    """A vendored copy without the SDKs says exactly what to install."""
    with pytest.raises(SystemExit) as exc:
        applier._exit_missing_sdk(applier.CloudProvider.AZURE)
    assert "azure-keyvault-secrets azure-identity" in str(exc.value)


# --------------------------------------------------------------------------
# Resolution across all sources
# --------------------------------------------------------------------------


@pytest.fixture
def stub_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the cloud fetch seam with a deterministic per-reference value.

    Args:
        monkeypatch (pytest.MonkeyPatch): Patching fixture.
    """
    monkeypatch.setattr(
        applier, "_fetch", lambda ref: f"value-for-{type(ref).__name__}"
    )


@pytest.mark.usefixtures("stub_fetch")
def test_resolve_values_covers_every_source(monkeypatch: pytest.MonkeyPatch) -> None:
    """All six authored sources resolve in one pass, without mutating the spec."""
    monkeypatch.setenv("SOME_VAR", "from-the-environment")
    spec = {
        "stringData": {"a": "inline"},
        "data": {"b": "aW5saW5lLWI="},
        "fromEnv": {"c": "SOME_VAR"},
        "fromGcpSecretManager": {"d": {"secret": "s", "project": "p"}},
        "fromAwsSecretsManager": {"e": {"secretId": "s"}},
        "fromAzureKeyVault": {
            "f": {"vaultUrl": "https://v.vault.azure.net", "secret": "s"}
        },
    }
    values = applier._resolve_values("s", spec, applier.CloudSecretFetcher())

    assert values["a"].value == "inline"
    assert values["b"].value == "inline-b"
    assert values["c"] == applier.SecretValue("from-the-environment", "SOME_VAR")
    assert values["d"].value == "value-for-GcpRef"
    assert values["e"].value == "value-for-AwsRef"
    assert values["f"].value == "value-for-AzureRef"
    # Resolution reads the spec; rewriting it is the write step's job.
    assert set(spec) == {
        "stringData",
        "data",
        "fromEnv",
        "fromGcpSecretManager",
        "fromAwsSecretsManager",
        "fromAzureKeyVault",
    }


@pytest.mark.usefixtures("stub_fetch")
def test_cloud_source_collides_with_inline_source() -> None:
    """One key may come from exactly one source, cloud sources included."""
    spec = {
        "stringData": {"k": "inline"},
        "fromGcpSecretManager": {"k": {"secret": "s", "project": "p"}},
    }
    with pytest.raises(SystemExit) as exc:
        applier._resolve_values("dup", spec, applier.CloudSecretFetcher())
    assert "more than one source" in str(exc.value)


@pytest.mark.usefixtures("stub_fetch")
def test_cloud_sources_collide_with_each_other() -> None:
    """The collision check spans providers, not just cloud-versus-inline."""
    spec = {
        "fromGcpSecretManager": {"k": {"secret": "s", "project": "p"}},
        "fromAwsSecretsManager": {"k": {"secretId": "s"}},
    }
    with pytest.raises(SystemExit) as exc:
        applier._resolve_values("dup", spec, applier.CloudSecretFetcher())
    assert "more than one source" in str(exc.value)


def test_malformed_reference_fails_before_any_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every reference is parsed before the first one is fetched.

    A typo in the last block must not leave earlier secrets already pulled out
    of a cloud provider.
    """
    fetched: list[object] = []
    monkeypatch.setattr(applier, "_fetch", lambda ref: fetched.append(ref) or "v")
    spec = {
        "fromAwsSecretsManager": {"good": {"secretId": "s"}},
        "fromAzureKeyVault": {"bad": {"vaultUrl": "not-a-url", "secret": "s"}},
    }
    with pytest.raises(SystemExit):
        applier._resolve_values("s", spec, applier.CloudSecretFetcher())
    assert fetched == []


def test_unset_env_var_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    """``fromEnv`` is now resolved only here, so this is the only check for it."""
    monkeypatch.delenv("DEFINITELY_UNSET_XYZ", raising=False)
    with pytest.raises(SystemExit) as exc:
        applier._resolve_values(
            "s",
            {"fromEnv": {"k": "DEFINITELY_UNSET_XYZ"}},
            applier.CloudSecretFetcher(),
        )
    assert "DEFINITELY_UNSET_XYZ" in str(exc.value)


# --------------------------------------------------------------------------
# Writing the upload
# --------------------------------------------------------------------------


def test_write_sealed_strips_every_authored_source() -> None:
    """No authored source may survive into the upload — the server rejects them."""
    spec = {
        "description": "kept",
        "stringData": {"a": "x"},
        "data": {"b": "y"},
        "fromEnv": {"c": "V"},
        "fromGcpSecretManager": {"d": {"secret": "s"}},
        "fromAwsSecretsManager": {"e": {"secretId": "s"}},
        "fromAzureKeyVault": {
            "f": {"vaultUrl": "https://v.vault.azure.net", "secret": "s"}
        },
    }
    values = {
        "a": applier.SecretValue("x", None),
        "c": applier.SecretValue("z", "V"),
    }
    applier._write_sealed(spec, values, lambda v: f"sealed:{v}")

    assert set(spec) == {"description", "encryptedData"}
    assert spec["encryptedData"]["a"] == {"ciphertext": "sealed:x"}
    assert spec["encryptedData"]["c"] == {"ciphertext": "sealed:z", "fromEnv": "V"}


def test_write_inline_strips_every_authored_source() -> None:
    """The ``--no-seal`` path strips the same sources it consumed."""
    spec = {
        "fromGcpSecretManager": {"d": {"secret": "s"}},
        "fromEnv": {"c": "V"},
    }
    values = {"d": applier.SecretValue("x", None), "c": applier.SecretValue("z", "V")}
    applier._write_inline(spec, values, lambda v: v)

    assert set(spec) == {"stringData"}
    assert spec["stringData"] == {"d": "x", "c": "z"}


def test_authored_source_fields_match_the_cloud_providers() -> None:
    """The strip list and the provider enum cannot drift apart."""
    assert set(applier._AUTHORED_SOURCE_FIELDS) == {
        "stringData",
        "data",
        "fromEnv",
    } | {p.value for p in applier.CloudProvider}


# --------------------------------------------------------------------------
# Log hygiene and removed options
# --------------------------------------------------------------------------


def test_mask_emitted_under_github_actions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cloud-fetched values are registered as log masks.

    GitHub masks repository secrets by itself, but knows nothing about a value
    pulled from a secret manager mid-job.
    """
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    applier._mask("sk-fetched-from-the-vault")
    assert "::add-mask::sk-fetched-from-the-vault" in capsys.readouterr().out


def test_mask_is_a_noop_outside_github_actions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A local run must not print the value in the name of masking it."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    applier._mask("sk-fetched-from-the-vault")
    assert capsys.readouterr().out == ""


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
