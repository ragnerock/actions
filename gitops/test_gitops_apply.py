"""Tests for the GitOps action's applier script.

The applier is a standalone PEP-723 script rather than a package module, so it is
loaded here by path. What matters most is the fold from authored sources
(``stringData``/``data``/``fromEnv``) into the wire-only ``encryptedData`` block:
it must preserve every value, keep ``fromEnv`` provenance, and never leave
plaintext anywhere it could be uploaded or logged.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
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


# --------------------------------------------------------------------------- #
# Source resolution
# --------------------------------------------------------------------------- #


def test_resolves_every_source(monkeypatch: pytest.MonkeyPatch) -> None:
    """All three authored sources resolve, with provenance only where it exists."""
    monkeypatch.setenv("SOME_VAR", "from-the-environment")
    spec: dict[str, Any] = {
        "stringData": {"a": "inline"},
        # base64 of "decoded"
        "data": {"b": "ZGVjb2RlZA=="},
        "fromEnv": {"c": "SOME_VAR"},
    }

    values = applier._resolve_values("creds", spec, resolve_env=True)

    assert values["a"] == ("inline", None)
    assert values["b"] == ("decoded", None)
    assert values["c"] == ("from-the-environment", "SOME_VAR")


def test_no_resolve_env_leaves_from_env_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """``--no-resolve-env`` keeps those values out of the process entirely."""
    monkeypatch.setenv("SOME_VAR", "never-read")
    spec: dict[str, Any] = {"stringData": {"a": "inline"}, "fromEnv": {"c": "SOME_VAR"}}

    values = applier._resolve_values("creds", spec, resolve_env=False)

    assert set(values) == {"a"}


@pytest.mark.parametrize("resolve_env", [True, False])
def test_key_in_two_sources_is_rejected(resolve_env: bool) -> None:
    """One source per key, matching the rule the server enforces."""
    spec: dict[str, Any] = {"stringData": {"a": "inline"}, "fromEnv": {"a": "SOME_VAR"}}
    with pytest.raises(SystemExit, match="more than one source"):
        applier._resolve_values("creds", spec, resolve_env=resolve_env)


def test_invalid_base64_is_rejected() -> None:
    """Malformed ``data`` fails before upload rather than at the server."""
    with pytest.raises(SystemExit, match="not valid base64"):
        applier._resolve_values("creds", {"data": {"a": "!!!not base64!!!"}}, True)


def test_unset_environment_variable_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing variable fails the run before anything is sent."""
    monkeypatch.delenv("MISSING_VAR", raising=False)
    with pytest.raises(SystemExit, match="MISSING_VAR"):
        applier._resolve_values("creds", {"fromEnv": {"a": "MISSING_VAR"}}, True)


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
    values = applier._resolve_values("creds", spec, resolve_env=True)

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
    values = applier._resolve_values("creds", spec, resolve_env=True)

    applier._write_sealed(spec, values, applier._seal_transform(key.public_key()))

    opened = {k: unseal(e["ciphertext"], key) for k, e in spec["encryptedData"].items()}
    assert opened == {
        "a": "inline-secret-value",
        "b": "decoded",
        "c": "env-secret-value",
    }


def test_from_env_provenance_survives_sealing(
    monkeypatch: pytest.MonkeyPatch, key: rsa.RSAPrivateKey
) -> None:
    """The binding is carried alongside the blob so export still round-trips it."""
    monkeypatch.setenv("SOME_VAR", "env-secret-value")
    spec: dict[str, Any] = {"stringData": {"a": "inline"}, "fromEnv": {"c": "SOME_VAR"}}
    values = applier._resolve_values("creds", spec, resolve_env=True)

    applier._write_sealed(spec, values, applier._seal_transform(key.public_key()))

    assert spec["encryptedData"]["c"]["fromEnv"] == "SOME_VAR"
    assert "fromEnv" not in spec["encryptedData"]["a"]


def test_unresolved_from_env_is_left_for_the_server(
    monkeypatch: pytest.MonkeyPatch, key: rsa.RSAPrivateKey
) -> None:
    """With ``--no-resolve-env`` the block stays put — there is nothing to seal."""
    monkeypatch.setenv("SOME_VAR", "never-read")
    spec: dict[str, Any] = {"stringData": {"a": "inline"}, "fromEnv": {"c": "SOME_VAR"}}
    values = applier._resolve_values("creds", spec, resolve_env=False)

    applier._write_sealed(spec, values, applier._seal_transform(key.public_key()))

    assert spec["fromEnv"] == {"c": "SOME_VAR"}
    assert set(spec["encryptedData"]) == {"a"}


def test_secret_with_only_unresolved_from_env_gets_no_wire_block(
    key: rsa.RSAPrivateKey,
) -> None:
    """Nothing resolved means nothing sealed, and no empty block emitted."""
    spec: dict[str, Any] = {"fromEnv": {"c": "SOME_VAR"}}
    values = applier._resolve_values("creds", spec, resolve_env=False)

    applier._write_sealed(spec, values, applier._seal_transform(key.public_key()))

    assert spec == {"fromEnv": {"c": "SOME_VAR"}}


# --------------------------------------------------------------------------- #
# The unsealed path and dry runs
# --------------------------------------------------------------------------- #


def test_unsealed_path_inlines_into_string_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--no-seal`` reproduces the pre-sealing behaviour."""
    monkeypatch.setenv("SOME_VAR", "env-secret-value")
    spec: dict[str, Any] = {"data": {"b": "ZGVjb2RlZA=="}, "fromEnv": {"c": "SOME_VAR"}}
    values = applier._resolve_values("creds", spec, resolve_env=True)

    applier._write_inline(spec, values, lambda v: v)

    assert spec == {"stringData": {"b": "decoded", "c": "env-secret-value"}}


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
    values = applier._resolve_values("creds", spec, resolve_env=True)

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
# Document discovery
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
