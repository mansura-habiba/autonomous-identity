"""Tests for the config-driven IdentityRuntime."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from autonomous_identity.config import ConfigError, IdentityRuntime, find_config_path
from autonomous_identity.config.runtime_config import _resolve_env


# ---------- env-var interpolation -------------------------------------------


class TestEnvInterpolation:
    def test_plain_strings_pass_through(self) -> None:
        assert _resolve_env("hello") == "hello"

    def test_env_ref_resolves(self, monkeypatch) -> None:
        monkeypatch.setenv("ASID_TEST_X", "VALUE")
        assert _resolve_env("env:ASID_TEST_X") == "VALUE"

    def test_missing_env_value_drops_field(self, monkeypatch) -> None:
        monkeypatch.delenv("ASID_TEST_MISSING", raising=False)
        cfg = {"a": 1, "b": "env:ASID_TEST_MISSING", "c": [1, "env:ASID_TEST_MISSING", 2]}
        out = _resolve_env(cfg)
        assert out == {"a": 1, "c": [1, 2]}


# ---------- config discovery ------------------------------------------------


class TestFindConfigPath:
    def test_explicit_wins(self) -> None:
        assert find_config_path("/x/y.yaml") == Path("/x/y.yaml")

    def test_env_var_when_no_explicit(self, monkeypatch) -> None:
        monkeypatch.setenv("ASID_CONFIG", "/etc/asid/x.yaml")
        assert find_config_path() == Path("/etc/asid/x.yaml")


# ---------- helper to build a tmp config tree -------------------------------


def _make_config_tree(
    tmp_path: Path,
    *,
    provenance_required: bool = False,
    with_provenance_file: bool = True,
    extra_yaml: str = "",
    extra_provenance: dict | None = None,
) -> Path:
    data_dir = tmp_path / ".asid"
    yaml = f"""
identity:
  adapter: spiffe
  data_dir: {data_dir}

system:
  identifier: spiffe://example.org/agents/test
  instance_id: env:ASID_TEST_INSTANCE
  deployment_id: d-1

owner:
  id: team:demo
  type: team

attestation:
  chain:
    - local:bootstrap

scopes:
  issuer:
    - web.read
    - inbox.label
  tools:
    web_search: web.read
    apply_label: inbox.label
    no_scope_tool: ""

provenance:
  file: ./provenance.json
  required: {str(provenance_required).lower()}

{extra_yaml}
"""
    config_path = tmp_path / "agent.yaml"
    config_path.write_text(yaml, encoding="utf-8")
    if with_provenance_file:
        prov = {
            "code_hash": "sha256:codecode",
            "policy_bundle_hash": "sha256:policypolicy",
        }
        if extra_provenance:
            prov.update(extra_provenance)
        (tmp_path / "provenance.json").write_text(json.dumps(prov), encoding="utf-8")
    return config_path


# ---------- from_config ------------------------------------------------------


class TestFromConfig:
    def test_loads_envelope_from_config(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("ASID_TEST_INSTANCE", "host-7")
        config_path = _make_config_tree(tmp_path)
        runtime = IdentityRuntime.from_config(config_path)
        env = runtime.envelope
        assert env.system_identifier == "spiffe://example.org/agents/test"
        assert env.runtime_instance.instance_id == "host-7"
        assert env.owner_binding.owner_id == "team:demo"
        # Provenance came from provenance.json, not from code.
        assert env.provenance.code_hash == "sha256:codecode"
        assert env.provenance.policy_bundle_hash == "sha256:policypolicy"

    def test_missing_env_var_drops_field_cleanly(self, tmp_path, monkeypatch) -> None:
        monkeypatch.delenv("ASID_TEST_INSTANCE", raising=False)
        config_path = _make_config_tree(tmp_path)
        runtime = IdentityRuntime.from_config(config_path)
        # The env-driven instance_id was dropped → default applied.
        assert runtime.envelope.runtime_instance.instance_id == "default-instance"

    def test_missing_required_provenance_raises(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("ASID_TEST_INSTANCE", "host-7")
        config_path = _make_config_tree(
            tmp_path,
            provenance_required=True,
            with_provenance_file=False,
        )
        with pytest.raises(ConfigError, match="provenance.required=true"):
            IdentityRuntime.from_config(config_path)

    def test_required_provenance_missing_field_raises(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("ASID_TEST_INSTANCE", "host-7")
        config_path = _make_config_tree(
            tmp_path,
            provenance_required=True,
            extra_provenance={"code_hash": "sha256:abc"},  # policy_bundle_hash missing
        )
        # Re-write provenance.json without policy_bundle_hash.
        (tmp_path / "provenance.json").write_text(
            json.dumps({"code_hash": "sha256:abc"}), encoding="utf-8"
        )
        with pytest.raises(ConfigError, match="missing required keys"):
            IdentityRuntime.from_config(config_path)


# ---------- tool binding from config ----------------------------------------


class TestToolBinding:
    def test_tool_by_name_uses_config_scope(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("ASID_TEST_INSTANCE", "host-7")
        config_path = _make_config_tree(tmp_path)
        runtime = IdentityRuntime.from_config(config_path)

        def my_search(q: str) -> str:
            return f"OK:{q}"

        wrapped = runtime.tool("web_search", my_search)
        with runtime:
            assert wrapped("query") == "OK:query"

    def test_unmapped_tool_refused_at_bind(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("ASID_TEST_INSTANCE", "host-7")
        config_path = _make_config_tree(tmp_path)
        runtime = IdentityRuntime.from_config(config_path)
        with pytest.raises(ConfigError, match="No scope configured"):
            runtime.tool("send_email", lambda *a, **k: None)

    def test_identity_tool_decorator(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("ASID_TEST_INSTANCE", "host-7")
        config_path = _make_config_tree(tmp_path)
        runtime = IdentityRuntime.from_config(config_path)

        @runtime.identity_tool("apply_label")
        def apply_label(message_id: str, label: str) -> str:
            return f"{message_id}:{label}"

        with runtime:
            assert apply_label("msg-1", "x") == "msg-1:x"

    def test_scope_map_visible_for_inspection(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("ASID_TEST_INSTANCE", "host-7")
        config_path = _make_config_tree(tmp_path)
        runtime = IdentityRuntime.from_config(config_path)
        # The operator-declared map is visible for diagnostic / observability
        # tools without giving callers a way to mutate it.
        assert runtime.scope_map["web_search"] == "web.read"
        assert runtime.scope_map["apply_label"] == "inbox.label"

    def test_empty_scope_string_means_no_gate(self, tmp_path, monkeypatch) -> None:
        """An explicit empty scope string ('') means 'bind but don't gate'.

        Distinct from 'unmapped' (which fails at bind). Useful for tools
        whose authorization runs elsewhere.
        """
        monkeypatch.setenv("ASID_TEST_INSTANCE", "host-7")
        config_path = _make_config_tree(tmp_path)
        runtime = IdentityRuntime.from_config(config_path)
        scope = runtime.required_scope_for("no_scope_tool")
        assert scope is None
