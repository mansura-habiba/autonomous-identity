from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from autonomous_identity.storage.file import FileAuditStore, FileLifecycleStore
from autonomous_identity.storage.memory import MemoryAuditStore, MemoryLifecycleStore
from autonomous_identity.storage.postgres import PostgresAuditStore, PostgresLifecycleStore
from autonomous_identity.storage.sqlite import SQLiteAuditStore, SQLiteLifecycleStore


def load_yaml_config(path: Path | str) -> dict[str, Any]:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Config must be a YAML mapping at the top level")
    return data


def build_stores_from_config(cfg: dict[str, Any]) -> tuple[Any, Any]:
    storage = cfg.get("storage") or {}
    backend = storage.get("backend", "file")
    if backend == "memory":
        return MemoryLifecycleStore(), MemoryAuditStore()
    if backend == "file":
        base = Path(storage.get("data_dir", ".asid"))
        return (
            FileLifecycleStore(base / "lifecycle.json"),
            FileAuditStore(base / "audit.jsonl"),
        )
    if backend == "sqlite":
        path = Path(storage.get("path", ".asid/store.sqlite3"))
        path.parent.mkdir(parents=True, exist_ok=True)
        return SQLiteLifecycleStore(path), SQLiteAuditStore(path)
    if backend == "postgres":
        dsn = storage.get("dsn")
        if not dsn:
            raise ValueError("storage.dsn is required for postgres backend")
        return PostgresLifecycleStore(dsn), PostgresAuditStore(dsn)
    raise ValueError(f"Unknown storage backend: {backend!r}")
