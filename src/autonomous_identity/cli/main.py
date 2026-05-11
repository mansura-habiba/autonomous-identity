from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from autonomous_identity.application.facade import AutonomousIdentity
from autonomous_identity.core.exceptions import AutonomousIdentityError
from autonomous_identity.core.serialize import envelope_from_serializable, envelope_to_serializable


def _build_identity(args: argparse.Namespace) -> AutonomousIdentity:
    if args.config:
        return AutonomousIdentity.from_config(args.config)
    cfg = {
        "identity": {"adapter": args.identity_adapter},
        "storage": {
            "backend": args.store,
            "data_dir": args.data_dir,
            "path": args.sqlite_path,
            "dsn": args.postgres_dsn,
        },
        "crypto": {},
    }
    if args.private_key_pem:
        cfg["crypto"]["private_key_pem"] = args.private_key_pem
    return AutonomousIdentity.from_config_dict(cfg)


def cmd_issue(args: argparse.Namespace) -> int:
    identity = _build_identity(args)
    ctx = {
        "system_identifier": args.system_id,
        "instance_id": args.instance_id,
        "deployment_id": args.deployment_id,
        "environment": args.environment,
        "region": args.region,
        "owner_id": args.owner,
        "owner_type": args.owner_type,
        "responsibility_scope": args.responsibility_scope,
        "provenance": {
            "code_hash": args.code_hash,
            "policy_bundle_hash": args.policy_hash,
        },
        "attestation_chain": ["local:dev-attestation"],
    }
    if args.issuer_scopes:
        ctx["issuer_scopes"] = [s.strip() for s in args.issuer_scopes.split(",") if s.strip()]
    envelope = identity.issue_envelope(ctx)
    print(json.dumps({"audit_ref": envelope.audit_ref, "system_identifier": envelope.system_identifier}, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    identity = _build_identity(args)
    identity.verify_audit_ref(args.audit_ref)
    print("ok")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    identity = _build_identity(args)
    identity.revoke(args.system_id, args.reason)
    print("ok")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    identity = _build_identity(args)
    row = identity.inspect_audit(args.audit_ref)
    if not row:
        print("not found", file=sys.stderr)
        return 1
    print(json.dumps(row, indent=2, default=str))
    return 0


def cmd_delegate(args: argparse.Namespace) -> int:
    identity = _build_identity(args)
    raw = json.loads(Path(args.parent_json).read_text(encoding="utf-8"))
    parent = envelope_from_serializable(raw)
    scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
    caveats = json.loads(args.caveats_json) if args.caveats_json else {}
    exp = None
    if args.expires:
        exp = datetime.fromisoformat(args.expires.replace("Z", "+00:00"))
    child = identity.delegate(
        parent,
        args.child_system_id,
        scopes,
        caveats,
        expires_at=exp,
    )
    print(json.dumps(envelope_to_serializable(child), indent=2))
    return 0


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="asid")
    p.add_argument("--config", type=Path, help="YAML config path")
    p.add_argument("--identity-adapter", default="merkle_chain", dest="identity_adapter")
    p.add_argument("--store", choices=("file", "sqlite", "postgres", "memory"), default="file")
    p.add_argument("--data-dir", default=".asid", dest="data_dir")
    p.add_argument("--sqlite-path", default=".asid/store.sqlite3", dest="sqlite_path")
    p.add_argument("--postgres-dsn", default=None, dest="postgres_dsn")
    p.add_argument("--private-key-pem", default=None, dest="private_key_pem")

    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("issue", help="Issue an identity envelope and register lifecycle")
    pi.set_defaults(func=cmd_issue)
    pi.add_argument("--system-id", required=True)
    pi.add_argument("--instance-id", required=True)
    pi.add_argument("--deployment-id", required=True)
    pi.add_argument("--owner", required=True)
    pi.add_argument("--owner-type", default="team")
    pi.add_argument("--responsibility-scope", default="unspecified")
    pi.add_argument("--environment", default="dev")
    pi.add_argument("--region", default="local")
    pi.add_argument("--code-hash", required=True)
    pi.add_argument("--policy-hash", required=True)
    pi.add_argument(
        "--issuer-scopes",
        default=None,
        help=(
            "Comma-separated root scopes allowed for later delegation (stored in envelope metadata). "
            "For a production naming scheme see docs/SCOPE_CONVENTION.md (asid v1)."
        ),
    )

    pv = sub.add_parser("verify", help="Verify merkle audit event signature")
    pv.set_defaults(func=cmd_verify)
    pv.add_argument("--audit-ref", required=True)

    pr = sub.add_parser("revoke", help="Revoke lifecycle for a system id")
    pr.set_defaults(func=cmd_revoke)
    pr.add_argument("--system-id", required=True)
    pr.add_argument("--reason", required=True)

    pin = sub.add_parser("inspect", help="Print raw audit record")
    pin.set_defaults(func=cmd_inspect)
    pin.add_argument("--audit-ref", required=True)

    pd = sub.add_parser("delegate", help="Create child envelope from parent JSON (narrowed scopes)")
    pd.set_defaults(func=cmd_delegate)
    pd.add_argument("--parent-json", type=Path, required=True, help="JSON file from envelope export")
    pd.add_argument("--child-system-id", required=True)
    pd.add_argument("--scopes", required=True, help="Comma-separated subset of parent effective scopes")
    pd.add_argument("--caveats-json", default="{}", dest="caveats_json")
    pd.add_argument("--expires", default=None, help="ISO-8601 expiry for the delegation grant")

    args = p.parse_args(argv)
    try:
        raise SystemExit(args.func(args))
    except AutonomousIdentityError as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(2) from e


if __name__ == "__main__":
    main()
