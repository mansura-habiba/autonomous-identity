"""Shared helpers for the SPIFFE demos.

Two things every demo needs:

* ``load_dotenv()`` — Python doesn't read ``.env`` files by default. Demos
  expect ``LANGFUSE_PUBLIC_KEY`` / ``LANGFUSE_SECRET_KEY`` / ``LANGFUSE_HOST``
  to come from one if the user put them there.
* ``build_tracer(name)`` — return a Langfuse tracer if env vars are present,
  else a ConsoleTracer. Either way, print a one-line banner so the operator
  can SEE which tracer is active.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Iterable


def _candidate_env_files() -> Iterable[Path]:
    """Search for ``.env`` in the locations users actually put them.

    Order:
        1. cwd / .env
        2. walk up from cwd to the filesystem root, looking for .env at each
           level (the standard ``python-dotenv.find_dotenv`` pattern)
        3. examples/ / .env  (where the demo files live)
        4. repo root / .env
        5. src/ / .env  (some users put it there alongside the package)
        6. walk up from this file's directory
    """
    seen: set[Path] = set()

    def _yield(p: Path) -> Iterable[Path]:
        try:
            resolved = p.resolve()
        except OSError:
            return
        if resolved in seen:
            return
        seen.add(resolved)
        yield resolved

    here = Path(__file__).resolve().parent  # examples/
    repo_root = here.parent                 # repo

    yield from _yield(Path.cwd() / ".env")

    # Walk up from cwd
    cur = Path.cwd().resolve()
    for parent in [cur, *cur.parents]:
        yield from _yield(parent / ".env")

    yield from _yield(here / ".env")
    yield from _yield(repo_root / ".env")
    yield from _yield(repo_root / "src" / ".env")

    # Walk up from this module
    for parent in here.parents:
        yield from _yield(parent / ".env")


def load_dotenv(*, override: bool = False, verbose: bool = True) -> Path | None:
    """Naive ``.env`` parser. Returns the path that was loaded, or None.

    We avoid taking a dependency on ``python-dotenv`` so demos work out of
    the box. Format is the standard one: ``KEY=VALUE`` per line, ``#`` for
    comments, optional surrounding quotes.

    When ``verbose`` is True (the default) and no ``.env`` file is found at
    any of the candidate paths, we print the full list of locations we
    searched. That makes the "nothing happened" failure mode debuggable.
    """
    searched: list[Path] = []
    for path in _candidate_env_files():
        searched.append(path)
        if not path.is_file():
            continue
        try:
            loaded_keys: list[str] = []
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if not override and key in os.environ:
                    continue
                os.environ[key] = value
                loaded_keys.append(key)
            if verbose:
                # Echo which keys we actually wrote so the operator can
                # confirm the right ones landed without leaking values.
                redacted = [k for k in loaded_keys if "KEY" in k or "SECRET" in k or "TOKEN" in k]
                visible = [k for k in loaded_keys if k not in redacted]
                summary = []
                if visible:
                    summary.append("plain=" + ",".join(visible))
                if redacted:
                    summary.append("secret=" + ",".join(redacted))
                print(
                    f"[asid] loaded env from {path}  ({'; '.join(summary) or 'no keys'})",
                    file=sys.stderr,
                )
            return path
        except OSError as exc:
            if verbose:
                print(f"[asid] could not read {path}: {exc}", file=sys.stderr)
            continue
    if verbose:
        print(
            "[asid] no .env file found. Searched:\n  - "
            + "\n  - ".join(str(p) for p in searched),
            file=sys.stderr,
        )
    return None


def build_tracer(trace_name: str):
    """Return the most capable tracer the environment supports.

    Order: Langfuse (if env vars present) → ConsoleTracer. Always prints
    which tracer was chosen so the demo operator can confirm.
    """
    from autonomous_identity.tracing import ConsoleTracer

    load_dotenv()  # already prints diagnostics

    have_keys = bool(
        os.environ.get("LANGFUSE_PUBLIC_KEY")
        and os.environ.get("LANGFUSE_SECRET_KEY")
    )

    if have_keys:
        try:
            from autonomous_identity.tracing import LangfuseTracer  # type: ignore[attr-defined]

            tracer = LangfuseTracer.from_env_or_none(trace_name=trace_name)
            if tracer is not None:
                host = os.environ.get("LANGFUSE_HOST", "<default>")
                print(
                    f"[asid] tracer=LangfuseTracer  host={host}  trace_name={trace_name}",
                    file=sys.stderr,
                )
                return tracer
        except Exception as exc:  # noqa: BLE001
            print(
                f"[asid] failed to build LangfuseTracer ({type(exc).__name__}: {exc});"
                f" using ConsoleTracer instead. Set ASID_TRACE_DEBUG=1 for details.",
                file=sys.stderr,
            )

    print("[asid] tracer=ConsoleTracer", file=sys.stderr)
    return ConsoleTracer()


def wait_for_flush() -> None:
    """Best-effort flush of any background telemetry pipeline before exit.

    Only attempts the Langfuse flush when LANGFUSE_PUBLIC_KEY is set so we
    don't trigger the SDK's "client disabled" warning during console-only
    runs.
    """
    if not os.environ.get("LANGFUSE_PUBLIC_KEY"):
        return
    try:
        from langfuse import get_client

        client = get_client()
        if client is not None and hasattr(client, "flush"):
            client.flush()
    except Exception:
        pass
