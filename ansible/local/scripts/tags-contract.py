#!/usr/bin/env python3
"""Contrato de tags (ADR-006 E1-8).

Reglas:
  1. Toda tarea de los roles declara tags y todas sus tags estan en
     {install, config, start}.
  2. Ninguna tarea con tag `start` usa un modulo que descargue algo.

Se complementa con `ansible-playbook --list-tasks --tags start` en el Makefile
(que valida que el playbook compila con esa seleccion).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

ALLOWED_TAGS = {"install", "config", "start"}
DOWNLOAD_MODULES = {
    "apt",
    "apk",
    "apt_key",
    "apt_repository",
    "dnf",
    "docker_image",
    "get_url",
    "git",
    "package",
    "pip",
    "snap",
    "unarchive",
    "yum",
}
META_KEYS = {
    "name",
    "tags",
    "when",
    "register",
    "changed_when",
    "failed_when",
    "ignore_errors",
    "no_log",
    "become",
    "become_user",
    "become_flags",
    "delegate_to",
    "run_once",
    "loop",
    "loop_control",
    "until",
    "retries",
    "delay",
    "notify",
    "vars",
    "environment",
    "args",
    "check_mode",
    "diff",
    "any_errors_fatal",
    "listen",
    "throttle",
    "timeout",
    "connection",
    "remote_user",
    "collections",
}


def module_of(task: dict[str, Any]) -> str | None:
    for key in task:
        if key in META_KEYS or key.startswith("with_"):
            continue
        return key.split(".")[-1]
    return None


def walk(tasks: list[Any], path: Path, errors: list[str]) -> None:
    for task in tasks:
        if not isinstance(task, dict):
            continue
        if "block" in task or "rescue" in task or "always" in task:
            tags = task.get("tags", [])
            if isinstance(tags, str):
                tags = [tags]
            for key in ("block", "rescue", "always"):
                walk(task.get(key) or [], path, errors)
            if "block" in task:
                block_tags = set(tags)
                if not block_tags:
                    errors.append(f"{path}: bloque sin tags")
                elif not block_tags <= ALLOWED_TAGS:
                    errors.append(f"{path}: bloque con tags fuera del contrato: {sorted(block_tags)}")
            continue

        name = task.get("name", "<sin nombre>")
        tags = task.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        tags = set(tags)

        if not tags:
            errors.append(f"{path}: tarea sin tags: {name}")
            continue
        if not tags <= ALLOWED_TAGS:
            errors.append(f"{path}: tags fuera del contrato {sorted(tags)}: {name}")

        mod = module_of(task)
        if "start" in tags and mod in DOWNLOAD_MODULES:
            errors.append(f"{path}: el tag 'start' usa modulo de descarga '{mod}': {name}")


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    files = sorted(root.glob("roles/*/tasks/*.yml"))
    if not files:
        print("tags-contract: no se encontraron roles/*/tasks/*.yml", file=sys.stderr)
        return 1

    errors: list[str] = []
    for path in files:
        data = yaml.safe_load(path.read_text()) or []
        if not isinstance(data, list):
            errors.append(f"{path}: se esperaba una lista de tareas")
            continue
        walk(data, path.relative_to(root), errors)

    if errors:
        print("tags-contract: FALLA (E1-8)", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"tags-contract: ok ({len(files)} archivos de tareas)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
