#!/usr/bin/env python3
"""Contrato de tags (ADR-006 E1-8).

Reglas:
  1. Toda tarea de los roles declara tags y todas sus tags estan en
     {install, config, start, stop} (mas el especial `never`).
  2. Ninguna tarea con tag `start` o `stop` usa un modulo que descargue algo.
  3. Toda tarea con tag `stop` lleva `never`: no corre en pasadas sin tags
     ni en install/config/start.

Se complementa con `ansible-playbook --list-tasks --tags start,stop` en el Makefile
(que valida que el playbook compila con esa seleccion).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

ALLOWED_TAGS = {"install", "config", "start", "stop"}
SPECIAL_TAGS = {"never"}
NO_DOWNLOAD_TAGS = {"start", "stop"}
DOWNLOAD_MODULES = {
    "apt",
    "apk",
    "apt_key",
    "apt_repository",
    "dnf",
    "docker_compose_v2_pull",
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
                elif not block_tags - SPECIAL_TAGS <= ALLOWED_TAGS:
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
        if not tags - SPECIAL_TAGS <= ALLOWED_TAGS:
            errors.append(f"{path}: tags fuera del contrato {sorted(tags)}: {name}")
        if "stop" in tags and "never" not in tags:
            errors.append(f"{path}: el tag 'stop' sin 'never' correría en pasadas sin tags: {name}")

        mod = module_of(task)
        if tags & NO_DOWNLOAD_TAGS and mod in DOWNLOAD_MODULES:
            errors.append(f"{path}: el tag {sorted(tags & NO_DOWNLOAD_TAGS)} usa modulo de descarga '{mod}': {name}")
        if tags & NO_DOWNLOAD_TAGS and mod == "docker_compose_v2":
            args = next(v for k, v in task.items() if k.split(".")[-1] == "docker_compose_v2")
            if not isinstance(args, dict) or args.get("pull") != "never":
                errors.append(f"{path}: el tag {sorted(tags & NO_DOWNLOAD_TAGS)} usa docker_compose_v2 sin 'pull: never': {name}")


def selftest() -> int:
    """Casos sinteticos: (tareas, errores esperados)."""
    casos = [
        ([{"name": "pull en start", "community.docker.docker_compose_v2_pull": {"project_src": "/x"}, "tags": ["start"]}], 1),
        ([{"name": "up sin pull never", "community.docker.docker_compose_v2": {"project_src": "/x"}, "tags": ["start"]}], 1),
        ([{"name": "up con pull missing", "community.docker.docker_compose_v2": {"project_src": "/x", "pull": "missing"}, "tags": ["start"]}], 1),
        ([{"name": "up con pull never", "community.docker.docker_compose_v2": {"project_src": "/x", "pull": "never"}, "tags": ["start"]}], 0),
        ([{"name": "pull en install", "community.docker.docker_compose_v2_pull": {"project_src": "/x"}, "tags": ["install"]}], 0),
        ([{"name": "up sin pull never en block", "tags": ["start"], "block": [{"name": "up sin pull never anidado", "community.docker.docker_compose_v2": {"project_src": "/x"}, "tags": ["start"]}]}], 1),
        ([{"name": "down con pull never y never", "community.docker.docker_compose_v2": {"project_src": "/x", "state": "absent", "pull": "never"}, "tags": ["stop", "never"]}], 0),
        ([{"name": "down sin pull never", "community.docker.docker_compose_v2": {"project_src": "/x", "state": "absent"}, "tags": ["stop", "never"]}], 1),
        ([{"name": "stop sin never", "ansible.builtin.file": {"path": "/x", "state": "absent"}, "tags": ["stop"]}], 1),
        ([{"name": "apt en stop", "ansible.builtin.apt": {"name": "x"}, "tags": ["stop", "never"]}], 1),
    ]
    for tareas, esperados in casos:
        errores: list[str] = []
        walk(tareas, Path("selftest.yml"), errores)
        if len(errores) != esperados:
            print(f"tags-contract --selftest: FALLA en '{tareas[0]['name']}': {errores}", file=sys.stderr)
            return 1
    print(f"tags-contract --selftest: ok ({len(casos)} casos)")
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
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
