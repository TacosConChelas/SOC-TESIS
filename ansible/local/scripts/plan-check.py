#!/usr/bin/env python3
"""Checks de la Etapa 1 sobre `terraform show -json /tmp/tfplan`.

Valida por tipo y nombre (E1-9), no por conteo total de recursos:

  a. sin secretos en el plan (reglas A/B/C de `secret-scan.py`; los valores
     marcados como sensitive por Terraform no cuentan como fuga),
  b. ninguna regla `Allow-Out-Maintenance-Egress`,
  c. exactamente 4 `azurerm_linux_virtual_machine` con los 4 nombres,
  d. las 3 reglas `Allow-Lab-Admin-SSH` (22) solo desde lab_cidr y solo hacia
     10.50.20.10 / 10.50.30.10 / 10.50.40.10,
  e. `Allow-Lab-Admin-SSH-22222` solo desde lab_cidr hacia 10.50.10.10,
  f. el `custom_data` de honeyserver mueve sshd al 22222 (E1-2).

Exit 0 solo si pasan a-f. Uso: plan-check.py /tmp/tfplan.json
"""
from __future__ import annotations

import base64
import importlib.util
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

VM_TYPE = "azurerm_linux_virtual_machine"
RULE_TYPE = "azurerm_network_security_rule"
MAINTENANCE_RULE = "Allow-Out-Maintenance-Egress"
ADMIN_SSH = "Allow-Lab-Admin-SSH"
ADMIN_SSH_HONEY = "Allow-Lab-Admin-SSH-22222"
HONEYSERVER = "vm-honeyserver"
VM_NAMES = {"vm-honeyserver", "vm-strongswan", "vm-logrelay", "vm-wazuh"}
ADMIN_SSH_DEST = {
    "nsg-vpn": "10.50.20.10",
    "nsg-logrelay": "10.50.30.10",
    "nsg-wazuh": "10.50.40.10",
}
HONEY_ADMIN_DEST = "10.50.10.10"
HONEY_ADMIN_PORT = "22222"
PORT_RE = re.compile(r"(?m)^\s*Port\s+(\d+)\s*$")


class CheckError(Exception):
    pass


def load_secret_scanner():
    """Reutiliza las reglas A/B/C de secret-scan.py (sin duplicarlas)."""
    path = SCRIPT_DIR / "secret-scan.py"
    spec = importlib.util.spec_from_file_location("soc_secret_scan", path)
    if spec is None or spec.loader is None:
        raise CheckError("no se pudo cargar secret-scan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def instances(plan: dict) -> list[dict]:
    """Recursos planificados (incluye modulos hijos)."""
    found: list[dict] = []

    def walk(module: dict) -> None:
        found.extend(module.get("resources", []))
        for child in module.get("child_modules", []):
            walk(child)

    walk(plan.get("planned_values", {}).get("root_module", {}))
    return found


def changes(plan: dict) -> list[dict]:
    return list(plan.get("resource_changes", []))


def effective_lab_cidr(plan: dict) -> str:
    value = plan.get("variables", {}).get("lab_cidr")
    if isinstance(value, str) and value:
        return value
    try:
        default = plan["configuration"]["root_module"]["variables"]["lab_cidr"]["default"]
    except (KeyError, TypeError):
        default = None
    if isinstance(default, str) and default:
        return default
    raise CheckError(
        "no se pudo determinar el lab_cidr efectivo desde el plan "
        "(define lab_cidr en terraform.tfvars)"
    )


def prefixes(values: dict, single: str, plural: str) -> set[str]:
    out: set[str] = set()
    one = values.get(single)
    if isinstance(one, str) and one:
        out.add(one)
    many = values.get(plural)
    if isinstance(many, list):
        out.update(str(item) for item in many if item)
    return out


def ports(values: dict) -> set[str]:
    out: set[str] = set()
    for key in ("destination_port_range", "destination_port_ranges"):
        raw = values.get(key)
        if isinstance(raw, str) and raw:
            out.add(raw)
        elif isinstance(raw, list):
            out.update(str(item) for item in raw if item)
    return out


def is_admin_ssh(values: dict) -> bool:
    return (
        values.get("direction") == "Inbound"
        and values.get("access") == "Allow"
        and str(values.get("protocol", "")).lower() == "tcp"
        and ports(values) == {"22"}
    )


def check_a(plan: dict) -> None:
    scanner = load_secret_scanner()
    findings: list[str] = []

    def walk(value, sensitive, label: str) -> None:
        if isinstance(sensitive, bool):
            if sensitive:
                return
            sensitive = {}
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, (sensitive or {}).get(key, False), f"{label}.{key}")
        elif isinstance(value, list):
            sens_list = sensitive if isinstance(sensitive, list) else []
            for index, child in enumerate(value):
                sens = sens_list[index] if index < len(sens_list) else False
                walk(child, sens, f"{label}[{index}]")
        elif isinstance(value, str) and value:
            local: list[str] = []
            scanner.scan_line(Path(label), 1, value.encode(), local, False)
            findings.extend(local)

    for item in changes(plan):
        change = item.get("change") or {}
        walk(change.get("after"), change.get("after_sensitive"), item.get("address", "?"))
    for name, output in (plan.get("output_changes") or {}).items():
        walk(output.get("after"), output.get("after_sensitive"), f"output.{name}")
    for name, value in (plan.get("variables") or {}).items():
        walk(value, False, f"var.{name}")

    if findings:
        raise CheckError("; ".join(findings[:5]))


def check_b(plan: dict) -> None:
    hits = [
        item.get("address", "?")
        for item in instances(plan)
        if str(item.get("name", "")) == MAINTENANCE_RULE
        or str(item.get("values", {}).get("name", "")) == MAINTENANCE_RULE
    ]
    for item in changes(plan):
        values = (item.get("change") or {}).get("after") or {}
        if str(values.get("name", "")) == MAINTENANCE_RULE:
            hits.append(item.get("address", "?"))
    if hits:
        raise CheckError(f"existe la regla {MAINTENANCE_RULE} en: {', '.join(sorted(set(hits)))}")


def check_c(plan: dict) -> None:
    vms = [item for item in instances(plan) if item.get("type") == VM_TYPE]
    names = {str((item.get("values") or {}).get("name")) for item in vms}
    if len(vms) != 4:
        raise CheckError(f"hay {len(vms)} {VM_TYPE}, se esperan 4")
    missing = VM_NAMES - names
    extra = names - VM_NAMES
    if missing or extra:
        detail = []
        if missing:
            detail.append(f"faltan {sorted(missing)}")
        if extra:
            detail.append(f"sobran {sorted(extra)}")
        raise CheckError("; ".join(detail))


def check_d(plan: dict, lab_cidr: str) -> None:
    rules = [
        item["values"]
        for item in instances(plan)
        if item.get("type") == RULE_TYPE and item.get("values", {}).get("name") == ADMIN_SSH
    ]
    if len(rules) != 3:
        raise CheckError(f"hay {len(rules)} reglas {ADMIN_SSH}, se esperan 3")
    seen: dict[str, str] = {}
    for values in rules:
        nsg = str(values.get("network_security_group_name", "?"))
        if not is_admin_ssh(values):
            raise CheckError(f"{nsg}: {ADMIN_SSH} no es Inbound/Allow/Tcp/22")
        if prefixes(values, "source_address_prefix", "source_address_prefixes") != {lab_cidr}:
            raise CheckError(f"{nsg}: {ADMIN_SSH} no tiene origen exclusivo lab_cidr")
        dests = prefixes(values, "destination_address_prefix", "destination_address_prefixes")
        expected = ADMIN_SSH_DEST.get(nsg)
        if expected is None:
            raise CheckError(f"{nsg}: {ADMIN_SSH} en un NSG inesperado")
        if dests != {expected}:
            raise CheckError(f"{nsg}: {ADMIN_SSH} destino {sorted(dests)} != {expected}")
        if nsg in seen:
            raise CheckError(f"{nsg}: {ADMIN_SSH} duplicada")
        seen[nsg] = expected
    if set(seen) != set(ADMIN_SSH_DEST):
        raise CheckError(f"{ADMIN_SSH} no cubre exactamente {sorted(ADMIN_SSH_DEST)}")


def check_e(plan: dict, lab_cidr: str) -> None:
    rules = [
        item["values"]
        for item in instances(plan)
        if item.get("type") == RULE_TYPE
        and item.get("values", {}).get("name") == ADMIN_SSH_HONEY
    ]
    if len(rules) != 1:
        raise CheckError(f"hay {len(rules)} reglas {ADMIN_SSH_HONEY}, se espera 1")
    values = rules[0]
    if not (
        values.get("direction") == "Inbound"
        and values.get("access") == "Allow"
        and str(values.get("protocol", "")).lower() == "tcp"
        and ports(values) == {HONEY_ADMIN_PORT}
    ):
        raise CheckError(f"{ADMIN_SSH_HONEY} no es Inbound/Allow/Tcp/{HONEY_ADMIN_PORT}")
    if prefixes(values, "source_address_prefix", "source_address_prefixes") != {lab_cidr}:
        raise CheckError(f"{ADMIN_SSH_HONEY} no tiene origen exclusivo lab_cidr")
    if prefixes(values, "destination_address_prefix", "destination_address_prefixes") != {
        HONEY_ADMIN_DEST
    }:
        raise CheckError(f"{ADMIN_SSH_HONEY} no apunta solo a {HONEY_ADMIN_DEST}")


def check_f(plan: dict) -> None:
    found = None
    for item in changes(plan):
        if item.get("type") != VM_TYPE:
            continue
        values = (item.get("change") or {}).get("after") or {}
        if values.get("name") == HONEYSERVER:
            found = values.get("custom_data")
            break
    if not isinstance(found, str) or not found:
        raise CheckError(
            "custom_data de honeyserver no aparece en el plan JSON (sensible/ausente); "
            "no se puede verificar E1-2"
        )
    try:
        text = base64.b64decode(found, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise CheckError(f"custom_data de honeyserver no es base64 valido: {exc}") from exc
    if "10-admin-port.conf" not in text:
        raise CheckError("custom_data no escribe 10-admin-port.conf")
    found_ports = PORT_RE.findall(text)
    if not found_ports:
        raise CheckError("custom_data no fija ningun 'Port'")
    if set(found_ports) != {HONEY_ADMIN_PORT}:
        raise CheckError(f"custom_data fija Port {sorted(set(found_ports))}, se espera solo {HONEY_ADMIN_PORT}")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("uso: plan-check.py PLAN.json", file=sys.stderr)
        return 2
    path = Path(argv[1])
    if not path.is_file():
        print(f"plan-check: no existe {path}", file=sys.stderr)
        return 2
    try:
        plan = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"plan-check: JSON invalido: {exc}", file=sys.stderr)
        return 2

    failures: list[tuple[str, str]] = []
    try:
        lab_cidr = effective_lab_cidr(plan)
    except CheckError as exc:
        failures.append(("d/e", str(exc)))
        lab_cidr = None

    runners = {
        "a": lambda: check_a(plan),
        "b": lambda: check_b(plan),
        "c": lambda: check_c(plan),
        "d": lambda: check_d(plan, lab_cidr) if lab_cidr else None,
        "e": lambda: check_e(plan, lab_cidr) if lab_cidr else None,
        "f": lambda: check_f(plan),
    }
    for key in ("a", "b", "c", "d", "e", "f"):
        if key in {"d", "e"} and lab_cidr is None:
            continue
        try:
            runners[key]()
        except CheckError as exc:
            failures.append((key, str(exc)))

    if failures:
        print(f"plan-check: FALLA ({len(failures)} check(s))", file=sys.stderr)
        for key, detail in failures:
            print(f"  - [{key}] {detail}", file=sys.stderr)
        return 1

    print("plan-check: ok (a,b,c,d,e,f)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
