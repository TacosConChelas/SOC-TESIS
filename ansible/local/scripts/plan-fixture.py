#!/usr/bin/env python3
"""Genera planes sinteticos para plan-check-selftest.

`--case control` produce el plan que debe pasar los 6 checks; las letras a-f
rompen exactamente el check correspondiente. Sin datos reales: lab_cidr usa
TEST-NET-3 (203.0.113.0/24) y las IPs privadas son las de D7.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys

LAB_CIDR = "203.0.113.0/24"
VM_TYPE = "azurerm_linux_virtual_machine"
RULE_TYPE = "azurerm_network_security_rule"

CLOUD_INIT = (
    "#cloud-config\n"
    "write_files:\n"
    "  - path: /etc/ssh/sshd_config.d/10-admin-port.conf\n"
    "    content: |\n"
    "      Port 22222\n"
    "runcmd:\n"
    "  - [systemctl, restart, ssh]\n"
)


def vm(name: str, custom_data: str | None = None) -> dict:
    values = {"name": name, "size": "Standard_B2als_v2"}
    sensitive: dict = {}
    if custom_data is not None:
        values["custom_data"] = base64.b64encode(custom_data.encode()).decode()
        sensitive["custom_data"] = True
    label = name.removeprefix("vm-")  # etiqueta de Terraform; "name" de Azure va en values
    return {
        "address": f"{VM_TYPE}.{label}",
        "type": VM_TYPE,
        "name": label,
        "values": values,
        "sensitive": sensitive,
    }


def rule(
    nsg: str,
    name: str,
    priority: int,
    port: str,
    destination: str,
    source: str = LAB_CIDR,
    direction: str = "Inbound",
) -> dict:
    return {
        "address": f"{RULE_TYPE}.{nsg}.{name}",
        "type": RULE_TYPE,
        "name": name,
        "values": {
            "name": name,
            "priority": priority,
            "direction": direction,
            "access": "Allow",
            "protocol": "Tcp",
            "source_port_range": "*",
            "destination_port_range": port,
            "source_address_prefix": source,
            "destination_address_prefix": destination,
            "network_security_group_name": nsg,
        },
        "sensitive": {},
    }


def base_resources() -> list[dict]:
    return [
        vm("vm-honeyserver", CLOUD_INIT),
        vm("vm-strongswan"),
        vm("vm-logrelay"),
        vm("vm-wazuh"),
        rule("nsg-vpn", "Allow-Lab-Admin-SSH", 200, "22", "10.50.20.10"),
        rule("nsg-logrelay", "Allow-Lab-Admin-SSH", 200, "22", "10.50.30.10"),
        rule("nsg-wazuh", "Allow-Lab-Admin-SSH", 210, "22", "10.50.40.10"),
        rule("nsg-honeypot", "Allow-Lab-Admin-SSH-22222", 300, "22222", "10.50.10.10"),
    ]


def plan(resources: list[dict]) -> dict:
    """Emula la forma de `terraform show -json` (create desde estado vacio)."""
    return {
        "format_version": "1.2",
        "terraform_version": "1.16.3",
        "variables": {"lab_cidr": LAB_CIDR, "maintenance_egress": False},
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": item["address"],
                        "type": item["type"],
                        "name": item["name"],
                        "values": item["values"],
                    }
                    for item in resources
                ]
            }
        },
        "resource_changes": [
            {
                "address": item["address"],
                "type": item["type"],
                "name": item["name"],
                "change": {
                    "actions": ["create"],
                    "after": item["values"],
                    "after_sensitive": item["sensitive"],
                },
            }
            for item in resources
        ],
    }


def build(case: str) -> dict:
    resources = base_resources()
    # Control: valor con pinta de secreto, pero marcado sensible por Terraform.
    # El check (a) debe ignorarlo (no cuenta como fuga).
    strongswan = next(item for item in resources if item["values"].get("name") == "vm-strongswan")
    strongswan["values"]["admin_password"] = "secret" + " = " + "hunter2hunter2"
    strongswan["sensitive"]["admin_password"] = True

    if case == "a":
        # Secreto literal en un valor NO sensible -> regla B.
        strongswan["values"]["notes"] = "psk" + " = " + "0123456789abcdef"
    elif case == "b":
        resources.append(
            rule("nsg-wazuh", "Allow-Out-Maintenance-Egress", 300, "*", "Internet", source="*")
        )
    elif case == "c":
        resources.append(vm("vm-extra"))
    elif case == "d":
        vpn = next(item for item in resources if item["address"].endswith("nsg-vpn.Allow-Lab-Admin-SSH"))
        vpn["values"]["source_address_prefix"] = "Internet"
    elif case == "e":
        honey = next(item for item in resources if item["name"] == "Allow-Lab-Admin-SSH-22222")
        honey["values"]["destination_address_prefix"] = "10.50.10.11"
    elif case == "f":
        honey = next(item for item in resources if item["values"].get("name") == "vm-honeyserver")
        honey["values"]["custom_data"] = base64.b64encode(
            CLOUD_INIT.replace("Port 22222", "Port 22").encode()
        ).decode()
    elif case != "control":
        raise SystemExit(f"caso desconocido: {case}")
    return plan(resources)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", default="control", choices=["control", "a", "b", "c", "d", "e", "f"])
    args = parser.parse_args()
    json.dump(build(args.case), sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
