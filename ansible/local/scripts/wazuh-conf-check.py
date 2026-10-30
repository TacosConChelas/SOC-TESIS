#!/usr/bin/env python3
"""Comprueba en ossec.conf los valores de D5. Uso: wazuh-conf-check.py /ruta/ossec.conf

Entrada CONFIABLE: el ossec.conf propio del contenedor de ensayo (root, desechable). Por eso
basta xml.etree de la biblioteca estandar; si algun dia se usara con XML ajeno, cambiar a
defusedxml (XXE y billion-laughs).
"""
import sys
import xml.etree.ElementTree as ET

# ossec.conf tiene varios <ossec_config>: se envuelve en una raiz para parsearlo.
raw = open(sys.argv[1], encoding="utf-8").read()
root = ET.fromstring("<r>" + raw + "</r>")


def textos(ruta: str) -> list[str]:
    return [(e.text or "").strip() for e in root.findall(ruta)]


esperado = [
    ("global/logall", "no"),
    ("global/logall_json", "no"),
    ("auth/use_password", "yes"),
    ("auth/use_source_ip", "no"),
    ("vulnerability-detection/enabled", "no"),
    ("active-response/disabled", "yes"),
]

mal = 0
for ruta, quiero in esperado:
    hay = textos(f".//{ruta}")
    if hay and all(v == quiero for v in hay):
        print(f"ok {ruta}={quiero}")
    else:
        print(f"FALLA {ruta}: esperado {quiero}, hay {hay}")
        mal = 1
sys.exit(mal)
