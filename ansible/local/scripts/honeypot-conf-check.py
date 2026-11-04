#!/usr/bin/env python3
"""Check 5 de honeypot-check: ossec.conf del agente (spec honeypot §4.4, D4).

Se ejecuta DENTRO del contenedor:
  docker exec -i soc-local-honeyserver python3 - /var/ossec/etc/ossec.conf < honeypot-conf-check.py
ossec.conf admite varios bloques <ossec_config>; se envuelven en una raiz.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

RELAY = "10.50.30.10"
JSON_FILES = {
    "/srv/soc-tesis/cowrie/log/cowrie.json": "cowrie",
    "/srv/soc-tesis/dionaea/lib/dionaea.json": "dionaea",
    "/srv/soc-tesis/tanner/log/tanner_report.json": "tanner",
}
MAILONEY_FILTER = "^soc-tesis-mailoney$"


def text(el: ET.Element | None, tag: str) -> str:
    return ((el.findtext(tag) if el is not None else None) or "").strip()


def main() -> int:
    raw = open(sys.argv[1], encoding="utf-8").read()
    root = ET.fromstring("<root>" + raw + "</root>")
    errs: list[str] = []

    addrs = [(e.text or "").strip() for e in root.iter("address")]
    if addrs != [RELAY]:
        errs.append(f"<server><address> debe ser solo {RELAY}; hay {addrs}")

    qs = [(e.text or "").strip() for e in root.iter("queue_size")]
    eps = [(e.text or "").strip() for e in root.iter("events_per_second")]
    if qs != ["100000"] or eps != ["500"]:
        errs.append(f"client_buffer: queue_size={qs} events_per_second={eps} (se esperaba 100000 y 500)")

    files = {text(lf, "location"): lf for lf in root.iter("localfile")}
    for loc, hp in JSON_FILES.items():
        lf = files.get(loc)
        if lf is None:
            errs.append(f"falta el localfile {loc}")
            continue
        if text(lf, "log_format") != "json":
            errs.append(f"{loc}: log_format no es json")
        if text(lf, "only-future-events") != "no":
            errs.append(f"{loc}: only-future-events no es 'no'")
        labels = {lb.get("key"): (lb.text or "").strip() for lb in lf.findall("label")}
        if labels != {"@honeypot": hp}:
            errs.append(f"{loc}: etiquetas {labels}; se esperaba solo @honeypot={hp}")

    journald = [lf for lf in root.iter("localfile") if text(lf, "location") == "journald"]
    if len(journald) != 1:
        errs.append(f"se esperaba exactamente un localfile de journald; hay {len(journald)}")
    else:
        lf = journald[0]
        flt = lf.find("filter")
        if text(lf, "log_format") != "journald":
            errs.append("journald: log_format no es journald")
        if flt is None or flt.get("field") != "CONTAINER_NAME" or (flt.text or "").strip() != MAILONEY_FILTER:
            errs.append(f"journald: falta <filter field=\"CONTAINER_NAME\">{MAILONEY_FILTER}</filter>")
        if text(lf, "only-future-events") != "no":
            errs.append("journald: only-future-events no es 'no'")
        if lf.findall("label"):
            errs.append("journald: no debe llevar <label> (solo funciona con log_format json)")

    for e in errs:
        print(e)
    if not errs:
        print("relay, client_buffer, 3 localfile json con @honeypot y journald de Mailoney")
    return 1 if errs else 0


if __name__ == "__main__":
    raise SystemExit(main())
