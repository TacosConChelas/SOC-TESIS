#!/usr/bin/env python3
"""Escaneo de secretos sobre el arbol que ve git (no solo el diff).

Universo de archivos:
    git ls-files --cached --others --exclude-standard

Reglas:
  A. `-----BEGIN ... PRIVATE KEY-----` en cualquier archivo del arbol.
  B. Asignacion literal de PSK / pre_shared_key / secret con valor de 8+
     caracteres. Se ignoran referencias (`$VAR`, `{{ var }}`, `<...>`).
  C. Token hexadecimal de 64 caracteres (32 bytes: tamano de un PSK), fuera de
     `.terraform.lock.hcl` y de contextos de digest (`sha256:...`, salida de
     `sha256sum`, `"sha256": "..."`), que son hashes legitimos ya registrados
     como evidencia.

La regla C se exceptua ademas para los prefijos listados en
`local/secret-scan.allow` (evidencia grabada con hashes sha256). Las reglas A y
B cubren el arbol completo, sin excepciones.

Salida: `archivo:linea [regla]`, con el valor redactado. Exit 1 si hay hallazgos.
"""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import sys
from pathlib import Path

MAX_BYTES = 5 * 1024 * 1024
SKIP_HEX_FILES = {".terraform.lock.hcl"}

PRIV_RE = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
ASSIGN_RE = re.compile(
    rb"(?i)\b(?:psk|pre[_-]?shared[_-]?key|secret)\b\s*[:=]\s*[\"']?(?P<val>[^\s\"'#]{8,})"
)
HEX64_RE = re.compile(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
DIGEST_BEFORE_RE = re.compile(rb"(?i)(sha(?:1|224|256|384|512)|md5)[\"']?\s*[:=]\s*[\"']?$")
SHA256SUM_LINE_RE = re.compile(rb"^[0-9a-fA-F]{64}[ \t]+\S")
IGNORED_VALUE_PREFIXES = (b"$", b"{{", b"<", b"%(", b"!!")


def git_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        check=True,
    ).stdout
    return [Path(os.fsdecode(p)) for p in out.split(b"\0") if p]


def read_text(path: Path) -> bytes | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data


def redact(value: bytes) -> str:
    return value[:4].decode("utf-8", "replace") + "..." if value else ""


def load_hex_allowlist(root: Path) -> list[str]:
    allow = root / "ansible" / "local" / "secret-scan.allow"
    if not allow.is_file():
        return []
    patterns: list[str] = []
    for raw in allow.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def hex_allowed(rel: Path, patterns: list[str]) -> bool:
    if rel.name in SKIP_HEX_FILES:
        return True
    text = rel.as_posix()
    return any(fnmatch.fnmatch(text, pat) for pat in patterns)


def scan_line(path: Path, lineno: int, line: bytes, findings: list[str], allow_hex: bool) -> None:
    if PRIV_RE.search(line):
        findings.append(f"{path}:{lineno} [A:llave-privada] bloque PEM detectado")

    for match in ASSIGN_RE.finditer(line):
        value = match.group("val")
        if value.startswith(IGNORED_VALUE_PREFIXES):
            continue
        findings.append(
            f"{path}:{lineno} [B:valor-literal] asignacion con valor (redactado: {redact(value)})"
        )

    if allow_hex:
        return
    for match in HEX64_RE.finditer(line):
        before = line[max(0, match.start() - 32) : match.start()]
        if DIGEST_BEFORE_RE.search(before):
            continue
        if path.suffix.lower() in {".txt", ".log"} and SHA256SUM_LINE_RE.match(line):
            continue
        findings.append(
            f"{path}:{lineno} [C:hex64] token de 64 hex (redactado: {redact(match.group(0))})"
        )


def main() -> int:
    root = Path.cwd()
    if not (root / ".git").exists():
        print("secret-scan: ejecutar desde la raiz del repo", file=sys.stderr)
        return 2

    findings: list[str] = []
    scanned = 0
    allow_patterns = load_hex_allowlist(root)

    for rel in git_files():
        path = root / rel
        data = read_text(path)
        if data is None:
            continue
        scanned += 1
        allow_hex = hex_allowed(rel, allow_patterns)
        for lineno, line in enumerate(data.splitlines(), start=1):
            scan_line(rel, lineno, line, findings, allow_hex)

    if findings:
        print(f"secret-scan: FALLA ({len(findings)} hallazgo(s))", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1

    print(f"secret-scan: ok ({scanned} archivos)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
