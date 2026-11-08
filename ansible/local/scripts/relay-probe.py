#!/usr/bin/env python3
"""Utilidad del ensayo local de logrelay (no forma parte del rol).

  relay-probe.py serve SEGUNDOS PUERTO [PUERTO...]   eco TCP; sale solo tras SEGUNDOS
  relay-probe.py probe HOST PUERTO TOKEN echo|none   cliente; exit 0 si se cumple lo esperado
"""
from __future__ import annotations

import socket
import sys
import threading
import time


def serve(seconds: float, ports: list[int]) -> int:
    deadline = time.monotonic() + seconds

    def handle(conn: socket.socket) -> None:
        with conn:
            try:
                while data := conn.recv(4096):
                    conn.sendall(data)
            except OSError:
                pass

    def listen(port: int) -> None:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(8)
        srv.settimeout(0.5)
        while time.monotonic() < deadline:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
        srv.close()

    threads = [threading.Thread(target=listen, args=(p,)) for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return 0


def probe(host: str, port: int, token: str, expect: str) -> int:
    want = token.encode()
    got = b""
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            s.settimeout(3)
            s.sendall(want)
            try:
                while len(got) < len(want):
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    got += chunk
            except (socket.timeout, ConnectionResetError):
                pass
    except OSError:
        got = b""  # rechazo o corte antes de responder: sin eco

    ok = got == want if expect == "echo" else got == b""
    print(f"probe {host}:{port} esperado={expect} recibido={len(got)}B -> {'ok' if ok else 'FALLA'}")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "serve" and len(argv) >= 4:
        return serve(float(argv[2]), [int(p) for p in argv[3:]])
    if cmd == "probe" and len(argv) == 6 and argv[5] in ("echo", "none"):
        return probe(argv[2], int(argv[3]), argv[4], argv[5])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
