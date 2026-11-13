# Día 5 — Enrolamiento y eventos (2026-11-13, 00:51–04:14 CST)

Plan: `docs/superpowers/plans/2026-11-09-ruta-endpoints.md` (E4). Logs `d5-*` de esta carpeta; `SHA256SUMS` verificado.

## Resultado

| Casilla de E4 | Resultado |
|---|---|
| Preflight, R1, `az vm start`, SA, 4 pong | **Hecho** (`d5-1`). SA sola. R1 requiere `mtu 1360` (corregido en el plan). |
| Alcance 1514/1515 desde `.74` y `.75` | **Hecho** (`d5-2`, `d5-3`, `d5-4`). TCP conectaba, pero el TLS se colgaba: ver "Hallazgo principal". |
| Arrancar agentes | **Hecho** (`d5-4`, `d5-5`). `win11-lab` se enroló solo en el primer intento con clamp (02:03:26); `ubuntu-lab` a las 02:30:42, sin `mtu` en su ruta. |
| `agent_control -l` | **Hecho.** `001 vm-honeyserver`, `002 win11-lab`, `003 ubuntu-lab` Active. |
| Eventos benignos y latencia | **Hecho** (`d5-6`). Ubuntu 0,14–0,35 s; Windows ~0,9 s. |
| Dashboard | **Hecho** (`d5-7`). El operador accedió y confirmó la verificación visual (sin conteos numéricos); cruce con `alerts.json` coherente. |
| Ciclo `deallocate`/`start` con agentes | **Hecho** (`d5-8`). Ver TEST-008. |
| Evidencia, higiene, `deallocate` en orden inverso | **Hecho** (`d5-9`, `d5-10`). |

## Hallazgo principal: faltaba un MSS-clamp en el túnel
El Manager respondía con segmentos de 1410 B hacia la LAN. Con la sobrecarga de ESP no caben en 1500, nunca recibían ACK y no volvía un ICMP útil. Síntomas: SSH con KEX post-cuántico colgado en `.73`, TLS colgado desde `.74` y `ERROR: SSL error (5)` del agente de Windows contra `authd` (que estaba sano).
Solución: dos reglas en la cadena `forward` de la Pi, `ip saddr @azure_net` e `ip daddr @azure_net`, `tcp flags syn tcp option maxseg size set 1320`. Cubre a los tres clientes sin tocar sus rutas; los clientes no llevan `mtu`. Persistido en `/etc/nftables.conf` (sha256 `b03aa8b8…` → `245b0e72…`, copia `.bak-20261113`, diff en `d5-9-pi-nftables.diff`). El reload no tumbó el túnel. Rollback: `sudo cp -a /etc/nftables.conf.bak-20261113 /etc/nftables.conf && sudo nft -f /etc/nftables.conf`.
Hay que reflejarlo en ADR-006 E1-11 (fuera del repo, en `.knowledge`): la solución pasa de "mtu por ruta" a "clamp en la Pi".

## Medidas (TEST-008, base)
- Caída de Azure: 13 min 28 s (03:47:11 → 04:00:39).
- SA tras el `start` de strongswan: ~33 s, sola, sin `--initiate`.
- Reconexión: win11-lab ~2 s tras terminar el `start` de wazuh; ubuntu-lab ~39 s.
- Eventos generados con Azure apagado (3 logins SSH fallidos en Ubuntu; 2 altas y 2 bajas de usuario local en Windows): **0 perdidos, 0 duplicados**. Todo llegó después de reconectar, ~2 s (Windows) y ~4 s (Ubuntu) tras la reconexión. Cada intento SSH da 2 alertas 5710; cada alta de usuario da 4720 y 4722 (60109).
- Honeyserver tras el ciclo: 7/7 contenedores `healthy` (confirma otra vez el Día 4).
- Límites: los "Active" son cotas superiores (una sola consulta); la reconexión de `001` no se midió; solo se probó una caída corta con pocos eventos, **el límite del buffer del agente no se ha ejercitado**.

## Otros cambios y hallazgos
- Reloj de Win11 con +7200 s (sin sincronizar): corregido con `w32tm` (offset < 0,4 s); el agente siguió Active.
- Windows deduplica el 4625: 3 `net use` fallidos dan un solo evento. Contar 4625 subestima los intentos de red; el 4776 no está auditado.
- `<oper-ubuntu>` (cuenta del cliente Ubuntu) es `NOPASSWD: ALL`: no existe fallo de `sudo` que generar; se sustituyó por un 4.º login SSH fallido.
- Ruido preexistente: AppArmor `52002` cada ~10 s en `ubuntu-lab`.
- `~/.ssh/known_hosts` del operador tiene claves RSA de los contenedores del ensayo local (mismas IPs 10.50.x): Ansible solo funciona con `source ~/soc-tesis-secrets/azure-session.env`.
- `w32tm /resync` devuelve rc=0 aunque falle; verificar con `w32tm /query /status` y el offset.

## Costos
Cómputo de las 4 VMs: ~3,1 h (00:53 → 03:47 y 04:00 → 04:12; ≈ 0,73 USD a 0,234 USD/h, estimación). Costo fijo con las VMs `deallocated`: 0,72 USD/día. Cierre: `deallocate` en orden inverso 04:12:11 → 04:14:21; las 4 `VM deallocated`. La Pi queda reintentando IKE (consecuencia aceptada de `close_action`).

## Higiene y pendientes
- `grep -rlFf` de `authd.pass` y `psk.hex` sobre esta carpeta: 0 coincidencias; sin claves privadas ni IPs públicas del operador.
- Anonimización (2026-11-13): las cuentas locales reales de la Pi y del cliente Ubuntu se sustituyeron por `<oper-pi>` y `<oper-ubuntu>` en los `d5-*`. Los originales están fuera del repo.
- Pendientes: ADR-006 E1-11 (nota del clamp); README de `ansible/local` (sugiere un `known_hosts` que no funciona); entradas para TEST-005 (4625 deduplicado, AppArmor `52002`, 4776 sin auditar, Sysmon solo si deja un FN).
