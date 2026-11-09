# Día 4 — Validación en Azure (2026-11-09, 01:08–01:56 CST)

Plan: `docs/superpowers/plans/2026-11-08-riesgos-post-dia3.md` (tabla "Día 4"). Logs `d4-*` de esta carpeta; `SHA256SUMS` verificado.

## Resultado por riesgo

| Riesgo | Paso | Resultado |
|---|---|---|
| 1 · tanner tras un ciclo real | 2 | **Validado.** Tras `deallocate`/`start` sin tocar nada: 7/7 `healthy`, `RestartCount` 0 en tanner y snare, `/tmp/tanner` y `/opt/tanner/files` con `mode=1777`. |
| 2 · el túnel no se recupera solo | 3, 4 | **Validado (1 observación).** Con `close_action = start` la SA llegó a `ESTABLISHED` a las 01:08:53, unos 26 s después de iniciarse `az vm start` de vm-strongswan, sin intervención. Tras `swanctl --terminate --child lab` en la VM, la Pi recreó el CHILD en el mismo segundo (SPI nuevo); 133 pings, 0 fallos (muestreo de 2 s). |
| 3 · Wazuh no alertaba | 5a, 5b | **Validado.** Ver abajo. |
| 4 · mantenimiento con el honeypot arrancado | 6a–6c | **Validado.** Etapa M completa; egreso abierto 9 min 27 s. |

## Medidas

**Arranque (paso 1):** 4 VMs en 173 s (01:08:27 → 01:11:20). IPs públicas sin cambios (172.202.13.163, 130.131.218.113).

**SA (paso 3):** el cronómetro desde T0=01:11:20 no sirve (la SA subió 146 s antes). El dato válido es "inicio de `az vm start` de strongswan → ESTABLISHED = ~26 s". La Pi estaba reintentando IKE (`peer not responding, trying again`) y enganchó en la retransmisión 3. Es una sola observación: el peor caso es el ciclo de reintentos de la Pi (~2 min).

**Detección (pasos 5a/5b)**, reglas locales (13) cargadas con `failed=0`:
- 6 logins aceptados (contraseñas `zq1`–`zq6`) → 6 × 100102 (nivel 10). MTTD 0,7 s (evento Cowrie → alerta); 1,4 s desde el primer intento.
- 12 fallos (6 con `root/root` y `root/123456`, 6 claves públicas desechables) → 10 × 100101 y 2 × 100110 (una por ráfaga, en el 5.º fallo). Cada fallo generó una alerta.
- 0 alertas con regla 1002 y 0 con 100105/100201 (healthchecks, nivel 0).
- Observación de diseño: Cowrie acepta a `root` con cualquier contraseña que no esté en su lista negra por defecto (`root`, `123456`...). Una fuerza bruta con otras contraseñas entra al primer intento (100102) y no produce `login.failed`. 100110 solo se activa con contraseñas vetadas o con claves públicas. **Decisión pendiente:** si TEST-002 debe medir también este caso (regla por frecuencia sobre 100102 o `userdb` restrictivo).
- Tráfico real: antes de la prueba, tres IPs de Internet ya habían iniciado sesión en el señuelo.

**Etapa M (pasos 6a–6c):**
- `--tags stop`: `changed=3`, 2.ª pasada `changed=0`; E1-3 cumplido (4 unidades `inactive disabled`, `centinelas-ok`).
- Egreso abierto 01:32:36 → cerrado 01:42:03 (9 min 27 s). Plan: exactamente 4 × create / 4 × destroy de `Allow-Out-Maintenance-Egress`.
- `--tags install,config` con egreso abierto: `ok=48 changed=0`, 57 s; E1-3 se mantuvo (Docker y agente dormidos).
- Cierre verificado en las 4 VMs (`curl` rc=28, DNS resuelve, 4 pong) antes del `start`.
- `--tags start`: `changed=4`; 2.ª `changed=0`; 7/7 `healthy`, agente `Active`, banner del 22 `SSH-2.0-OpenSSH_9.2p1 Debian…` (Cowrie, como indica el plan del Día 2).

**Regresión (paso 7):** `site.yml` sin tags `changed=0 failed=0` en las 4; `--check --diff` sin cambios; `terraform plan -var maintenance_egress=false -detailed-exitcode` → rc 0.

**Costos (paso 8):** `az consumption usage list` devolvió 52 registros con `pretaxCost` nulo, pero la API de Cost Management (`az rest`, tras un 429 con `retry-after: 18 s`) sí devolvió datos: ver `d4-8b-costos-api.json`. Acumulado a la fecha (USD): VMs 1,348; discos 0,278; IPs públicas 0,101; **total 1,728** (11-08: 1,463; 11-09: 0,265). **Los datos del 11-09 son parciales:** el cargo de VMs equivale a 0,52 h del precio combinado de ADR-006 ($0,234/h) y las 4 VMs llevaban unas 1,4 h encendidas desde las 00:00 UTC (esperable ≥ 0,33), así que la facturación se publica con retraso. Aún no hay un día completo con el que comparar con ≈ USD 35/mes (50 h/mes de cómputo ≈ 12 + IPs ≈ 9 + discos ≈ 14); repetir pasadas 24–48 h.

**Cierre (paso 9):** higiene 0/0 (PSK y `authd.pass`); `deallocate` en orden inverso 01:54:19 → 01:56:30; las 4 `VM deallocated`. La Pi queda reintentando IKE hacia 172.202.13.163 (consecuencia aceptada de `close_action`).

## Incidencias de la sesión (para no repetirlas)
- El prompt del paso 1 decía que `time-guard` rechazaba antes de las 07:00; yo lo había añadido y luego revertido (`e0de81d`). E1-9 solo prohíbe después de las 20:30.
- Mi primer filtro de contenedores contaba los de `terraform-mcp-server` (del plugin) como si fueran del ensayo local; el filtro correcto es `^soc-local`.
- Mi script de prueba SSH imprimía un `rc` siempre 0 (`$?` tras un `$(date)`); el resultado real se tomó de las alertas de Wazuh.
- "≥ 14 reglas" en 5a era un error de mi prompt: `local_rules.xml` tiene 13.

## Higiene y pendientes
- `grep -rFf` de `psk.hex` y `authd.pass` sobre esta carpeta: 0 coincidencias.
- Anonimización (2026-11-09): en los logs `d4-4`, `d4-5b`, `d4-9`, en este documento y en `2026-11-08/8-evento-prueba-archives.jsonl`, la IP pública del operador se sustituyó por `203.0.113.10` y las de tres escáneres de Internet por `198.51.100.1`–`.3` (rangos de documentación). Los originales y el mapa están fuera del repo. Las IPs del laboratorio (VPN y honeypot) se conservan. La IP real del operador sigue en `8-cierre-dia2.md` y en el plan del 2026-11-05 (commits ya publicados). Las contraseñas de prueba (`zq1`–`zq6`, `root`, `123456`) no son sensibles.
- Pendientes: costos con días completos (repetir pasadas 24–48 h) y PR de `merge/ansible-local`. Resueltos después del cierre: P8 (se mantiene sin `enable`) y la regla 100111 para el caso "contraseña aceptada" (ver el plan de riesgos).
