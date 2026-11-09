# Riesgos y deudas abiertas tras el Día 3 — plan de cierre

> **Para agentes:** SUB-SKILL REQUERIDA: superpowers:subagent-driven-development. El Bloque L se puede delegar por tarea. Ningún agente ejecuta `docker`, `make *-rehearse`, `make up/clean`, Terraform, `az` ni comandos en la Pi: la validación con contenedores la serializa el orquestador (la red local `10.50.0.0/16` choca con la ruta R1 mientras exista). La sesión Azure (Día 4) la ejecuta o autoriza el operador. Commits sin línea de coautor.

**Objetivo:** cerrar los 6 riesgos de `evidence/azure/2026-11-08/9-cierre-dia3.md` §Pendiente y de la auditoría del 2026-11-08, y dejar el SOC detectando (no solo ingiriendo) antes de la Fase 9.

**Arquitectura:** primero, todo lo que se puede hacer en local y sin costo (Bloque L); después, una sola sesión de Azure (Día 4) que valida todo junto.

## Riesgos (en orden de importancia)

| # | Riesgo | Tarea |
|---|---|---|
| 1 | Arreglo de tanner (`mode=1777`) sin probar en un ciclo real ni en el ensayo local | L1 + Día 4 paso 2 |
| 2 | El túnel no se recupera solo tras `deallocate`/`start` | L4 + Día 4 pasos 3–4 |
| 3 | Wazuh ingiere los eventos de los honeypots pero no genera alertas (`local_rules.xml` vacío) | L2 + Día 4 paso 5 |
| 4 | No hay procedimiento para abrir el egreso con el honeypot ya arrancado (E1-3) | L3 |
| 5 | Documentación posterior al despliegue sin actualizar (PIPELINE, ADR-006 P-A2, casillas) | L0 |
| 6 | Commits sin subir | L0 |

---

# Bloque L — Local, sin costo

### L0: limpieza (riesgos 5 y 6)
- [x] `git push` de la rama.
- [x] `docs/superpowers/plans/2026-11-05-despliegue-azure.md`: marcar `[x]` lo que la evidencia de `evidence/azure/2026-11-08/` (`7-`, `8-`, `9-cierre-*.md`) da por hecho. Dejar `[ ]` en Cost Management y en "tanner tras un ciclo real". Añadir al final una sección "Resultado" que enlace los tres cierres.
- [x] `ansible/PIPELINE.md`: registrar lo aprendido en Azure:
  - 4a usa la clave pública (no solo la huella), obtenida por `run-command`.
  - 4b entrega el PSK por `az rest` con un body JSON 0600 y `protectedParameters`.
  - Comprobación del origen sin NAT (`$SSH_CLIENT` empieza por `192.168.1.`).
  - La Etapa 6 va por grupos (`--limit`) con `ansible all -m ping` entre cada uno.
  - tmpfs con `mode` explícito (hallazgo de tanner, `0689283`).
- [x] ADR-006: P-A2 pasa a **VERIFICADO (2026-11-08, Día 1)**: el PSK no aparece en la instance view (`leak=0`) y el run command se borra al terminar. Queda abierto solo cuánto tiempo retiene Azure el historial de run-command.

**Hecho cuando:** `git status -sb` sin `ahead` y ningún "POR VERIFICAR" que ya esté resuelto.

**Resultado (2026-11-08):** HECHO. `1e7b307` (casillas y resultado), `9d99aac` (PIPELINE); ADR-004/006 actualizados en `.knowledge/` (fuera de git). Las casillas del Día 1 sin salida registrada se dejaron en `[ ]` con nota.

### L1: tanner en el ensayo local (riesgo 1, parte local) — orquestador
- [x] Operador: `ssh -t soc71 sudo swanctl --terminate --ike lab` y `sudo ip route del 10.50.0.0/16`.
- [x] `cd ansible && nix-shell --run 'make clean preflight honeypot-rehearse'`: `c10` en verde.
- [x] Prueba en rojo: sin `mode=1777` en `docker-compose.yml` (cambio temporal, sin commit), `c10` debe fallar. Restaurar y `make clean`.

**Hecho cuando:** `c10` pasa con el arreglo y falla sin él.

**Resultado (2026-11-08):** HECHO. `c10` en verde dentro de `honeypot-rehearse`; sin `mode=1777`, tanner `unhealthy` en los 2 reinicios y `Restarting (1)` (mismo síntoma que en Azure). Ciclo real validado el 2026-11-09 (Día 4, paso 2).

### L2: reglas de detección (riesgo 3; bloquea la Fase 9)

Punto de partida (`evidence/azure/2026-11-08/8-evento-prueba-archives.jsonl`): los 15 eventos de Cowrie llegan con `decoder.name=json` y `data.@honeypot=cowrie`. Solo `cowrie.login.failed` hace match, y lo hace con la regla genérica **1002** de Wazuh (ruido: contaría como FP).

**Archivos:**
- Modificar: `ansible/roles/wazuh/files/local_rules.xml`
- Crear: `ansible/local/fixtures/rules/<honeypot>.jsonl`, con eventos reales y anonimizados (IP de origen → `203.0.113.x`) tomados de `evidence/azure/2026-11-08/` y `evidence/local-tests/**/bind-mounts/`.
- Crear: `ansible/local/rules-check.sh`, que lleva cada fixture a `wazuh-logtest` del manager del ensayo local y exige el `rule.id` esperado. Incluye un caso negativo: un evento que no es de honeypot no puede hacer match en 100100–100499.
- Modificar: `ansible/Makefile` (target `rules-check`, añadido a `preflight`).

| Rango | Regla | TEST |
|---|---|---|
| 100100 | Base Cowrie: `<decoded_as>json</decoded_as>` + `<field name="@honeypot">^cowrie$</field>`, nivel 3; tiene que ganarle a la 1002 | — |
| 100101–100105 | `cowrie.login.failed` (5), `cowrie.login.success` (10), `cowrie.command.input` (8), `cowrie.session.file_download` (12) | TEST-002 |
| 100110 | Fuerza bruta: `frequency=5 timeframe=60` + `<same_source_ip/>` sobre 100101 (10) | TEST-002 |
| 100200 / 100210 | Base Dionaea y escaneo por frecuencia en varios puertos | TEST-001 / TEST-006 |
| 100300 | Mailoney (journald, `CONTAINER_NAME=soc-tesis-mailoney`): sesión SMTP | TEST-004 |
| 100400 / 100410 | Base Tanner y petición clasificada como ataque (campo de detección de `tanner_report.json`) | TEST-003 |

Nota: si de algún honeypot no hay muestra real, no se inventan campos. Se deja la regla base con un comentario `<!-- PENDIENTE: muestra real -->` y la captura de la muestra pasa a L1/L2-validación.

**Validación (orquestador, con contenedores):** `make clean wazuh-rehearse rules-check`; después, `make clean`.

**Hecho cuando:** cada fixture da el id esperado, ningún evento de Cowrie cae en la 1002, el caso negativo pasa y `preflight` sale en verde.

**Resultado (2026-11-08/09):** HECHO, `1d71477` + ampliación con muestras del ensayo local. `rules-check: ok (32 eventos)` contra el Manager 4.14.10; `wazuh-check` ok. `rules-check` queda fuera de `preflight` (preflight no levanta el Manager).
- Supuestos corregidos al validar: `frequency=N` dispara en el evento N (no N+1); Mailoney se reconoce por `<program_name>` (el pre-decoder lo saca del mensaje y `<match>` no lo ve).
- Muestras reales capturadas con tráfico controlado contra el honeyserver local: `cowrie.command.input` (100103), `sqli`/`xss` de Tanner (100410), sondeo de 4 servicios de Dionaea (100210, con `<different_field>dst_port</different_field>`).
- **Hallazgo — healthchecks:** los healthchecks de Docker de Cowrie (127.0.0.1:2222) y Dionaea (127.0.0.1:21) generan eventos cada pocos segundos (25 y 15 en ~15 min). Sin filtro serían alertas nivel 3 permanentes (ruido y FP). Reglas 100105 y 100201 de nivel 0. Siguen viajando al Manager: filtrarlos en el agente si el volumen pesa.
- **Hallazgo — escaneos y Dionaea:** un `nmap -sT` no deja eventos en Dionaea (falla `getpeername` al aceptar una conexión ya cerrada). 100210 detecta sondeo de servicios (banner grab, `-sV`), no un connect scan puro. Afecta el diseño de TEST-001: o se usa `-sV`, o el escaneo se mide por otra fuente.
- Sigue sin muestra posible: 100104 (`file_download`), porque con el egreso cerrado Cowrie no descarga (el `wget` falla al resolver). Queda como regla preventiva.

### L3: procedimiento de mantenimiento (riesgo 4)

**Archivos:**
- Modificar: `ansible/roles/honeypot/tasks/main.yml` con un tag nuevo `stop`, inverso de `start`: `docker compose down`; `systemctl disable --now` de `docker.socket`, `docker.service`, `containerd.service` y `wazuh-agent`; borrar `/etc/soc-tesis/honeypot-started`. Sin descargas.
- Modificar: el contrato de tags (`make tags-contract`) para que `stop` tampoco descargue nada.
- Modificar: `ansible/Makefile` con el target `egress-precheck`, que reutiliza el check E1-3 del plan de Azure (4 unidades `inactive disabled` y `centinelas-ok`) y sale con código ≠ 0 si no se cumple.
- Modificar: `ansible/PIPELINE.md` con una "Etapa M (mantenimiento)" en este orden: `--tags stop` → `egress-precheck` → abrir egreso (gate) → `install,config` → cerrar egreso (gate) → `--tags start` → 2ª `start` con `changed=0`.

**Validación (orquestador, con contenedores):** en local, `start` → `stop` → `toggle-install` → `install,config` → `toggle-operate` → `start`, con los 7 contenedores healthy y `changed=0` en la 2ª pasada de `start`.

**Resultado (2026-11-08):** HECHO, `9d99aac`. `stop` changed=3 y luego 0; `egress-precheck` ok tras `stop` y en rojo con el honeypot arrancado (`E1-3 FALLA: docker.socket`); `install,config` + `start` ×2 (2ª con changed=0); `honeypot-check` con `c10` ok. Nota: ejecutar Ansible siempre por `make` (o con sus 5 variables `ANSIBLE_*`): sin ellas se usan el inventario de Azure y `~/.ssh/known_hosts`, y `StrictHostKeyChecking` corta la conexión (comprobado).

### L4: túnel (riesgo 2) — diagnóstico HECHO, la decisión es del operador

**Evidencia (2026-11-08, `journalctl -u strongswan` en la Pi, solo lectura):**
```
17:41:44 deleting IKE_SA lab[2] ... 172.202.13.163   (cierre del Día 2)
   — ningún intento de reconexión en 35 min —
18:17:24 vici initiate CHILD_SA 'lab'                (activar.sh a mano, Día 3)
18:35:26 deleting IKE_SA lab[3] ... 172.202.13.163   (deallocate del Día 3)
```
`swanctl --list-conns`: `dpd delay 30s`, `dpd action is start`.

**Causa:** al apagarse la VM de Azure (o con `swanctl --terminate`), el par manda un IKE DELETE. La Pi borra la SA y no la vuelve a iniciar: `dpd_action` solo actúa cuando el par deja de responder, no cuando avisa que cierra, y `start_action=start` solo actúa al cargar la configuración. Falta `close_action = start` en el CHILD `lab` de la Pi.

**Arreglo propuesto (operador; la config de la Pi vive fuera del repo):**
- [x] En `/root/soc-tesis-ipsec/10-azure-lab.conf` (y en la copia cargada en `/etc/swanctl/conf.d/`): `close_action = start` en `children.lab`. `keyingtries = 0` ya está.
- [x] `sudo swanctl --load-all` sin errores (2026-11-08). `swanctl --list-conns` (5.9.13) no muestra `close_action`: se comprueba en el Día 4, pasos 3 y 4.
- [x] Consecuencia que se acepta: mientras las VMs están `deallocated`, la Pi reintenta IKE hacia la IP pública de Azure (tráfico mínimo). El cierre de día deja de necesitar `--terminate`.
- [ ] Decisión aparte, P8 (ADR-004 §12): `systemctl enable strongswan` en la Pi para sobrevivir a un reinicio. Hoy no se hace.
- [x] Registrar la causa y la decisión en ADR-004 §12.

---

# Día 4 — Validación en Azure (~2 h, con los gates habituales)

| # | Paso | Valida |
|---|---|---|
| 1 | Restaurar R1; `make time-guard pin-check`; `az vm start` en orden | — |
| 2 | Sin tocar nada: 7/7 `healthy` y `RestartCount` de tanner en 0 | Riesgo 1 |
| 3 | La SA se levanta sola (con `close_action=start`); anotar el tiempo hasta `ESTABLISHED` | Riesgo 2 |
| 4 | TEST-008 adelantado: `swanctl --terminate --child lab` en la VM (por `run-command`); la Pi se recupera sola; anotar el tiempo | Riesgo 2 |
| 5 | `--tags config --limit wazuh` (reglas); `ssh root@<honeyserver_public_ip>` con 6 contraseñas → 100101 ×6 y 100110 ×1. Anotar el primer MTTD | Riesgo 3 |
| 6 | (Opcional, abre el egreso, con gate) Etapa M completa | Riesgo 4 |
| 7 | Pasada sin tags → `changed=0`; `terraform plan -var maintenance_egress=false -detailed-exitcode` → 0 | Regresión |
| 8 | Cost Management con más de 24 h de datos frente a ≈ USD 35/mes (ADR-006 §6) | Pendiente del Día 3 |
| 9 | Evidencia + `SHA256SUMS` + higiene (PSK, `authd.pass` → 0); `deallocate` en orden inverso | — |

**Resultado (2026-11-09):** HECHO, salvo costos. Detalle y medidas en [`10-cierre-dia4.md`](../../../evidence/azure/2026-11-09/10-cierre-dia4.md).

| # | Resultado |
|---|---|
| 1 | VMs arrancadas en 173 s; IPs sin cambios |
| 2 | 7/7 `healthy`, `RestartCount` 0 en tanner y snare (riesgo 1 validado) |
| 3 | SA `ESTABLISHED` sola en ~26 s desde el inicio del arranque de vm-strongswan (riesgo 2) |
| 4 | CHILD recreado en el mismo segundo, 0 pings perdidos (riesgo 2) |
| 5 | 6 × 100102 (MTTD 0,7 s); 10 × 100101 y 2 × 100110 con 12 fallos; 0 en la 1002 (riesgo 3) |
| 6 | Etapa M completa; egreso abierto 9 min 27 s (riesgo 4) |
| 7 | `changed=0` en las 4, `--check` sin cambios, `terraform plan` rc 0 |
| 8 | **Parcial:** `az consumption` dio `pretaxCost` nulo, pero la API de Cost Management dio datos: 1,73 USD acumulados (VMs 1,35; discos 0,28; IPs 0,10), con el 11-09 incompleto por retraso de facturación. Sin día completo aún; repetir pasadas 24–48 h |
| 9 | Higiene 0/0, `SHA256SUMS` correcto, 4 VMs `deallocated` |

**Decisiones tomadas (2026-11-09):**
- **P8:** se mantiene `activar.sh` sin `enable`. Habilitarlo haría que la Pi reintentara IKE para siempre hacia una IP que `activar.sh` sustituye a mano y que cambia si se recrea la IP pública; con `close_action` el único paso manual restante es tras reiniciar la Pi.
- **TEST-002:** el señuelo acepta casi cualquier contraseña de `root`, así que "fuerza bruta" se mide por dos vías: `login.failed` (100101 → 100110) con contraseñas vetadas o claves, y ráfaga de logins aceptados (100102 → 100111, 5 en 60 s). La 100111 está en `local_rules.xml` con fixture; su validación en `rules-check` queda registrada en el commit.

## Fuera de alcance
- Fase 4 (agentes en Windows/Linux; TEST-005) y Fase 7 (aplicar `terraform/evidence`): siguen en el plan maestro.
