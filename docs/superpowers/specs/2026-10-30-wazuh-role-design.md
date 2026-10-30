# Diseño del rol Ansible `wazuh`

**Fecha:** 2026-10-30
**Rama:** `practica/ansible-local`
**Estado:** diseño aprobado por el operador; pendiente de plan de implementación.
**Fuentes:** `.knowledge/18_DECISIONES_IMPLEMENTACION.md` (D4, D5, D7, D8), `.knowledge/17_SOFTWARE_BASELINE.md` (D1), ADR-006 (A3, E1-3, E1-7, E1-8), `ansible/PIPELINE.md`, documentación de Wazuh (asistente de instalación y herramienta de contraseñas).
**Contexto:** tercer subproyecto de P-A1. Los roles `logrelay` y `common` ya están hechos.

## 1. Objetivo

Reemplazar el rol marcador `wazuh` por la instalación y configuración reales del all-in-one (Manager + Indexer + Dashboard, sin Logstash) en `10.50.40.10`, con verificación de versión, manejo de secretos fuera del repositorio y ensayo local con el all-in-one real en el contenedor.

Descomposición acordada: **W1** instalación y verificación de versión, **W2** configuración posterior, **W3** manejo de secretos, en un solo rol. Quedan fuera las reglas por honeypot (otra fase) y el rol `honeypot`.

## 2. Decisiones del operador

| Tema | Decisión |
|---|---|
| Versión | Asistente online `wazuh-install.sh -a` y verificación posterior de la versión contra `wazuh_expected_version`. El asistente no admite fijar versión: instala el último parche de la rama 4.14, que puede diferir de 4.14.8-1 (la documentación actual ya indexa 4.14.9). Si no coincide, el rol falla y se decide el baseline (D1). |
| Ensayo local | All-in-one **completo** en el contenedor `wazuh`, con heap sobrescrito. |
| Cuándo corre | Target aparte `make wazuh-rehearse`; `make preflight` omite el rol. |
| Secretos | Ansible los mueve, siempre fuera del repo: `authd.pass` entra desde el controlador; `wazuh-install-files.tar` sale con `fetch` y se destruye con `shred` en la VM. |
| Chequeo ampliado | Check de la cadena D4 real: un agente en `honeyserver` se enrola por el relay y aparece activo. |

## 3. Variables (prefijo `wazuh_`)

| Variable | Valor |
|---|---|
| `wazuh_enabled` | `true` (en el inventario local: `false`; `wazuh-rehearse` pasa `-e wazuh_enabled=true`) |
| `wazuh_expected_version` | `4.14.8` (baseline; subirla a 4.14.9 es decisión del operador tras verificarla) |
| `wazuh_installer_url` | `https://packages.wazuh.com/4.14/wazuh-install.sh` |
| `wazuh_indexer_heap` | `8g` (D5); el inventario local lo sobrescribe a `2g` |
| `wazuh_retention_days` | `30` |
| `wazuh_secrets_dir` | `~/soc-tesis-secrets/wazuh` en el controlador; debe estar **fuera del repo** |
| `wazuh_relay_ip` | `10.50.30.10` |
| `wazuh_admin_cidr` | `192.168.1.0/24` (`lab_cidr`) |

## 4. Contenido y tags

| Tag | Qué hace | Descarga |
|---|---|---|
| `install` | Comprueba RAM, disco y `vm.max_map_count` ≥ 262144 (persistido en `/etc/sysctl.d/99-soc-wazuh.conf`; `sysctl -p` solo en host real). Descarga el instalador y corre `-a` con `no_log`, protegido por el centinela `/etc/soc-tesis/wazuh-installed` (se escribe solo tras pasar el gate de versión). Exige que `wazuh-control info` reporte `wazuh_expected_version`. Retiene (`hold`) `wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard` y `filebeat` | **Sí** (único tag) |
| `config` | Entrega `authd.pass` desde el controlador (640 `root:wazuh`, `no_log`). Edita `ossec.conf`: `use_password yes`, `use_source_ip no`, `logall` y `logall_json` en `no`, Active Response y detección de vulnerabilidades apagados. Punto de enganche para `local_rules.xml` (validado con `wazuh-analysisd -t`; hoy solo encabezado). Heap del Indexer en `jvm.options`. API en loopback (`api.yaml`). Política ISM de `wazuh_retention_days` días sobre `wazuh-alerts-*`, aplicada con la contraseña leída en memoria del tar (`no_log`). Luego `fetch` del tar al controlador, comparación de `sha256`, y solo entonces `shred` del tar y borrado de `/var/log/wazuh-install.log`; centinela `wazuh-secrets-handed-over`. UFW al final (solo host real) | No |
| `start` | Habilita y arranca indexer, manager, filebeat y dashboard en ese orden y espera con reintentos (30 × 10 s) a 1514, 1515, 443 y 9200 local | Nunca |

Reglas del rol:
- **Guardas de secretos:** falla si `wazuh_secrets_dir` queda dentro del repo, si `authd.pass` no existe, o si el `fetch` no coincide por `sha256` (en ese caso no se hace `shred`).
- **Idempotencia:** las tareas de ISM, `fetch` y `shred` se saltan si existe el centinela `wazuh-secrets-handed-over`.
- **UFW** (solo host real, mismo patrón que `logrelay`): SSH desde `wazuh_admin_cidr`; 1514/1515 desde el relay y `wazuh_admin_cidr`; 443 desde `wazuh_admin_cidr`; entrada denegada, salida permitida; activar al final.
- **Servicios durante `install`:** el asistente los arranca con `systemctl`, no con `invoke-rc.d`, así que el `policy-rc.d` de `common` no interviene. E1-3 aplica al honeypot, no a Wazuh.
- `wazuh_enabled: false` termina el rol de inmediato (`meta: end_role`, con las tres tags del contrato).

## 5. Errores y casos límite

| Riesgo | Comportamiento |
|---|---|
| El asistente instala otro parche | Falla *después* de instalar con un mensaje de desviación de D1. El `pin-check` del lote de pendientes debe consultar el índice `packages.wazuh.com/4.x/apt` para verlo en la Etapa 0. |
| Instalación a medias | Sin centinela y con restos en `/var/ossec`, el rol se detiene y pide desinstalar a mano con `wazuh-install.sh -u`; no borra nada solo. |
| RAM, disco o `vm.max_map_count` insuficientes | Verificación previa con mensaje claro, antes de descargar. |
| `fetch` falla o `sha256` distinto | No hay `shred`: el tar sigue en la VM para reintentar. |
| La API del Indexer no responde al aplicar ISM | Reintentos; si falla, no hay `fetch` ni `shred`. |
| Cambiar la retención después de entregar los secretos | Límite conocido: se hace a mano desde el Dashboard, porque la contraseña ya no está en la VM. |
| Arranque en frío lento | Reintentos en `start`; si no responde, el play falla indicando qué servicio falta. |
| El log del asistente contiene contraseñas | `no_log` y borrado de `/var/log/wazuh-install.log` tras el `fetch`; el check 8 lo verifica. |

## 6. Pruebas locales

**Separación del `preflight`:** el inventario local marca `wazuh_enabled: false`. `make wazuh-rehearse` pasa `-e wazuh_enabled=true`.

**Entorno de ensayo:**
- Inventario local: `wazuh_indexer_heap: 2g`.
- Secretos del ensayo en `/tmp/soc-local-secrets/` (700, fuera del repo; así la guarda de "fuera del repo" se ejerce de verdad). `make clean` lo borra. `authd.pass` desechable.
- Verificación del anfitrión antes de empezar: `MemAvailable` suficiente y `vm.max_map_count` ≥ 262144. No cambia nada del sistema; si falta algo, se detiene con un mensaje.

**Flujo de `make wazuh-rehearse`:** verificación del anfitrión → 1ª pasada `--tags install,config` sobre el contenedor `wazuh` (10 a 25 min, exige `changed`) → 2ª pasada (`changed=0`) → `--check --diff` sin cambios → egreso cerrado → `--tags start` dos veces → `make wazuh-check`.

**`make wazuh-check`** (exit ≠ 0 si algo falla):

| # | Check |
|---|---|
| 1 | `wazuh-control info` reporta `wazuh_expected_version`; los 4 paquetes en `hold` |
| 2 | indexer, manager, filebeat y dashboard activos |
| 3 | 1514, 1515 y 443 en todas las interfaces; 9200 y 55000 solo en `127.0.0.1`; 1516, 9300 y 514 cerrados |
| 4 | `ossec.conf` con `logall`/`logall_json` en `no`, `use_password yes`, `use_source_ip no`, AR y vulnerabilidades apagados; `wazuh-analysisd -t` en 0 |
| 5 | `authd.pass` en `640 root:wazuh` con el mismo `sha256` que el del controlador (sin imprimirlo) |
| 6 | `jvm.options` con el heap de la variable (no un valor fijo en el check) |
| 7 | La política ISM existe y borra `wazuh-alerts-*` a los 30 días (consulta a la API con la contraseña leída del tar, sin imprimirla) |
| 8 | Ni el tar ni `/var/log/wazuh-install.log` quedan en la VM; el tar fetched está en `/tmp/soc-local-secrets/` con `0600`; `make secret-scan` limpio |
| 9 | Cadena D4 real: un fixture del arnés instala `wazuh-agent` en `honeyserver` apuntando a `10.50.30.10` con la contraseña, y el agente aparece **activo** en `agent_control -l` |
| 10 | Prueba negativa: con `-e wazuh_expected_version=4.14.0` el rol falla con el mensaje de desviación |

El check 9 cierra el hueco que dejó `relay-check` (probaba el paso de bytes, no el enrolamiento TLS ni el cifrado reales). El agente es un fixture del arnés: el rol `honeypot` lo instalará de verdad.

**No se valida en local:** UFW real y el NSG de Azure; el tamaño real (heap de 8g en `B4as_v2`) y el arranque en frío con `az vm start`; que los datos del Indexer sobrevivan a `deallocate`/`start`; el acceso al Dashboard desde la LAN por el túnel.

## 7. Criterio de listo

- `make wazuh-rehearse` pasa (los 10 checks) con la 2ª pasada en `changed=0`.
- `make preflight` sigue en verde con el rol omitido.
- Lint, contrato de tags y escaneo de secretos limpios.
- Los cambios se limitan a `ansible/` y `docs/`; `PIPELINE.md` (Etapas 6 y 8) se actualiza con el gate de versión, la entrega de secretos, la ventana de instalación y los puertos.

**Dependencias:**
- `make up` no debe recrear contenedores (Tarea A del lote de pendientes), o `wazuh-rehearse` destruiría la instalación al reiniciar el arnés.
- La decisión del baseline (4.14.8 o 4.14.9) sale de la Tarea C del mismo lote. Conviene completarlo antes de implementar.

## 8. Fuera de alcance

- Contenido de `local_rules.xml` (otra fase, rangos 100100–100499).
- Cambio de contraseña de admin.
- Agentes Windows 11 y Ubuntu del laboratorio.
- Personalización del Dashboard y despliegue distribuido.
- El rol `honeypot`.
