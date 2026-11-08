# Diseño del rol Ansible `logrelay`

**Fecha:** 2026-10-29
**Rama:** `practica/ansible-local`
**Estado:** diseño aprobado por el operador; pendiente de plan de implementación.
**Fuentes:** `.knowledge/18_DECISIONES_IMPLEMENTACION.md` (D4, D7), `.knowledge/17_SOFTWARE_BASELINE.md` (D1), ADR-006 (A7, E1-3, E1-7, E1-8), `ansible/PIPELINE.md`.
**Contexto:** primer subproyecto de P-A1 (tareas reales de cada rol). Orden previsto de los siguientes: `common`/`strongswan`, `wazuh`, `honeypot`.

## 1. Objetivo

Reemplazar el rol marcador `logrelay` por el reenvío real definido en D4: NGINX `stream` (L4 passthrough) en `10.50.30.10` que pasa los puertos 1514 y 1515 del agente Wazuh del honeyserver hacia el Manager en `10.50.40.10`. El relay no descifra, no almacena eventos y no tiene credenciales de Wazuh.

## 2. Enfoque elegido

Plantilla Jinja del `/etc/nginx/nginx.conf` completo, parametrizada con variables de `defaults`:

| Variable | Valor |
|---|---|
| `logrelay_listen_ip` | `10.50.30.10` |
| `logrelay_manager_ip` | `10.50.40.10` |
| `logrelay_agent_ip` | `10.50.10.10` |
| `logrelay_admin_cidr` | `192.168.1.0/24` (`lab_cidr`) |
| `logrelay_nginx_version` | `1.18.0-6ubuntu14.22` |

El pin pasó de `1.18.0-6ubuntu14.21` (baseline D1, verificado el 2026-10-07) a `1.18.0-6ubuntu14.22` el 2026-10-29, porque 14.21 ya no existe en `jammy-updates` ni `jammy-security`. El baseline (`17_SOFTWARE_BASELINE.md`, fila NGINX) queda por actualizar por el operador como desviación registrada.

El `nginx.conf` es mínimo: solo `events {}` y `stream {}`. Se descartan el archivo estático (IPs repetidas, no parametrizable para el ensayo) y los roles de la comunidad (dependencia nueva para pocas líneas).

## 3. Contrato de tags

| Tag | Acciones | Descarga |
|---|---|---|
| `install` | `nginx`, `nginx-core`, `nginx-common` y `libnginx-mod-stream` en la versión exacta y retenidos (`dpkg_selections` hold; el binario `/usr/sbin/nginx` vive en `nginx-core`), `ufw` y `logrotate` si faltan | Sí (único tag) |
| `config` | plantilla de `nginx.conf` con `validate: nginx -t -c %s`; `access_log` de `stream` solo con metadatos (IP, bytes, duración); logs en `/var/log/soc-relay/stream.log` (fuera de `/var/log/nginx/`, que el paquete ya rota a 14 días) con logrotate propio a 7 días; reglas UFW y activación de UFW al final | No |
| `start` | NGINX habilitado y activo | Nunca |

Reglas de UFW (solo host real, `when: ansible_virtualization_type != 'docker'`, E1-7):
- permitir SSH 22 desde `logrelay_admin_cidr`;
- permitir 1514/1515 solo desde `logrelay_agent_ip`;
- política de entrada: denegar; política de salida: **permitir** (el control de egreso lo mantiene el NSG, cerrado fuera de la ventana de mantenimiento, para no romper `apt` en una pasada posterior);
- las reglas `allow` se definen antes de activar UFW.

Excepción deliberada al contrato: activar UFW habilita `ufw.service` dentro de `config`; es aceptable porque no arranca servicios de la aplicación.

Defensa en profundidad dentro de NGINX: `allow 10.50.10.10; deny all;` en el bloque `stream`, además del NSG y UFW.

## 4. Errores y casos límite

| Riesgo | Comportamiento |
|---|---|
| Ubuntu retira la versión fijada de `jammy-updates` | `apt` falla con "version not found"; no se instala otra. Se re-verifica el baseline (doc 17 §3) y se actualiza `logrelay_nginx_version`. |
| Plantilla inválida | `nginx -t` falla antes de reemplazar el archivo. |
| NGINX arranca solo al instalarse | Lo evita el `policy-rc.d` del rol `common` (E1-3), que corre antes. El arranque ocurre en `start`. |
| Cambio de configuración con NGINX activo | Un handler hace `reload`, solo si el servicio está activo. |
| UFW corta el SSH | Reglas `allow` antes de `enable`; la Etapa 6 hace `ansible all -m ping` justo después. Rescate: `az vm run-command` con `ufw disable`. |
| NGINX escucha en una IP concreta | El drop-in `10-soc-relay.conf` hace que arranque tras `network-online.target`, para que `az vm start` tras un `deallocate` no falle con "Cannot assign requested address". |
| `install` sin egreso | Falla por red; sin reintento silencioso. |

## 5. Pruebas locales

Los contenedores usan las IPs reales de Azure en la red `operate`. Pieza de prueba, solo local y fuera del rol: un eco TCP en 1514 y 1515 en el contenedor `wazuh` que hace de Manager falso. Target nuevo `make relay-check` (incluido en `preflight`), todos con exit ≠ 0 si fallan:

1. Desde `honeyserver`, conexión a `10.50.30.10:1514` y `:1515`; el token enviado vuelve igual.
2. Desde `strongswan` (origen no permitido), la misma conexión no recibe eco.
3. El `access_log` registra la conexión y no contiene el token.
4. `nginx -t` pasa, la versión instalada es la fijada y `apt-mark showhold` incluye los cuatro paquetes y el dueño de `/usr/sbin/nginx`.
5. `logrotate -d` sobre la configuración nueva no da errores.

La doble pasada con `changed=0` y el contrato de tags de la Etapa 0 siguen cubriendo idempotencia y que `start` no descargue. Como arrancar NGINX es un cambio legítimo, `make rehearse` corre `--tags start` dos veces: la primera exige solo ausencia de fallos (`recap-check.sh ... ok`) y la segunda `changed=0`.

**No se valida en local:** reglas y activación reales de UFW, el NSG de Azure, y el protocolo real del agente Wazuh (enrolamiento TLS en 1515, cifrado en 1514). Esto último se verifica en la Etapa 9 de `PIPELINE.md`.

## 6. Criterio de listo

- `make relay-check` pasa (los 5 checks).
- `make preflight` pasa, incluido `relay-check`, con segunda pasada en `changed=0`.
- El contrato de tags sigue verde.
- Los cambios se limitan a `ansible/roles/logrelay`, `ansible/local/`, el `Makefile` y la documentación.

## 7. Fuera de alcance

- Manager de Wazuh y agente del honeyserver.
- Enrolamiento con contraseña (D8) y medición de duplicados y pérdidas (TEST-007/008).
- Cualquier cambio en Terraform.
