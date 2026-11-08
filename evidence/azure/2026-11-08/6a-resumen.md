# Etapa 6a — Roles base en strongswan y logrelay (2026-11-08)

- **Fecha y hora:** 2026-11-08 14:45 CST (20:45 UTC)
- **Rama:** `practica/ansible-local`
- **Hosts limitados:** `strongswan`, `logrelay`

---

## 1. Precondiciones (Paso 0)
- `ip route get 10.50.20.10`:
  `10.50.20.10 via 192.168.1.10 dev br0 src 192.168.1.73 uid 1000 cache mtu 1360` (OK)
- `timeout 120 ansible all -m ping`: 4 pong (OK)

---

## 2. Pasada 1 — Instalación y configuración (`--tags install,config`)
- **Log:** `evidence/azure/2026-11-08/6a-pass1.log`
- **Código de salida:** `exit=0`

### PLAY RECAP:
```text
logrelay                   : ok=30   changed=19   unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
strongswan                 : ok=20   changed=9    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
```

---

## 3. Ping post-roles (Paso 2)
- `timeout 120 ansible all -m ping`:
  - `strongswan`: pong (`SUCCESS`)
  - `logrelay`: pong (`SUCCESS`)
  - `honeyserver`: pong (`SUCCESS`)
  - `wazuh`: pong (`SUCCESS`)
- UFW en `logrelay` no interrumpió el acceso administrativo ni la conectividad.

---

## 4. Verificación de reenvío IP y túnel IPsec (Paso 3)
- `sysctl -n net.ipv4.ip_forward` en `strongswan`: `1` (OK)
- Túnel IPsec verificado desde `soc71` con `sudo swanctl --list-sas`: activo y operativo (OK).

---

## 5. Pasada 2 — Idempotencia (`--tags install,config`)
- **Log:** `evidence/azure/2026-11-08/6a-pass2.log`
- **Código de salida:** `exit=0`

### PLAY RECAP:
```text
logrelay                   : ok=28   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
strongswan                 : ok=19   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
```
Idempotencia confirmada: `changed=0`, `failed=0`, `unreachable=0` en ambos hosts.

---

## 6. Sincronización NTP (Paso 5)
- Comando: `ansible all -b -m command -a 'timedatectl show -p NTPSynchronized --value'`
  - `strongswan`: `yes`
  - `logrelay`: `yes`
  - `honeyserver`: `yes`
  - `wazuh`: `yes`

Sincronización confirmada en las 4 máquinas virtuales con el egreso aún abierto.
