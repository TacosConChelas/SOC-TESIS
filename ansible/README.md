# Ansible — configuración reproducible de las VMs de Azure

Alcance: solo las 4 VMs de `terraform/lab`. La Pi (nftables/sysctl/rfkill/
strongSwan iniciador) NO va aquí: se gestiona por etapas con gates y rollback.

## Flujo
Fuente de verdad: [`PIPELINE.md`](PIPELINE.md) (ADR-006 con la enmienda E1). Resumen:
1. `terraform apply` con `maintenance_egress=false`; honeyserver arranca con sshd en el 22222.
2. Abrir egreso: `terraform apply -var maintenance_egress=true`.
3. Bootstrap por `az vm run-command`: huellas de host y VM strongSwan (paquete, swanctl, PSK).
4. Túnel (C4) arriba.
5. Desde el host del lab: `ansible-playbook site.yml --tags install,config` (honeypot apagado).
6. Cerrar egreso: `terraform apply -var maintenance_egress=false`.
7. `ansible-playbook site.yml --tags start`.
8. Ciclo de captura: `az vm start` → capturar → `az vm deallocate`.

## Secretos
- El PSK NO entra en este repo, ni en `group_vars`, ni en el inventario.
  Si hace falta un secreto: archivo fuera del repo + `no_log: true`.
- `.vault_pass` y `*.vault` están en `.gitignore`.

## Pruebas sin costo
Probar los roles primero en una VM local Ubuntu 22.04 antes de gastar horas de Azure.
