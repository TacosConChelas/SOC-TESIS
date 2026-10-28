# Ansible — configuración reproducible de las VMs de Azure

Alcance: solo las 4 VMs de `terraform/lab`. La Pi (nftables/sysctl/rfkill/
strongSwan iniciador) NO va aquí: se gestiona por etapas con gates y rollback.

## Flujo
1. `terraform apply` (con `maintenance_egress=true` solo durante la instalación).
2. Bootstrap del túnel (C4): PSK e IKE en la VM strongSwan con `az vm run-command`.
3. Con el túnel arriba, desde el host del lab: `ansible-playbook site.yml`.
4. `terraform apply` con `maintenance_egress=false`; luego arrancar servicios.
5. Ciclo de captura: `az vm start` → capturar → `az vm deallocate`.

## Secretos
- El PSK NO entra en este repo, ni en `group_vars`, ni en el inventario.
  Si hace falta un secreto: archivo fuera del repo + `no_log: true`.
- `.vault_pass` y `*.vault` están en `.gitignore`.

## Pruebas sin costo
Probar los roles primero en una VM local Ubuntu 22.04 antes de gastar horas de Azure.
