# Plantilla VERSIONABLE (sin secretos, D8). Copiar a `terraform.tfvars`
# (ignorado por git) y completar los valores reales antes de `apply`.

# D6 — CONFIRMADO (handoff 2026-10-14, `ip -4 route` del laboratorio):
lab_cidr = "192.168.1.0/24"

# N3 acotada (2026-10-27): origen IKE permitido = prefijo del ISP. Opcional;
# el default ya es este valor. Para N1 usar ["IP_REAL/32"].
lab_source_cidrs = ["201.96.0.0/12"]

# Ruta LOCAL a la clave pública SSH del operador (D8). No existe un valor por
# defecto seguro: cada operador genera su propio par de claves.
# OJO: `file()` NO expande `~` — la ruta tiene que ser ABSOLUTA (falla en
# `terraform plan` con "no such file" si se deja el tilde).
admin_ssh_public_key_path = "/home/OPERADOR/soc-tesis-secrets/ssh/id_ed25519.pub"

maintenance_egress = false
