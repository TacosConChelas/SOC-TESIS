# Plantilla VERSIONABLE (sin secretos). Copiar a `terraform.tfvars`.

# D6 — PENDIENTE: ver la nota equivalente en terraform/lab/example.tfvars.
# Placeholder de documentación (RFC 5737), NO una IP real.
lab_public_ip = "203.0.113.1" # <-- PLACEHOLDER, NO REAL (D6 pendiente)

# Verificar disponibilidad global del nombre antes de `apply`:
#   az storage account check-name-availability --name <nombre>
storage_account_name = "socesisevidencia01"
