# Plantilla VERSIONABLE (sin secretos). Copiar a `terraform.tfvars`.

# Prefijos de salida del laboratorio (ADR-005 N3). Mismo valor que terraform/lab.
lab_source_cidrs = ["201.96.0.0/12"]

# Verificar disponibilidad global del nombre antes de `apply`:
#   az storage account check-name-availability --name <nombre>
storage_account_name = "socesisevidencia01"
