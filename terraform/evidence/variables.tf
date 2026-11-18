variable "location" {
  description = <<-EOT
    Región de la raíz "evidence". CAMBIADA de "eastus2" a "centralus" el
    2026-10-18 junto con ADR-003 (misma región que `terraform/lab/`): dejar
    la evidencia en otra región que el laboratorio no aporta nada y sí
    complica la revisión de coherencia entre raíces.
  EOT
  type        = string
  default     = "centralus"
}

variable "resource_group_name" {
  description = "RG separado del laboratorio (D9: raíz independiente, prevent_destroy)."
  type        = string
  default     = "rg-soc-tesis-evidence"
}

variable "storage_account_name" {
  description = "Nombre de cuenta de almacenamiento (3-24 caracteres, minúsculas/dígitos, globalmente único en Azure)."
  type        = string
  default     = "socesisevidencia01" # verificado NameAvailable el 2026-10-18 (`evidence/terraform-prep/2026-10-18-adr003-verificacion/03-nombre-storage-y-cuotas-red.txt`)
}

variable "container_name" {
  type    = string
  default = "evidencia-soc-tesis"
}

variable "lab_source_cidrs" {
  description = <<-EOT
    Prefijos de salida del laboratorio permitidos en el firewall de la cuenta.
    Mismo valor que terraform/lab (ADR-005 N3, vigente desde 2026-10-27): la
    IP del ISP es dinámica dentro del /12. El control fuerte es Entra ID +
    RBAC (sin claves); el firewall es una segunda capa.
  EOT
  type        = list(string)
  default     = ["201.96.0.0/12"]
}

variable "retention_days" {
  description = "Retención objetivo de la evidencia cruda (doc 19 §8: 90 días, 'cuando sea viable')."
  type        = number
  default     = 90
}

variable "soft_delete_days" {
  type    = number
  default = 7
}

variable "tags" {
  type = map(string)
  default = {
    project     = "soc-tesis"
    environment = "evidence"
    managed_by  = "terraform"
  }
}
