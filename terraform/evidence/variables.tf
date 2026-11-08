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

# ADR-005 (enmienda 2026-10-27): terraform/lab ya NO usa esta IP (usa lab_source_cidrs, /12).
# Esta variable solo filtra el Blob (/32). Si la IP de salida cambia,
# actualizarla aquí. Solo comentario.
variable "lab_public_ip" {
  description = <<-EOT
    Mismo significado que terraform/lab: IP pública WAN del laboratorio, para
    restringir el firewall de la cuenta de almacenamiento (doc 19 §6).
    PENDIENTE (D6). Sin default: debe proveerse explícitamente.
  EOT
  type        = string
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
