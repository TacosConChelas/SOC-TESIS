# Variables de la raíz "lab" (destruible, D9). Ninguna tiene un secreto.
# Los valores reales no secretos van en `example.tfvars` -> copiar a
# `terraform.tfvars` (ignorado por git, *.tfvars).

variable "location" {
  description = <<-EOT
    Región Azure. CAMBIADA de "East US 2" (ADR-001 original) a **Central US**
    el 2026-10-18, decisión del responsable con evidencia (doc 21 §11.1–§11.3):
    en East US 2 las SKU `Standard_B2als_v2`/`Standard_B4as_v2` no aparecían
    en absoluto en el catálogo de la suscripción (`NotAvailableForSubscription`
    region-wide); en Central US aparecen SIN ninguna restricción de zona.
    D1 (imagen Ubuntu) se re-verificó para Central US el 2026-10-18
    (`evidence/d1-ubuntu-image/2026-10-18-centralus/`): misma versión
    exacta, `imageState = Active`, V2. NO queda ningún pendiente regional.
  EOT
  type        = string
  default     = "centralus"
}

variable "resource_group_name" {
  description = "Nombre del Resource Group del laboratorio."
  type        = string
  default     = "rg-soc-tesis-lab"
}

# ---------------------------------------------------------------------------
# D6 — Conectividad del laboratorio (parcialmente resuelta, handoff 2026-10-14)
# ---------------------------------------------------------------------------

variable "lab_cidr" {
  description = <<-EOT
    CIDR de la LAN del laboratorio. CONFIRMADO (handoff 2026-10-14, `ip -4 route`
    del equipo del responsable): 192.168.1.0/24. No se solapa con 10.50.0.0/16.
    Necesario para: reglas NSG de administración (D7 §5.1/5.2) y la tabla de
    rutas (D6). NO necesario para generar el plan en sí (tiene default), pero
    SÍ es indispensable antes de poder establecer y validar el túnel IPsec/IKEv2.
  EOT
  type        = string
  default     = "192.168.1.0/24"
}

# ADR-004/ADR-005: el origen del túnel es la Raspberry Pi 5 detrás de CGNAT
# (IP de salida dinámica 201.108.8.x). Política de origen de nsg-vpn: N3
# ACOTADA al prefijo del ISP (LACNIC RDAP: 201.96.0.0/12), decisión del
# operador 2026-10-27 (pendiente enmienda formal de ADR-005). Es un filtro
# grueso (~1M IPs): la protección real es IKEv2 + PSK fuerte, no este CIDR.
# terraform/evidence tiene su PROPIA variable lab_public_ip (Blob) y NO usa
# este /12.
variable "lab_source_cidrs" {
  description = <<-EOT
    CIDRs de origen permitidos hacia `nsg-vpn` (UDP 500/4500, ESP) y destino
    de las salidas de rekey/ESP. Por defecto el prefijo del ISP del lab
    (201.96.0.0/12). Para volver a N1 pasar ["<IP>/32"].
  EOT
  type        = list(string)
  default     = ["201.96.0.0/12"]

  validation {
    condition     = length(var.lab_source_cidrs) > 0 && alltrue([for c in var.lab_source_cidrs : can(cidrnetmask(c)) && c != "0.0.0.0/0"])
    error_message = "lab_source_cidrs: CIDRs IPv4 válidos, no vacío y sin 0.0.0.0/0."
  }
}

variable "maintenance_egress" {
  description = "D7 §5.2: habilita egress 80/443 a Internet para apt/Docker Hub/GHCR/packages.wazuh.com. false durante los experimentos."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# D1 — Software baseline (imagen Ubuntu, 17_SOFTWARE_BASELINE.md §1)
# ---------------------------------------------------------------------------

variable "ubuntu_image_version" {
  description = <<-EOT
    Versión EXACTA de la imagen Ubuntu 22.04 (D1, CLOSED). Verificada
    disponible y activa en East US 2 el 2026-10-13 (`evidence/d1-ubuntu-image/
    2026-10-13/`) y RE-VERIFICADA en Central US el 2026-10-18
    (`evidence/d1-ubuntu-image/2026-10-18-centralus/`): `imageState = Active`,
    `hyperVGeneration: V2` — sigue siendo la misma versión. NO usar "latest":
    si el apply real ocurre mucho después, re-verificar con `az vm image show`
    antes de aplicar (nota de caducidad de la evidencia).
  EOT
  type        = string
  default     = "22.04.202608060"
}

# ---------------------------------------------------------------------------
# SKU de las 4 VM (architecture.md §2, ADR-002).
#
# HISTORIAL DEL BLOQUEO (handoff 2026-10-14/16/18, tres sesiones; detalle
# completo en doc 21 §10–§11): `Standard_B1s`, `Standard_B2als_v2` y
# `Standard_B4as_v2` existen y tienen precio público, pero en `eastus2` NINGUNA
# aparecía en el catálogo de esta suscripción (`NotAvailableForSubscription`,
# no es falta de registro de providers ni de cuota — se verificaron y
# descartaron ambas hipótesis). `Standard_B1s` específicamente: ausente del
# catálogo en las 6 regiones probadas, sin excepción — es la familia "BS"
# (Bv1), de generación anterior, que Microsoft restringe a suscripciones
# nuevas camino a su retiro (15-nov-2028, confirmado con Microsoft Learn,
# doc 21 §11.5).
#
# DECISIÓN ADOPTADA (2026-10-18, responsable, con evidencia — ADR-001
# actualizado): `location` → `centralus` (sin restricción de zona para
# `B2als_v2`/`B4as_v2`, doc 21 §11.1) + `vm_size_strongswan`/
# `vm_size_logrelay` → `Standard_B2ats_v2` (misma familia "Basv2" AMD que
# Wazuh/Honey-Server, sin restricción de catálogo verificada en `centralus`/
# `southcentralus`, mismo 1 GiB RAM que `B1s`, +$0.0002/h). Elimina el
# problema de ELEGIBILIDAD (`NotAvailableForSubscription`) para las 4 VM.
#
# CUOTA RESUELTA (re-chequeo 2026-10-18, doc 21 §11.9): "Standard Basv2
# Family vCPUs" en Central US subió de limit=0 a limit=10 — exactamente lo
# necesario (2+4+2+2=10, SIN margen). Ya no hay ningún bloqueo de SKU
# conocido para estas 4 VM en Central US.
# ---------------------------------------------------------------------------

variable "vm_size_wazuh" {
  description = "SKU VM Wazuh (D5/ADR-002: 4 vCPU, 16 GiB)."
  type        = string
  default     = "Standard_B4as_v2"
}

variable "vm_size_honeyserver" {
  description = "SKU VM Honey-Server (D-H07: 2 vCPU, 4 GiB)."
  type        = string
  default     = "Standard_B2als_v2"
}

variable "vm_size_strongswan" {
  description = "SKU VM strongSwan. CAMBIADA de Standard_B1s (ausente del catálogo en toda región probada) a Standard_B2ats_v2 el 2026-10-18 (doc 21 §11.6/§11.7): 2 vCPU/1 GiB, misma familia Basv2, sin restricción de elegibilidad."
  type        = string
  default     = "Standard_B2ats_v2"
}

variable "vm_size_logrelay" {
  description = "SKU VM Log Relay. Mismo cambio que vm_size_strongswan (2026-10-18)."
  type        = string
  default     = "Standard_B2ats_v2"
}

variable "os_disk_size_gb" {
  description = "Disco E4 = Standard SSD 32 GB (ADR-001), para strongSwan y Log Relay."
  type        = number
  default     = 32
}

variable "os_disk_size_gb_large" {
  description = <<-EOT
    Disco E6 = Standard SSD 64 GB, para Wazuh y Honey-Server. CAMBIADO de E4
    (32 GB, ADR-002 original: "Disco Wazuh: E4 se mantiene") a E6 el
    2026-10-18 — decisión explícita del responsable por mayor espacio
    (Wazuh: índices/evidencia antes de la ISM de 30 días; Honey-Server:
    binarios/capturas de los honeypots), con el sobrecosto ya incluido en el
    presupuesto recalculado (doc 21 §11.7: +$4.80/mes por las 2 VM frente a
    E4, total $33.849/mes, sigue ≤ $50 D11/ADR-001).
  EOT
  type        = number
  default     = 64
}

variable "admin_username" {
  description = "Usuario administrador Linux de las 4 VM."
  type        = string
  default     = "soctesis"
}

variable "admin_ssh_public_key_path" {
  description = <<-EOT
    Ruta LOCAL (fuera del repo) a la clave pública SSH ed25519 del operador
    (D8: "solo la pública va a Terraform"). NO tiene default: no se inventa
    una ruta ni se genera un par de claves aquí.
  EOT
  type        = string
}

variable "budget_amount_usd" {
  description = "Presupuesto mensual del Resource Group (D11/ADR-001: ≤ 50 USD/mes)."
  type        = number
  default     = 50
}

variable "auto_shutdown_time" {
  description = "Hora local de apagado automático diario de las 4 VM (HHmm, D11 §8: obligatorio para no exceder el presupuesto)."
  type        = string
  default     = "2200"
}

variable "auto_shutdown_timezone" {
  description = "Zona horaria del auto-shutdown."
  type        = string
  default     = "Central Standard Time (Mexico)"
}

variable "tags" {
  description = "Tags comunes de todos los recursos."
  type        = map(string)
  default = {
    project     = "soc-tesis"
    environment = "lab"
    managed_by  = "terraform"
  }
}
