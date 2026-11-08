# SOC-Tesis — raíz Terraform "lab" (D9: destruible)
#
# Versiones fijadas por D1 (.knowledge/17_SOFTWARE_BASELINE.md §1):
#   Terraform 1.16.5 · azurerm 5.8.0
#
# DESVIACIÓN DOCUMENTADA (no es una redecisión de D1): el binario Terraform
# disponible en este entorno de preparación es 1.16.3 (verificado con
# `terraform version`), no 1.16.5. Se deja el required_version fijado a
# ">= 1.16.3, < 2.0.0" para que `validate`/`plan` puedan ejecutarse en ESTE
# entorno sin bloquear por versión, pero el pin exacto "1.16.5" sigue siendo
# la decisión de D1 para el `apply` real — responsable: instalar 1.16.5 (o
# actualizar D1 con evidencia si se usa otra versión) antes de desplegar.
terraform {
  required_version = ">= 1.16.3, < 2.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "5.8.0"
    }
  }

  # D9 (18_DECISIONES_IMPLEMENTACION.md §7): backend local, un solo operador,
  # sin CI. State en terraform/lab/terraform.tfstate (ignorado por .gitignore;
  # .terraform.lock.hcl SÍ se versiona, CON-15).
  backend "local" {
    path = "terraform.tfstate"
  }
}
