# SOC-Tesis — raíz Terraform "evidence" (D9: state propio, NO destruible
# vía `terraform destroy` del laboratorio — raíz separada a propósito).
#
# Misma desviación documentada que terraform/lab/versions.tf: binario local
# 1.16.3, decisión D1 = 1.16.5.
terraform {
  required_version = ">= 1.16.3, < 2.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "5.8.0"
    }
  }

  backend "local" {
    path = "terraform.tfstate"
  }
}
