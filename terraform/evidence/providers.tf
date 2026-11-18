provider "azurerm" {
  features {}
  # shared_access_key_enabled = false: el provider usa Entra ID, no la clave,
  # para leer el plano de datos de la cuenta (azurerm #25218).
  storage_use_azuread = true
}
