# D8 (18_DECISIONES_IMPLEMENTACION.md §6): credenciales Azure = sesión de
# `az login` (caché de Azure CLI). Sin subscription_id/client_secret en este
# archivo: el provider toma el contexto activo de `az account show`.
provider "azurerm" {
  features {}
}
