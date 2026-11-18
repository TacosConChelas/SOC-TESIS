# D9/D10/doc 19 §6: Storage Account separado del laboratorio, con
# `prevent_destroy` — `terraform destroy` de la raíz "lab" NUNCA debe poder
# tocar esto (raíces distintas, states distintos, ya es una protección
# estructural; `prevent_destroy` es la segunda capa, por si alguien corre
# `destroy` dentro de ESTA misma raíz por error).

resource "azurerm_resource_group" "evidence" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_storage_account" "evidence" {
  name                = var.storage_account_name
  resource_group_name = azurerm_resource_group.evidence.name
  location            = azurerm_resource_group.evidence.location

  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  access_tier              = "Cool"

  # doc 19 §6: "acceso con az storage blob upload-batch --auth-mode login
  # (sin claves de cuenta)" -> se deshabilita la autenticación por clave
  # compartida; solo Azure AD/RBAC.
  shared_access_key_enabled = false

  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false

  blob_properties {
    delete_retention_policy {
      days = var.soft_delete_days
    }
    container_delete_retention_policy {
      days = var.soft_delete_days
    }
    versioning_enabled = true
  }

  # doc 19 §6 + ADR-005 N3: solo desde los prefijos de salida del laboratorio.
  network_rules {
    default_action = "Deny"
    ip_rules       = var.lab_source_cidrs
    bypass         = ["AzureServices"]
  }

  tags = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_storage_container" "evidence" {
  name                  = var.container_name
  storage_account_id    = azurerm_storage_account.evidence.id
  container_access_type = "private"

  lifecycle {
    prevent_destroy = true
  }
}

# doc 19 §6: "política de inmutabilidad temporal SIN BLOQUEAR de 90 días a
# nivel de contenedor" -> time-based retention, modo Unlocked (reversible),
# NO Locked (que sería irreversible y excede lo decidido).
resource "azurerm_storage_container_immutability_policy" "evidence" {
  storage_container_resource_manager_id = azurerm_storage_container.evidence.id
  immutability_period_in_days           = var.retention_days
  # Sin `locked`: política exigible pero MODIFICABLE (Unlocked), como decide
  # doc 19 §6. Bloquearla (lock = true) sería una decisión nueva, no tomada
  # aquí.

  lifecycle {
    prevent_destroy = true
  }
}

data "azurerm_client_config" "current" {}

# doc 19 §6: subida con --auth-mode login. Sin clave compartida, el operador
# necesita un rol del plano de datos; Owner/Contributor no bastan.
resource "azurerm_role_assignment" "operator_blob" {
  scope                = azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}
