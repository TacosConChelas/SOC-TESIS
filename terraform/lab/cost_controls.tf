# D11 (18_DECISIONES_IMPLEMENTACION.md §8): obligatorios para no exceder
# 50 USD/mes — auto-shutdown diario en las 4 VM + presupuesto con alertas.

resource "azurerm_dev_test_global_vm_shutdown_schedule" "honeyserver" {
  virtual_machine_id    = azurerm_linux_virtual_machine.honeyserver.id
  location              = azurerm_resource_group.lab.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone

  notification_settings {
    enabled = false
  }
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "strongswan" {
  virtual_machine_id    = azurerm_linux_virtual_machine.strongswan.id
  location              = azurerm_resource_group.lab.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone

  notification_settings {
    enabled = false
  }
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "logrelay" {
  virtual_machine_id    = azurerm_linux_virtual_machine.logrelay.id
  location              = azurerm_resource_group.lab.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone

  notification_settings {
    enabled = false
  }
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "wazuh" {
  virtual_machine_id    = azurerm_linux_virtual_machine.wazuh.id
  location              = azurerm_resource_group.lab.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone

  notification_settings {
    enabled = false
  }
}

# Presupuesto del Resource Group con alertas al 50 % y al 80 % (D11 §8).
resource "azurerm_consumption_budget_resource_group" "lab" {
  name              = "budget-soc-tesis-lab"
  resource_group_id = azurerm_resource_group.lab.id

  amount     = var.budget_amount_usd
  time_grain = "Monthly"

  time_period {
    start_date = formatdate("YYYY-MM-01'T'00:00:00Z", timestamp())
  }

  # Sin dirección de correo inventada (no hay una real que registrar aquí):
  # se notifica al rol RBAC "Owner" de la suscripción, no a una persona.
  notification {
    enabled        = true
    threshold      = 50
    operator       = "GreaterThan"
    threshold_type = "Actual"
    contact_roles  = ["Owner"]
  }

  notification {
    enabled        = true
    threshold      = 80
    operator       = "GreaterThan"
    threshold_type = "Actual"
    contact_roles  = ["Owner"]
  }

  lifecycle {
    ignore_changes = [time_period]
  }
}
