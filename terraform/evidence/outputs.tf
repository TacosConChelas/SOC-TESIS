output "storage_account_name" {
  value = azurerm_storage_account.evidence.name
}

output "container_name" {
  value = azurerm_storage_container.evidence.name
}

output "resource_group_name" {
  value = azurerm_resource_group.evidence.name
}
