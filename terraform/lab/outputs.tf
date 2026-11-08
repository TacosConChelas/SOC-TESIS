# Ningún output expone secretos (D8): solo nombres, IP e IDs.

output "resource_group_name" {
  value = azurerm_resource_group.lab.name
}

output "honeyserver_public_ip" {
  value = azurerm_public_ip.honeyserver.ip_address
}

output "strongswan_public_ip" {
  value = azurerm_public_ip.strongswan.ip_address
}

output "private_ips" {
  value = {
    honeyserver = azurerm_network_interface.honeyserver.private_ip_address
    strongswan  = azurerm_network_interface.strongswan.private_ip_address
    logrelay    = azurerm_network_interface.logrelay.private_ip_address
    wazuh       = azurerm_network_interface.wazuh.private_ip_address
  }
}

output "vm_ids" {
  value = {
    honeyserver = azurerm_linux_virtual_machine.honeyserver.id
    strongswan  = azurerm_linux_virtual_machine.strongswan.id
    logrelay    = azurerm_linux_virtual_machine.logrelay.id
    wazuh       = azurerm_linux_virtual_machine.wazuh.id
  }
}
