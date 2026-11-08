# Red (architecture.md §4): VNet 10.50.0.0/16, 4 subredes /24.

resource "azurerm_resource_group" "lab" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

resource "azurerm_virtual_network" "lab" {
  name                = "vnet-soc-tesis"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  address_space       = ["10.50.0.0/16"]
  tags                = var.tags
}

resource "azurerm_subnet" "honeypots" {
  name                 = "snet-honeypots"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.50.10.0/24"]
}

resource "azurerm_subnet" "vpn" {
  name                 = "snet-vpn"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.50.20.0/24"]
}

resource "azurerm_subnet" "logrelay" {
  name                 = "snet-logrelay"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.50.30.0/24"]
}

resource "azurerm_subnet" "wazuh" {
  name                 = "snet-wazuh"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.50.40.0/24"]
}

# D6: tabla de rutas hacia la LAN del laboratorio vía el appliance strongSwan
# (10.50.20.10), asociada a honeypots/logrelay/wazuh. Sin SNAT.
resource "azurerm_route_table" "rt_lab" {
  name                = "rt-lab"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags

  route {
    name                   = "to-lab-via-strongswan"
    address_prefix         = var.lab_cidr
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "10.50.20.10"
  }
}

resource "azurerm_subnet_route_table_association" "honeypots" {
  subnet_id      = azurerm_subnet.honeypots.id
  route_table_id = azurerm_route_table.rt_lab.id
}

resource "azurerm_subnet_route_table_association" "logrelay" {
  subnet_id      = azurerm_subnet.logrelay.id
  route_table_id = azurerm_route_table.rt_lab.id
}

resource "azurerm_subnet_route_table_association" "wazuh" {
  subnet_id      = azurerm_subnet.wazuh.id
  route_table_id = azurerm_route_table.rt_lab.id
}
