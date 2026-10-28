# 4 VM (architecture.md §2). Imagen Ubuntu 22.04 fijada por D1 (sin "latest").
# Sin custom_data: los comandos de instalación (Wazuh, strongSwan, Docker,
# honeypots) quedan fuera del alcance de este documento/arquitectura
# (architecture.md §19) y se ejecutan manualmente después del apply, por SSH
# a través del túnel — así lo fija el orden de implementación (architecture.md
# §20: Terraform -> Red -> NSG -> VMs -> strongSwan -> Wazuh -> Log Relay ->
# Docker/Honeypots, como pasos posteriores y separados).

locals {
  ubuntu_image = {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = var.ubuntu_image_version
  }
}

# ---------------------------------------------------------------------------
# IP públicas estáticas (solo Honey-Server y strongSwan, D-H17/D11: 2 IP).
# ---------------------------------------------------------------------------
resource "azurerm_public_ip" "honeyserver" {
  name                = "pip-honeyserver"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_public_ip" "strongswan" {
  name                = "pip-strongswan"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

# ---------------------------------------------------------------------------
# NIC — IP privada estática por VM (D7: 10.50.x.10 en cada subred).
# ---------------------------------------------------------------------------
resource "azurerm_network_interface" "honeyserver" {
  name                = "nic-honeyserver"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.honeypots.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.50.10.10"
    public_ip_address_id          = azurerm_public_ip.honeyserver.id
  }
}

resource "azurerm_network_interface" "strongswan" {
  name                = "nic-strongswan"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags

  # D6: la NIC debe reenviar paquetes que no son para sí misma (IPsec).
  ip_forwarding_enabled = true

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vpn.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.50.20.10"
    public_ip_address_id          = azurerm_public_ip.strongswan.id
  }
}

resource "azurerm_network_interface" "logrelay" {
  name                = "nic-logrelay"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.logrelay.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.50.30.10"
  }
}

resource "azurerm_network_interface" "wazuh" {
  name                = "nic-wazuh"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.wazuh.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.50.40.10"
  }
}

# ---------------------------------------------------------------------------
# VM — Honey-Server (D-H07, pública)
# ---------------------------------------------------------------------------
resource "azurerm_linux_virtual_machine" "honeyserver" {
  name                = "vm-honeyserver"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  size                = var.vm_size_honeyserver
  admin_username      = var.admin_username
  tags                = var.tags

  network_interface_ids           = [azurerm_network_interface.honeyserver.id]
  disable_password_authentication = true

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(var.admin_ssh_public_key_path)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = var.os_disk_size_gb_large # E6 (2026-10-18, más espacio)
  }

  source_image_reference {
    publisher = local.ubuntu_image.publisher
    offer     = local.ubuntu_image.offer
    sku       = local.ubuntu_image.sku
    version   = local.ubuntu_image.version
  }
}

# ---------------------------------------------------------------------------
# VM — strongSwan (D6, pública)
# ---------------------------------------------------------------------------
resource "azurerm_linux_virtual_machine" "strongswan" {
  name                = "vm-strongswan"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  size                = var.vm_size_strongswan
  admin_username      = var.admin_username
  tags                = var.tags

  network_interface_ids           = [azurerm_network_interface.strongswan.id]
  disable_password_authentication = true

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(var.admin_ssh_public_key_path)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = var.os_disk_size_gb
  }

  source_image_reference {
    publisher = local.ubuntu_image.publisher
    offer     = local.ubuntu_image.offer
    sku       = local.ubuntu_image.sku
    version   = local.ubuntu_image.version
  }
}

# ---------------------------------------------------------------------------
# VM — Log Relay (D4, privada)
# ---------------------------------------------------------------------------
resource "azurerm_linux_virtual_machine" "logrelay" {
  name                = "vm-logrelay"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  size                = var.vm_size_logrelay
  admin_username      = var.admin_username
  tags                = var.tags

  network_interface_ids           = [azurerm_network_interface.logrelay.id]
  disable_password_authentication = true

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(var.admin_ssh_public_key_path)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = var.os_disk_size_gb
  }

  source_image_reference {
    publisher = local.ubuntu_image.publisher
    offer     = local.ubuntu_image.offer
    sku       = local.ubuntu_image.sku
    version   = local.ubuntu_image.version
  }
}

# ---------------------------------------------------------------------------
# VM — Wazuh (D5, privada)
# ---------------------------------------------------------------------------
resource "azurerm_linux_virtual_machine" "wazuh" {
  name                = "vm-wazuh"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  size                = var.vm_size_wazuh
  admin_username      = var.admin_username
  tags                = var.tags

  network_interface_ids           = [azurerm_network_interface.wazuh.id]
  disable_password_authentication = true

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(var.admin_ssh_public_key_path)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = var.os_disk_size_gb_large # E6 (2026-10-18, más espacio)
  }

  source_image_reference {
    publisher = local.ubuntu_image.publisher
    offer     = local.ubuntu_image.offer
    sku       = local.ubuntu_image.sku
    version   = local.ubuntu_image.version
  }
}
