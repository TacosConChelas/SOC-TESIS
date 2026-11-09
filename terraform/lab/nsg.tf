# NSG (D7, 18_DECISIONES_IMPLEMENTACION.md §5). Cada NSG termina con
# Deny-All-In/Deny-All-Out explícito (prioridad 4096); azurerm ya tiene un deny
# implícito, se deja explícito por trazabilidad con D7.
# Reglas en `local.rules_by_nsg` (clave = etiqueta original, para moved.tf 1:1)
# y un único `azurerm_network_security_rule.rule` con for_each. Fijos en todas:
# source_port_range = "*" y resource_group_name = lab.

resource "azurerm_network_security_group" "honeypot" {
  name                = "nsg-honeypot"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags
}

resource "azurerm_network_security_group" "vpn" {
  name                = "nsg-vpn"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags
}

resource "azurerm_network_security_group" "logrelay" {
  name                = "nsg-logrelay"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags
}

resource "azurerm_network_security_group" "wazuh" {
  name                = "nsg-wazuh"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags
}

locals {
  # Destinos: IPs privadas fijas de D7 §5.1 (no "*"). Azure NSG admite UN
  # protocolo por regla: "UDP 500/4500; ESP" (egress vpn) y "UDP/TCP 53" no caben
  # en una; se mantienen las prioridades de D7 y la regla extra va al hueco libre.
  rules_by_nsg = {
    honeypot = {
      # D7 §5.1: TCP (architecture.md §6.1)
      honeypot_in_public_surface = { name = "Allow-Internet-Honeypot-Surface", priority = 100, direction = "Inbound", access = "Allow", protocol = "Tcp", destination_port_ranges = ["22", "23", "25", "80", "21", "135", "443", "445", "1433", "1883", "3306", "5060", "5061"], source_address_prefix = "Internet", destination_address_prefix = "10.50.10.10" }
      honeypot_in_tftp_udp       = { name = "Allow-Internet-Dionaea-TFTP-UDP", priority = 110, direction = "Inbound", access = "Allow", protocol = "Udp", destination_port_range = "69", source_address_prefix = "Internet", destination_address_prefix = "10.50.10.10" }
      honeypot_in_sip_udp        = { name = "Allow-Internet-Dionaea-SIP-UDP", priority = 120, direction = "Inbound", access = "Allow", protocol = "Udp", destination_port_ranges = ["5060", "5061"], source_address_prefix = "Internet", destination_address_prefix = "10.50.10.10" }
      honeypot_in_admin_ssh      = { name = "Allow-Lab-Admin-SSH-22222", priority = 300, direction = "Inbound", access = "Allow", protocol = "Tcp", destination_port_range = "22222", source_address_prefix = var.lab_cidr, destination_address_prefix = "10.50.10.10" }
      honeypot_out_to_logrelay   = { name = "Allow-Out-Agent-To-LogRelay", priority = 200, direction = "Outbound", access = "Allow", protocol = "Tcp", destination_port_ranges = ["1514", "1515"], source_address_prefix = "*", destination_address_prefix = "10.50.30.10" }
      # D7 §5.2 "todas 100". Azure ya permite DNS a 168.63.129.16 sin regla. NO usar el tag AzurePlatformDNS: solo admite Deny (Allow da 400).
      honeypot_out_dns        = { name = "Allow-Out-DNS", priority = 100, direction = "Outbound", access = "Allow", protocol = "*", destination_port_range = "53", source_address_prefix = "*", destination_address_prefix = "168.63.129.16" }
      honeypot_out_azure_mgmt = { name = "Allow-Out-AzureCloud-443", priority = 110, direction = "Outbound", access = "Allow", protocol = "Tcp", destination_port_range = "443", source_address_prefix = "*", destination_address_prefix = "AzureCloud" }
      honeypot_deny_all_in    = { name = "Deny-All-In", priority = 4096, direction = "Inbound", access = "Deny", protocol = "*", destination_port_range = "*", source_address_prefix = "*", destination_address_prefix = "*" }
      honeypot_deny_all_out   = { name = "Deny-All-Out", priority = 4096, direction = "Outbound", access = "Deny", protocol = "*", destination_port_range = "*", source_address_prefix = "*", destination_address_prefix = "*" }
    }

    # ADR-004/005: iniciador = Raspberry Pi 5; N3 acotada (var.lab_source_cidrs, IP dinámica por CGNAT).
    # Las reglas ESP y 200/210 se mantienen hasta observar el túnel real (ADR-005 §5).
    vpn = {
      vpn_in_ike = { name = "Allow-Lab-IKE-NATT", priority = 100, direction = "Inbound", access = "Allow", protocol = "Udp", destination_port_ranges = ["500", "4500"], source_address_prefixes = var.lab_source_cidrs, destination_address_prefix = "10.50.20.10" }
      # CON-18: ESP (protocolo 50) para IPsec sin NAT intermedio.
      vpn_in_esp = { name = "Allow-Lab-ESP", priority = 110, direction = "Inbound", access = "Allow", protocol = "Esp", destination_port_range = "*", source_address_prefixes = var.lab_source_cidrs, destination_address_prefix = "10.50.20.10" }
      # SSH de administración solo desde el lab (no desde Internet). El bootstrap PSK/IKE va por `az vm run-command`.
      vpn_in_admin_ssh = { name = "Allow-Lab-Admin-SSH", priority = 200, direction = "Inbound", access = "Allow", protocol = "Tcp", destination_port_range = "22", source_address_prefix = var.lab_cidr, destination_address_prefix = "10.50.20.10" }
      # D7 §5.2 "todas 100" (faltaba en nsg-vpn).
      vpn_out_dns = { name = "Allow-Out-DNS", priority = 100, direction = "Outbound", access = "Allow", protocol = "*", destination_port_range = "53", source_address_prefix = "*", destination_address_prefix = "168.63.129.16" }
      # D7 §5.2 "todas 110": agente, extensiones y Run Command (recuperación strongSwan, architecture.md §15).
      vpn_out_azure_mgmt = { name = "Allow-Out-AzureCloud-443", priority = 110, direction = "Outbound", access = "Allow", protocol = "Tcp", destination_port_range = "443", source_address_prefix = "*", destination_address_prefix = "AzureCloud" }
      vpn_out_rekey      = { name = "Allow-Out-Rekey-To-Lab", priority = 200, direction = "Outbound", access = "Allow", protocol = "Udp", destination_port_ranges = ["500", "4500"], source_address_prefix = "*", destination_address_prefixes = var.lab_source_cidrs }
      vpn_out_esp        = { name = "Allow-Out-ESP-To-Lab", priority = 210, direction = "Outbound", access = "Allow", protocol = "Esp", destination_port_range = "*", source_address_prefix = "*", destination_address_prefixes = var.lab_source_cidrs }
      # D6 / D7 §5.2 (prioridad 210 en D7): ESP ya ocupa 210, así que el reenvío sin SNAT va en 220 (primer hueco libre).
      vpn_out_forward_to_vnet = { name = "Allow-Out-Forward-To-VNet", priority = 220, direction = "Outbound", access = "Allow", protocol = "*", destination_port_range = "*", source_address_prefix = var.lab_cidr, destination_address_prefix = "10.50.0.0/16" }
      vpn_deny_all_in         = { name = "Deny-All-In", priority = 4096, direction = "Inbound", access = "Deny", protocol = "*", destination_port_range = "*", source_address_prefix = "*", destination_address_prefix = "*" }
      vpn_deny_all_out        = { name = "Deny-All-Out", priority = 4096, direction = "Outbound", access = "Deny", protocol = "*", destination_port_range = "*", source_address_prefix = "*", destination_address_prefix = "*" }
    }

    logrelay = {
      logrelay_in_from_honeyserver = { name = "Allow-HoneyServer-Events", priority = 100, direction = "Inbound", access = "Allow", protocol = "Tcp", destination_port_ranges = ["1514", "1515"], source_address_prefix = "10.50.10.10", destination_address_prefix = "10.50.30.10" }
      logrelay_in_admin_ssh        = { name = "Allow-Lab-Admin-SSH", priority = 200, direction = "Inbound", access = "Allow", protocol = "Tcp", destination_port_range = "22", source_address_prefix = var.lab_cidr, destination_address_prefix = "10.50.30.10" }
      logrelay_out_to_wazuh        = { name = "Allow-Out-To-Wazuh", priority = 200, direction = "Outbound", access = "Allow", protocol = "Tcp", destination_port_ranges = ["1514", "1515"], source_address_prefix = "*", destination_address_prefix = "10.50.40.10" }
      logrelay_out_dns             = { name = "Allow-Out-DNS", priority = 100, direction = "Outbound", access = "Allow", protocol = "*", destination_port_range = "53", source_address_prefix = "*", destination_address_prefix = "168.63.129.16" }
      logrelay_out_azure_mgmt      = { name = "Allow-Out-AzureCloud-443", priority = 110, direction = "Outbound", access = "Allow", protocol = "Tcp", destination_port_range = "443", source_address_prefix = "*", destination_address_prefix = "AzureCloud" }
      logrelay_deny_all_in         = { name = "Deny-All-In", priority = 4096, direction = "Inbound", access = "Deny", protocol = "*", destination_port_range = "*", source_address_prefix = "*", destination_address_prefix = "*" }
      logrelay_deny_all_out        = { name = "Deny-All-Out", priority = 4096, direction = "Outbound", access = "Deny", protocol = "*", destination_port_range = "*", source_address_prefix = "*", destination_address_prefix = "*" }
    }

    wazuh = {
      wazuh_in_from_logrelay = { name = "Allow-LogRelay-Events", priority = 100, direction = "Inbound", access = "Allow", protocol = "Tcp", destination_port_ranges = ["1514", "1515"], source_address_prefix = "10.50.30.10", destination_address_prefix = "10.50.40.10" }
      # CON-08: agentes Windows 11 / Ubuntu del laboratorio directo a Wazuh.
      wazuh_in_from_lab_agents = { name = "Allow-Lab-Agents-1514-1515", priority = 110, direction = "Inbound", access = "Allow", protocol = "Tcp", destination_port_ranges = ["1514", "1515"], source_address_prefix = var.lab_cidr, destination_address_prefix = "10.50.40.10" }
      wazuh_in_dashboard       = { name = "Allow-Lab-Dashboard-443", priority = 200, direction = "Inbound", access = "Allow", protocol = "Tcp", destination_port_range = "443", source_address_prefix = var.lab_cidr, destination_address_prefix = "10.50.40.10" }
      wazuh_in_admin_ssh       = { name = "Allow-Lab-Admin-SSH", priority = 210, direction = "Inbound", access = "Allow", protocol = "Tcp", destination_port_range = "22", source_address_prefix = var.lab_cidr, destination_address_prefix = "10.50.40.10" }
      wazuh_out_dns            = { name = "Allow-Out-DNS", priority = 100, direction = "Outbound", access = "Allow", protocol = "*", destination_port_range = "53", source_address_prefix = "*", destination_address_prefix = "168.63.129.16" }
      wazuh_out_azure_mgmt     = { name = "Allow-Out-AzureCloud-443", priority = 110, direction = "Outbound", access = "Allow", protocol = "Tcp", destination_port_range = "443", source_address_prefix = "*", destination_address_prefix = "AzureCloud" }
      wazuh_deny_all_in        = { name = "Deny-All-In", priority = 4096, direction = "Inbound", access = "Deny", protocol = "*", destination_port_range = "*", source_address_prefix = "*", destination_address_prefix = "*" }
      wazuh_deny_all_out       = { name = "Deny-All-Out", priority = 4096, direction = "Outbound", access = "Deny", protocol = "*", destination_port_range = "*", source_address_prefix = "*", destination_address_prefix = "*" }
    }
  }

  # D7 §5.2 "todas 300": egress 80/443 solo con var.maintenance_egress = true
  # (antes count = 0/1; azurerm no tiene enabled=false consistente).
  maintenance_by_nsg = {
    honeypot = { honeypot_out_maintenance = { name = "Allow-Out-Maintenance-Egress", priority = 300, direction = "Outbound", access = "Allow", protocol = "Tcp", destination_port_ranges = ["80", "443"], source_address_prefix = "*", destination_address_prefix = "Internet" } }
    vpn      = { vpn_out_maintenance = { name = "Allow-Out-Maintenance-Egress", priority = 300, direction = "Outbound", access = "Allow", protocol = "Tcp", destination_port_ranges = ["80", "443"], source_address_prefix = "*", destination_address_prefix = "Internet" } }
    logrelay = { logrelay_out_maintenance = { name = "Allow-Out-Maintenance-Egress", priority = 300, direction = "Outbound", access = "Allow", protocol = "Tcp", destination_port_ranges = ["80", "443"], source_address_prefix = "*", destination_address_prefix = "Internet" } }
    wazuh    = { wazuh_out_maintenance = { name = "Allow-Out-Maintenance-Egress", priority = 300, direction = "Outbound", access = "Allow", protocol = "Tcp", destination_port_ranges = ["80", "443"], source_address_prefix = "*", destination_address_prefix = "Internet" } }
  }

  nsg_names = {
    honeypot = azurerm_network_security_group.honeypot.name
    vpn      = azurerm_network_security_group.vpn.name
    logrelay = azurerm_network_security_group.logrelay.name
    wazuh    = azurerm_network_security_group.wazuh.name
  }

  # Aplana a un mapa por etiqueta de regla y añade `nsg` (clave de nsg_names).
  nsg_rules = merge([
    for nsg, rules in local.rules_by_nsg : {
      for k, v in merge(rules, var.maintenance_egress ? local.maintenance_by_nsg[nsg] : {}) : k => merge(v, { nsg = nsg })
    }
  ]...)
}

resource "azurerm_network_security_rule" "rule" {
  for_each = local.nsg_rules

  name                         = each.value.name
  priority                     = each.value.priority
  direction                    = each.value.direction
  access                       = each.value.access
  protocol                     = each.value.protocol
  source_port_range            = "*"
  destination_port_range       = lookup(each.value, "destination_port_range", null)
  destination_port_ranges      = lookup(each.value, "destination_port_ranges", null)
  source_address_prefix        = lookup(each.value, "source_address_prefix", null)
  source_address_prefixes      = lookup(each.value, "source_address_prefixes", null)
  destination_address_prefix   = lookup(each.value, "destination_address_prefix", null)
  destination_address_prefixes = lookup(each.value, "destination_address_prefixes", null)
  resource_group_name          = azurerm_resource_group.lab.name
  network_security_group_name  = local.nsg_names[each.value.nsg]
}

resource "azurerm_subnet_network_security_group_association" "honeypots" {
  subnet_id                 = azurerm_subnet.honeypots.id
  network_security_group_id = azurerm_network_security_group.honeypot.id
}

resource "azurerm_subnet_network_security_group_association" "vpn" {
  subnet_id                 = azurerm_subnet.vpn.id
  network_security_group_id = azurerm_network_security_group.vpn.id
}

resource "azurerm_subnet_network_security_group_association" "logrelay" {
  subnet_id                 = azurerm_subnet.logrelay.id
  network_security_group_id = azurerm_network_security_group.logrelay.id
}

resource "azurerm_subnet_network_security_group_association" "wazuh" {
  subnet_id                 = azurerm_subnet.wazuh.id
  network_security_group_id = azurerm_network_security_group.wazuh.id
}
