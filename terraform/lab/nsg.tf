# NSG (D7, 18_DECISIONES_IMPLEMENTACION.md §5). Cada NSG termina con
# Deny-All-In/Deny-All-Out explícito (prioridad 4096), aunque azurerm ya
# incluye un DenyAllInBound/OutBound implícito — se deja explícito por
# trazabilidad con la decisión documentada.

# ---------------------------------------------------------------------------
# nsg-honeypot
# ---------------------------------------------------------------------------
resource "azurerm_network_security_group" "honeypot" {
  name                = "nsg-honeypot"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags
}

# Destinos de entrada: las IP privadas estáticas literales que fija D7 §5.1
# (Honey-Server 10.50.10.10, strongSwan 10.50.20.10, Log Relay 10.50.30.10,
# Wazuh 10.50.40.10), las mismas que usa `vms.tf` para las NIC. No se usa "*"
# porque D7 fija el destino y "*" permitiría tráfico hacia cualquier host de
# la subred.
#
# Nota de implementación sobre D7 §5.2: Azure NSG admite UN protocolo por
# regla, así que las filas "UDP 500/4500; ESP" (egress vpn) y "UDP/TCP 53"
# (DNS) no pueden ser una sola regla. Se conservan las MISMAS prioridades de
# D7 y la regla adicional que el formato exige entra en el hueco libre de la
# franja (210 ESP / 220 reenvío en nsg-vpn).

resource "azurerm_network_security_rule" "honeypot_in_public_surface" {
  name                        = "Allow-Internet-Honeypot-Surface"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp" # D7 §5.1: los puertos de esta regla son TCP (architecture.md §6.1)
  source_port_range           = "*"
  destination_port_ranges     = ["22", "23", "25", "80", "21", "135", "443", "445", "1433", "1883", "3306", "5060", "5061"]
  source_address_prefix       = "Internet"
  destination_address_prefix  = "10.50.10.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

resource "azurerm_network_security_rule" "honeypot_in_tftp_udp" {
  name                        = "Allow-Internet-Dionaea-TFTP-UDP"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_range      = "69"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "10.50.10.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

resource "azurerm_network_security_rule" "honeypot_in_sip_udp" {
  name                        = "Allow-Internet-Dionaea-SIP-UDP"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_ranges     = ["5060", "5061"]
  source_address_prefix       = "Internet"
  destination_address_prefix  = "10.50.10.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

resource "azurerm_network_security_rule" "honeypot_in_admin_ssh" {
  name                        = "Allow-Lab-Admin-SSH-22222"
  priority                    = 300
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22222"
  source_address_prefix       = var.lab_cidr
  destination_address_prefix  = "10.50.10.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

resource "azurerm_network_security_rule" "honeypot_out_to_logrelay" {
  name                        = "Allow-Out-Agent-To-LogRelay"
  priority                    = 200
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["1514", "1515"]
  source_address_prefix       = "*"
  destination_address_prefix  = "10.50.30.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

resource "azurerm_network_security_rule" "honeypot_out_dns" {
  name                        = "Allow-Out-DNS"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "53"
  source_address_prefix       = "*"
  # D7 §5.2 fila "todas 100". Esta regla documenta la intencion: el DNS hacia 168.63.129.16 no pasa por
  # los NSG salvo que se apunte con el tag AzurePlatformDNS, asi que Azure ya lo permite sin esta regla.
  # NO volver a "AzurePlatformDNS": ese tag solo admite Deny (Allow da SecurityRuleInvalidAccessType, 400).
  destination_address_prefix  = "168.63.129.16"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

resource "azurerm_network_security_rule" "honeypot_out_azure_mgmt" {
  name                        = "Allow-Out-AzureCloud-443"
  priority                    = 110
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "AzureCloud"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

# D7 §5.2: egress genérico (apt/Docker Hub/GHCR/packages.wazuh.com) SOLO en
# modo mantenimiento. count=0 cuando maintenance_egress=false: la regla ni
# se crea, en vez de crearla deshabilitada (azurerm no soporta "enabled=false"
# en este recurso de forma nativa de manera consistente entre versiones).
resource "azurerm_network_security_rule" "honeypot_out_maintenance" {
  count                       = var.maintenance_egress ? 1 : 0
  name                        = "Allow-Out-Maintenance-Egress"
  priority                    = 300
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["80", "443"]
  source_address_prefix       = "*"
  destination_address_prefix  = "Internet"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

resource "azurerm_network_security_rule" "honeypot_deny_all_in" {
  name                        = "Deny-All-In"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

resource "azurerm_network_security_rule" "honeypot_deny_all_out" {
  name                        = "Deny-All-Out"
  priority                    = 4096
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.honeypot.name
}

resource "azurerm_subnet_network_security_group_association" "honeypots" {
  subnet_id                 = azurerm_subnet.honeypots.id
  network_security_group_id = azurerm_network_security_group.honeypot.id
}

# ---------------------------------------------------------------------------
# nsg-vpn
# ---------------------------------------------------------------------------
resource "azurerm_network_security_group" "vpn" {
  name                = "nsg-vpn"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags
}

# ADR-004/ADR-005 (2026-10-22): el iniciador es la Raspberry Pi 5. Política
# vigente (decisión 2026-10-27) = N3 acotada: origen var.lab_source_cidrs
# (por defecto el /12 del ISP; la IP de salida es dinámica tras CGNAT). La regla ESP y
# las salidas 200/210 (Allow-Out-Rekey/ESP-To-Lab) se MANTIENEN provisionalmente
# hasta observar el túnel real (ADR-005 §5). Nada de esto está desplegado ni
# validado. Solo comentario; sin cambio de comportamiento.
resource "azurerm_network_security_rule" "vpn_in_ike" {
  name                        = "Allow-Lab-IKE-NATT"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_ranges     = ["500", "4500"]
  source_address_prefixes     = var.lab_source_cidrs
  destination_address_prefix  = "10.50.20.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.vpn.name
}

# CON-18: ESP (protocolo 50) para IPsec sin NAT intermedio.
resource "azurerm_network_security_rule" "vpn_in_esp" {
  name                        = "Allow-Lab-ESP"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Esp"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefixes     = var.lab_source_cidrs
  destination_address_prefix  = "10.50.20.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.vpn.name
}

# SSH de administración a la VM strongSwan SOLO desde el lab (lab_cidr), igual
# que en las otras 3 NSG. Llega descifrado por el túnel (no hay SSH desde
# Internet). Necesario para que Ansible configure la VM una vez arriba el
# túnel; el bootstrap inicial (PSK/IKE) va por `az vm run-command`.
resource "azurerm_network_security_rule" "vpn_in_admin_ssh" {
  name                        = "Allow-Lab-Admin-SSH"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.lab_cidr
  destination_address_prefix  = "10.50.20.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.vpn.name
}

# D7 §5.2 "todas 100": DNS al resolver de Azure. Antes faltaba en nsg-vpn
# (solo existía en las otras 3 NSG).
resource "azurerm_network_security_rule" "vpn_out_dns" {
  name                        = "Allow-Out-DNS"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "53"
  source_address_prefix       = "*"
  destination_address_prefix  = "168.63.129.16"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.vpn.name
}

# D7 §5.2 "todas 110": agente de VM, extensiones y Run Command (vía de
# recuperación de strongSwan, architecture.md §15). Antes faltaba en nsg-vpn.
resource "azurerm_network_security_rule" "vpn_out_azure_mgmt" {
  name                        = "Allow-Out-AzureCloud-443"
  priority                    = 110
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "AzureCloud"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.vpn.name
}

resource "azurerm_network_security_rule" "vpn_out_rekey" {
  name                         = "Allow-Out-Rekey-To-Lab"
  priority                     = 200
  direction                    = "Outbound"
  access                       = "Allow"
  protocol                     = "Udp"
  source_port_range            = "*"
  destination_port_ranges      = ["500", "4500"]
  source_address_prefix        = "*"
  destination_address_prefixes = var.lab_source_cidrs
  resource_group_name          = azurerm_resource_group.lab.name
  network_security_group_name  = azurerm_network_security_group.vpn.name
}

resource "azurerm_network_security_rule" "vpn_out_esp" {
  name                         = "Allow-Out-ESP-To-Lab"
  priority                     = 210
  direction                    = "Outbound"
  access                       = "Allow"
  protocol                     = "Esp"
  source_port_range            = "*"
  destination_port_range       = "*"
  source_address_prefix        = "*"
  destination_address_prefixes = var.lab_source_cidrs
  resource_group_name          = azurerm_resource_group.lab.name
  network_security_group_name  = azurerm_network_security_group.vpn.name
}

# D6: tráfico descifrado del túnel reenviado hacia la VNet (sin SNAT).
# D7 §5.2 lo llama prioridad 210 (Any, lab_cidr → VNet); como ESP ya ocupa
# 210 como regla propia (no caben dos protocolos en una), el reenvío va en
# 220, el primer hueco libre. Sin cambio de alcance.
resource "azurerm_network_security_rule" "vpn_out_forward_to_vnet" {
  name                        = "Allow-Out-Forward-To-VNet"
  priority                    = 220
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = var.lab_cidr
  destination_address_prefix  = "10.50.0.0/16"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.vpn.name
}

# D7 §5.2 "todas 300": egress genérico (apt/Docker Hub/GHCR/packages.wazuh.com)
# SOLO en modo mantenimiento. Igual que en las otras 3 NSG: count=0 cuando
# maintenance_egress=false.
resource "azurerm_network_security_rule" "vpn_out_maintenance" {
  count                       = var.maintenance_egress ? 1 : 0
  name                        = "Allow-Out-Maintenance-Egress"
  priority                    = 300
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["80", "443"]
  source_address_prefix       = "*"
  destination_address_prefix  = "Internet"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.vpn.name
}

resource "azurerm_network_security_rule" "vpn_deny_all_in" {
  name                        = "Deny-All-In"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.vpn.name
}

resource "azurerm_network_security_rule" "vpn_deny_all_out" {
  name                        = "Deny-All-Out"
  priority                    = 4096
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.vpn.name
}

resource "azurerm_subnet_network_security_group_association" "vpn" {
  subnet_id                 = azurerm_subnet.vpn.id
  network_security_group_id = azurerm_network_security_group.vpn.id
}

# ---------------------------------------------------------------------------
# nsg-logrelay
# ---------------------------------------------------------------------------
resource "azurerm_network_security_group" "logrelay" {
  name                = "nsg-logrelay"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags
}

resource "azurerm_network_security_rule" "logrelay_in_from_honeyserver" {
  name                        = "Allow-HoneyServer-Events"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["1514", "1515"]
  source_address_prefix       = "10.50.10.10"
  destination_address_prefix  = "10.50.30.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.logrelay.name
}

resource "azurerm_network_security_rule" "logrelay_in_admin_ssh" {
  name                        = "Allow-Lab-Admin-SSH"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.lab_cidr
  destination_address_prefix  = "10.50.30.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.logrelay.name
}

resource "azurerm_network_security_rule" "logrelay_out_to_wazuh" {
  name                        = "Allow-Out-To-Wazuh"
  priority                    = 200
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["1514", "1515"]
  source_address_prefix       = "*"
  destination_address_prefix  = "10.50.40.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.logrelay.name
}

resource "azurerm_network_security_rule" "logrelay_out_dns" {
  name                        = "Allow-Out-DNS"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "53"
  source_address_prefix       = "*"
  destination_address_prefix  = "168.63.129.16"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.logrelay.name
}

resource "azurerm_network_security_rule" "logrelay_out_azure_mgmt" {
  name                        = "Allow-Out-AzureCloud-443"
  priority                    = 110
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "AzureCloud"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.logrelay.name
}

resource "azurerm_network_security_rule" "logrelay_out_maintenance" {
  count                       = var.maintenance_egress ? 1 : 0
  name                        = "Allow-Out-Maintenance-Egress"
  priority                    = 300
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["80", "443"]
  source_address_prefix       = "*"
  destination_address_prefix  = "Internet"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.logrelay.name
}

resource "azurerm_network_security_rule" "logrelay_deny_all_in" {
  name                        = "Deny-All-In"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.logrelay.name
}

resource "azurerm_network_security_rule" "logrelay_deny_all_out" {
  name                        = "Deny-All-Out"
  priority                    = 4096
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.logrelay.name
}

resource "azurerm_subnet_network_security_group_association" "logrelay" {
  subnet_id                 = azurerm_subnet.logrelay.id
  network_security_group_id = azurerm_network_security_group.logrelay.id
}

# ---------------------------------------------------------------------------
# nsg-wazuh
# ---------------------------------------------------------------------------
resource "azurerm_network_security_group" "wazuh" {
  name                = "nsg-wazuh"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = var.tags
}

resource "azurerm_network_security_rule" "wazuh_in_from_logrelay" {
  name                        = "Allow-LogRelay-Events"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["1514", "1515"]
  source_address_prefix       = "10.50.30.10"
  destination_address_prefix  = "10.50.40.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.wazuh.name
}

# CON-08: agentes Windows 11 / Ubuntu del laboratorio directo a Wazuh.
resource "azurerm_network_security_rule" "wazuh_in_from_lab_agents" {
  name                        = "Allow-Lab-Agents-1514-1515"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["1514", "1515"]
  source_address_prefix       = var.lab_cidr
  destination_address_prefix  = "10.50.40.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.wazuh.name
}

resource "azurerm_network_security_rule" "wazuh_in_dashboard" {
  name                        = "Allow-Lab-Dashboard-443"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = var.lab_cidr
  destination_address_prefix  = "10.50.40.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.wazuh.name
}

resource "azurerm_network_security_rule" "wazuh_in_admin_ssh" {
  name                        = "Allow-Lab-Admin-SSH"
  priority                    = 210
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.lab_cidr
  destination_address_prefix  = "10.50.40.10"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.wazuh.name
}

resource "azurerm_network_security_rule" "wazuh_out_dns" {
  name                        = "Allow-Out-DNS"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "53"
  source_address_prefix       = "*"
  destination_address_prefix  = "168.63.129.16"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.wazuh.name
}

resource "azurerm_network_security_rule" "wazuh_out_azure_mgmt" {
  name                        = "Allow-Out-AzureCloud-443"
  priority                    = 110
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "AzureCloud"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.wazuh.name
}

resource "azurerm_network_security_rule" "wazuh_out_maintenance" {
  count                       = var.maintenance_egress ? 1 : 0
  name                        = "Allow-Out-Maintenance-Egress"
  priority                    = 300
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["80", "443"]
  source_address_prefix       = "*"
  destination_address_prefix  = "Internet"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.wazuh.name
}

resource "azurerm_network_security_rule" "wazuh_deny_all_in" {
  name                        = "Deny-All-In"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.wazuh.name
}

resource "azurerm_network_security_rule" "wazuh_deny_all_out" {
  name                        = "Deny-All-Out"
  priority                    = 4096
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.wazuh.name
}

resource "azurerm_subnet_network_security_group_association" "wazuh" {
  subnet_id                 = azurerm_subnet.wazuh.id
  network_security_group_id = azurerm_network_security_group.wazuh.id
}
