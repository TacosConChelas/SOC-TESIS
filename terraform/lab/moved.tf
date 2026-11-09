# Borrar este archivo tras el próximo terraform apply autorizado (los moved ya estarán en el estado).
# Migracion 1:1 de las reglas NSG a un unico for_each (nsg.tf: local.nsg_rules).
# Las reglas de mantenimiento venian con count (X[0]); si maintenance_egress=false
# no hay instancia en estado y el bloque moved es un no-op.

moved {
  from = azurerm_network_security_rule.honeypot_in_public_surface
  to   = azurerm_network_security_rule.rule["honeypot_in_public_surface"]
}

moved {
  from = azurerm_network_security_rule.honeypot_in_tftp_udp
  to   = azurerm_network_security_rule.rule["honeypot_in_tftp_udp"]
}

moved {
  from = azurerm_network_security_rule.honeypot_in_sip_udp
  to   = azurerm_network_security_rule.rule["honeypot_in_sip_udp"]
}

moved {
  from = azurerm_network_security_rule.honeypot_in_admin_ssh
  to   = azurerm_network_security_rule.rule["honeypot_in_admin_ssh"]
}

moved {
  from = azurerm_network_security_rule.honeypot_out_to_logrelay
  to   = azurerm_network_security_rule.rule["honeypot_out_to_logrelay"]
}

moved {
  from = azurerm_network_security_rule.honeypot_out_dns
  to   = azurerm_network_security_rule.rule["honeypot_out_dns"]
}

moved {
  from = azurerm_network_security_rule.honeypot_out_azure_mgmt
  to   = azurerm_network_security_rule.rule["honeypot_out_azure_mgmt"]
}

moved {
  from = azurerm_network_security_rule.honeypot_deny_all_in
  to   = azurerm_network_security_rule.rule["honeypot_deny_all_in"]
}

moved {
  from = azurerm_network_security_rule.honeypot_deny_all_out
  to   = azurerm_network_security_rule.rule["honeypot_deny_all_out"]
}

moved {
  from = azurerm_network_security_rule.vpn_in_ike
  to   = azurerm_network_security_rule.rule["vpn_in_ike"]
}

moved {
  from = azurerm_network_security_rule.vpn_in_esp
  to   = azurerm_network_security_rule.rule["vpn_in_esp"]
}

moved {
  from = azurerm_network_security_rule.vpn_in_admin_ssh
  to   = azurerm_network_security_rule.rule["vpn_in_admin_ssh"]
}

moved {
  from = azurerm_network_security_rule.vpn_out_dns
  to   = azurerm_network_security_rule.rule["vpn_out_dns"]
}

moved {
  from = azurerm_network_security_rule.vpn_out_azure_mgmt
  to   = azurerm_network_security_rule.rule["vpn_out_azure_mgmt"]
}

moved {
  from = azurerm_network_security_rule.vpn_out_rekey
  to   = azurerm_network_security_rule.rule["vpn_out_rekey"]
}

moved {
  from = azurerm_network_security_rule.vpn_out_esp
  to   = azurerm_network_security_rule.rule["vpn_out_esp"]
}

moved {
  from = azurerm_network_security_rule.vpn_out_forward_to_vnet
  to   = azurerm_network_security_rule.rule["vpn_out_forward_to_vnet"]
}

moved {
  from = azurerm_network_security_rule.vpn_deny_all_in
  to   = azurerm_network_security_rule.rule["vpn_deny_all_in"]
}

moved {
  from = azurerm_network_security_rule.vpn_deny_all_out
  to   = azurerm_network_security_rule.rule["vpn_deny_all_out"]
}

moved {
  from = azurerm_network_security_rule.logrelay_in_from_honeyserver
  to   = azurerm_network_security_rule.rule["logrelay_in_from_honeyserver"]
}

moved {
  from = azurerm_network_security_rule.logrelay_in_admin_ssh
  to   = azurerm_network_security_rule.rule["logrelay_in_admin_ssh"]
}

moved {
  from = azurerm_network_security_rule.logrelay_out_to_wazuh
  to   = azurerm_network_security_rule.rule["logrelay_out_to_wazuh"]
}

moved {
  from = azurerm_network_security_rule.logrelay_out_dns
  to   = azurerm_network_security_rule.rule["logrelay_out_dns"]
}

moved {
  from = azurerm_network_security_rule.logrelay_out_azure_mgmt
  to   = azurerm_network_security_rule.rule["logrelay_out_azure_mgmt"]
}

moved {
  from = azurerm_network_security_rule.logrelay_deny_all_in
  to   = azurerm_network_security_rule.rule["logrelay_deny_all_in"]
}

moved {
  from = azurerm_network_security_rule.logrelay_deny_all_out
  to   = azurerm_network_security_rule.rule["logrelay_deny_all_out"]
}

moved {
  from = azurerm_network_security_rule.wazuh_in_from_logrelay
  to   = azurerm_network_security_rule.rule["wazuh_in_from_logrelay"]
}

moved {
  from = azurerm_network_security_rule.wazuh_in_from_lab_agents
  to   = azurerm_network_security_rule.rule["wazuh_in_from_lab_agents"]
}

moved {
  from = azurerm_network_security_rule.wazuh_in_dashboard
  to   = azurerm_network_security_rule.rule["wazuh_in_dashboard"]
}

moved {
  from = azurerm_network_security_rule.wazuh_in_admin_ssh
  to   = azurerm_network_security_rule.rule["wazuh_in_admin_ssh"]
}

moved {
  from = azurerm_network_security_rule.wazuh_out_dns
  to   = azurerm_network_security_rule.rule["wazuh_out_dns"]
}

moved {
  from = azurerm_network_security_rule.wazuh_out_azure_mgmt
  to   = azurerm_network_security_rule.rule["wazuh_out_azure_mgmt"]
}

moved {
  from = azurerm_network_security_rule.wazuh_deny_all_in
  to   = azurerm_network_security_rule.rule["wazuh_deny_all_in"]
}

moved {
  from = azurerm_network_security_rule.wazuh_deny_all_out
  to   = azurerm_network_security_rule.rule["wazuh_deny_all_out"]
}

moved {
  from = azurerm_network_security_rule.honeypot_out_maintenance[0]
  to   = azurerm_network_security_rule.rule["honeypot_out_maintenance"]
}

moved {
  from = azurerm_network_security_rule.vpn_out_maintenance[0]
  to   = azurerm_network_security_rule.rule["vpn_out_maintenance"]
}

moved {
  from = azurerm_network_security_rule.logrelay_out_maintenance[0]
  to   = azurerm_network_security_rule.rule["logrelay_out_maintenance"]
}

moved {
  from = azurerm_network_security_rule.wazuh_out_maintenance[0]
  to   = azurerm_network_security_rule.rule["wazuh_out_maintenance"]
}
