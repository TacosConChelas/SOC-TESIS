# Entrada: `terraform show -json <plan>`. Salida: nombre de cada regla NSG que el plan deja
# Outbound/Allow hacia "*", "Internet" o 0.0.0.0/0 (egreso abierto). Vacio = plan cerrado.
.resource_changes[]?
| select(.type == "azurerm_network_security_rule" and .change.after != null)
| .change.after
| select(.direction == "Outbound" and .access == "Allow")
| select(([.destination_address_prefix] + (.destination_address_prefixes // []))
         | any(. == "*" or . == "Internet" or . == "0.0.0.0/0"))
| .name
