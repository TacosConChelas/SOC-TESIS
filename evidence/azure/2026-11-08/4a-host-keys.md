# Etapa 4a — huellas SSH de las 4 VMs (2026-11-08)

Obtenidas por `az vm run-command` con `ansible/azure/host-keys.sh`; fijadas en `~/soc-tesis-secrets/azure_known_hosts` (0600, fuera del repo).

| VM | Host en known_hosts | Tipo | Huella |
|---|---|---|---|
| vm-strongswan | 10.50.20.10 | ED25519 | `SHA256:4wTIF2LL5ZDWmGxYDfnu/OBWT3Kb3WfLAeEjiP5dSkU` |
| vm-wazuh | 10.50.40.10 | ED25519 | `SHA256:iCmLJV2LNWnUT+GvuoZM1h6r4kez7obgPvocxY/D2+E` |
| vm-logrelay | 10.50.30.10 | ED25519 | `SHA256:QuHF9wHp8jk/mL6Lo6+pbf+cmiwPXL94S1t+Jl2Xb9k` |
| vm-honeyserver | [10.50.10.10]:22222 | ED25519 | `SHA256:P5zEqgiMvyY9sEbPRnDmYd/szqLSVWDMlACgtokQwzY` |

El honeyserver aparece en el 22222 (E1-2: sshd movido por cloud-init `custom_data`).
