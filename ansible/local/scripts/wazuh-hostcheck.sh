#!/usr/bin/env bash
# Requisitos del anfitrion para el all-in-one real en el contenedor. Solo lee; no cambia nada.
set -euo pipefail

min_mem_mb="${WAZUH_MIN_MEM_MB:-6144}"
min_disk_gb="${WAZUH_MIN_DISK_GB:-15}"
fail=0

bad() { echo "FALLA: $*" >&2; fail=1; }
good() { echo "ok: $*"; }

avail_mb="$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)"
if [ "$avail_mb" -ge "$min_mem_mb" ]; then
  good "memoria disponible ${avail_mb} MiB (minimo ${min_mem_mb})"
else
  bad "memoria disponible ${avail_mb} MiB; se necesitan ${min_mem_mb} MiB (cierra programas o baja WAZUH_MIN_MEM_MB bajo tu riesgo)"
fi

map_count="$(cat /proc/sys/vm/max_map_count)"
if [ "$map_count" -ge 262144 ]; then
  good "vm.max_map_count=${map_count} (minimo 262144)"
else
  bad "vm.max_map_count=${map_count}; el Indexer pide 262144. Ajustalo en el anfitrion (p. ej. sudo sysctl -w vm.max_map_count=262144); este script no lo cambia"
fi

root_dir="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
if [ -n "$root_dir" ]; then
  free_gb="$(df --output=avail -BG "$root_dir" | tail -n 1 | tr -dc '0-9')"
  if [ "${free_gb:-0}" -ge "$min_disk_gb" ]; then
    good "disco libre en ${root_dir}: ${free_gb} GiB (minimo ${min_disk_gb})"
  else
    bad "disco libre en ${root_dir}: ${free_gb:-0} GiB; se necesitan ${min_disk_gb} GiB"
  fi
else
  bad "no se pudo consultar el demonio de Docker"
fi

if docker inspect -f '{{.State.Running}}' soc-local-wazuh 2>/dev/null | grep -qx true; then
  good "contenedor soc-local-wazuh en ejecucion"
else
  bad "soc-local-wazuh no esta en ejecucion (corre make up o make rehearse)"
fi

if [ "$fail" -ne 0 ]; then
  echo "wazuh-hostcheck: FALLA" >&2
  exit 1
fi
echo "wazuh-hostcheck: ok"
