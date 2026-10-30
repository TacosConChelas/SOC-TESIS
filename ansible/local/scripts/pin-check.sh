#!/usr/bin/env bash
# Verifica que los pines de apt fijados en los defaults de los roles sigan
# existiendo hoy en el archivo de Ubuntu 22.04 (jammy). Requiere Internet.
# Uso: pin-check.sh [defaults-alternativo]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
override="${1:-}"
image="soc-tesis/ansible-local:22.04"

# Registro de pines: paquetes|defaults (relativo a ansible/)|variable
pines=(
  "nginx nginx-core nginx-common libnginx-mod-stream|roles/logrelay/defaults/main.yml|logrelay_nginx_version"
)

if ! docker image inspect "$image" >/dev/null 2>&1; then
  image="ubuntu:22.04"
fi

fail=0
for fila in "${pines[@]}"; do
  IFS='|' read -r paquetes archivo variable <<<"$fila"
  [ -n "$override" ] && archivo="$override"
  ruta="$archivo"
  case "$ruta" in /*) ;; *) ruta="$root/$archivo" ;; esac

  if [ ! -f "$ruta" ]; then
    echo "FALLA: no existe el archivo de defaults '$archivo' ($variable)" >&2
    fail=1
    continue
  fi

  want="$(sed -n "s/^${variable}:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$ruta" | head -n1)"
  if [ -z "$want" ]; then
    want="$(sed -n "s/^${variable}:[[:space:]]*'\([^']*\)'.*/\1/p" "$ruta" | head -n1)"
  fi
  if [ -z "$want" ]; then
    echo "FALLA: '$variable' no esta definida en $archivo" >&2
    fail=1
    continue
  fi

  script="apt-get update -qq >/dev/null 2>&1 || { echo __APT_UPDATE_FAIL__; exit 3; }; for p in $paquetes; do echo \"@@PKG \$p\"; apt-cache madison \"\$p\" || true; done"
  if ! out="$(docker run --rm --entrypoint sh "$image" -c "$script" 2>&1)"; then
    echo "FALLA: no se pudo consultar el archivo apt con la imagen '$image'" >&2
    echo "$out" >&2
    fail=1
    continue
  fi
  if grep -q __APT_UPDATE_FAIL__ <<<"$out"; then
    echo "FALLA: apt-get update fallo; pin-check necesita Internet" >&2
    fail=1
    continue
  fi

  for pkg in $paquetes; do
    disponibles="$(awk -F'|' -v pkg="$pkg" '
      /^@@PKG / { cur=$1; sub(/^@@PKG /, "", cur); next }
      cur == pkg { v=$2; gsub(/^[ \t]+|[ \t]+$/, "", v); if (v != "") print v }
    ' <<<"$out" | sort -u)"
    if grep -qxF "$want" <<<"$disponibles"; then
      echo "ok: $pkg $want disponible ($archivo:$variable)"
    else
      echo "FALLA: $pkg no tiene la version fijada $want ($archivo:$variable)" >&2
      if [ -n "$disponibles" ]; then
        echo "  versiones disponibles:" >&2
        sed 's/^/    /' <<<"$disponibles" >&2
      else
        echo "  el paquete no aparece en el archivo apt" >&2
      fi
      fail=1
    fi
  done
done

if [ "$fail" -ne 0 ]; then
  echo "pin-check: FALLA (revisar la version fijada en los defaults de los roles)" >&2
  exit 1
fi
echo "pin-check: ok"
