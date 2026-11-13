# Fase 7 — Evidencia en Blob (2026-11-13)

Plan: `docs/superpowers/plans/2026-11-13-fase7-evidencia-blob.md` (local). Logs `f7-*` de esta carpeta; GUIDs redactados como `<guid>`.

## Resultado por punto (plan maestro, Fase 7)

| Punto | Resultado | Evidencia |
|---|---|---|
| 1 · Almacenamiento histórico (Blob 15 GB Cool LRS) | `socesisevidencia01` en `rg-soc-tesis-evidence` (Central US), Cool, `Standard_LRS`, contenedor privado `evidencia-soc-tesis`. Apply `5 added`; plan posterior sin cambios | `f7-1-apply.log`, `f7-2-config.log` |
| 2 · Cifrado | En reposo por defecto (SSE de Azure); TLS 1.2 mínimo; sin clave compartida (`allowSharedKeyAccess=false`), solo Entra ID + RBAC (`Storage Blob Data Contributor` del operador); sin acceso público; firewall `Deny` salvo `201.96.0.0/12` | `f7-2-config.log` |
| 3 · Integridad e inmutabilidad | Política temporal de 90 días, **Unlocked**. Sobre un blob canario: sobrescribir y borrar → `BlobImmutableDueToPolicy`; acceso con clave → `KeyBasedAuthenticationNotPermitted`. Subida con verificación de restauración contra el manifiesto local | `f7-4-inmutabilidad.log`, `f7-3-sync.log` |
| 4 · Retención | 90 días por la política, más soft delete de 7 días y versionado. El borrado al vencer es manual (doc 19 §8) | `f7-2-config.log` |
| 5 · Terraform no destruye la evidencia | `plan -destroy` aborta con `Instance cannot be destroyed` (4 recursos con `prevent_destroy`). El state de `terraform/lab` no contiene recursos de evidencia (0 de 67) | `f7-5-prevent-destroy.log` |

**Subido:** `azure/2026-11-08` (22), `azure/2026-11-09` (30), `azure/2026-11-10` (3) = 55 blobs = 55 archivos locales, cada carpeta verificada con su `SHA256SUMS`. Esta carpeta se sube al cerrar, como `azure/2026-11-13`.

## Incidencias

- `evidence-sync.sh` resolvía `realpath` después de un `cd` (bug introducido al endurecer la verificación). La subida de `azure/2026-11-08` terminó (22/22), pero su verificación no corrió. Se corrigió (`c0cceb2`) y se verificó a mano con la misma lógica: manifiesto idéntico, hashes y lista de archivos iguales.
- La revisión de seguridad automática llevó a `b000e2c` y `9d00f76`: verificación contra el manifiesto local, ruta de secretos fija, llave SSH en la higiene y rechazo de enlaces y comprimidos. Límite conocido: no detecta un secreto recodificado (base64/hex).
- La copia del state está en `~/soc-tesis-secrets/tfstate/` (0600), aún **sin cifrar con gpg** (requiere la frase del operador; D9).

## Decisiones abiertas

- **Bloquear la política (Locked):** irreversible. Unlocked bloqueó el borrado de blobs en la prueba, pero la política se puede retirar con permisos de control. Decidir antes de la Fase 9 si la tesis exige WORM estricto.
- Rol limitado al contenedor e identidad separada para subir: no se aplica. Hay un solo operador, que además es Owner de la suscripción.

## Corrección posterior (redacción)

`f7-5-prevent-destroy.log` contenía el `id` de `data.azurerm_client_config` codificado en base64, con los IDs de cliente, objeto, suscripción y tenant. La redacción por regex de GUID no lo vio. En Git se sustituyó por `<client-config-base64>` y se regeneró `SHA256SUMS`. **La copia en Blob (`azure/2026-11-13`) es la versión anterior y es inmutable:** contiene esos IDs, que no son credenciales y solo puede leer el operador (contenedor privado, Entra ID). Retirarla exigiría quitar la política de inmutabilidad; no se hace sin decisión del operador. `evidence-sync.sh` rechaza ahora los tokens base64 que decodifican a un GUID.
