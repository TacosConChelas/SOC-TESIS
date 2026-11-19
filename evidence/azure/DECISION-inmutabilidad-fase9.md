# Decisión: inmutabilidad de la evidencia (Blob) antes de la Fase 9

Fecha: 2026-11-18. Estado: **decidida (mantener Unlocked hasta cierre de Fase 9)**. Fuentes: `terraform/evidence/storage.tf`, `.knowledge/19_ESTRATEGIA_EVIDENCIA.md` §5-§8, `.knowledge/21_TERRAFORM_PREPARACION.md` §5, `evidence/azure/2026-11-13/12-cierre-fase7.md`, `evidence/azure/2026-11-13/f7-4-inmutabilidad.log`, `evidence/azure/2026-11-14-f8b/14-acta-fase8-cierre.md`.

## Decisión

Mantener la política `Unlocked` de 90 días en `socesisevidencia01` / `evidencia-soc-tesis` durante toda la Fase 9. Bloquearla (`Locked`) solo cuando se cumpla el criterio de la sección 3.

## Justificación

- `Locked` es irreversible: no se puede borrar ni acortar, solo ampliar (Microsoft Learn, `az storage container immutability-policy`). Con la Fase 9 por ejecutar, es probable que haya re-ejecuciones o correcciones; con `Locked` no se pueden retirar ni siquiera los datos que sobren.
- Bloquear ahora no protege más la evidencia ya subida: la política `Unlocked` ya se probó (`f7-4`: sobrescribir y borrar devuelven `BlobImmutableDueToPolicy`), y ya se aplica a los blobs de 08-13 y 14-nov.
- Lo que queda sin resolver (la copia del 13-nov con IDs de Azure en base64, ver 12-cierre) no se arregla con `Locked`. Retirarla exige quitar la política o esperar a su vencimiento (~11-feb-2027). Con `Locked` ni siquiera se podría esperar a quitarla.
- El riesgo de `Unlocked` es que el operador (Owner) pueda quitar la política. Eso es un límite real y debe declararse en la tesis: la integridad se apoya en SHA256 verificados y en la política, no en un WORM que impida al propio operador. Ese es el argumento a favor de `Locked`, y por eso se pospone, no se descarta.

## Criterio para bloquear (todos deben cumplirse)

1. Fase 9 cerrada con acta final (versión sin hallazgos abiertos o con reservas aceptadas por escrito).
2. Todas las RUN de la Fase 9 subidas con `terraform/evidence/evidence-sync.sh` (línea `ok`) y verificadas con `sha256sum -c`.
3. Sin IDs de Azure en claro ni en base64 en las carpetas a subir (`grep -rE` del GUID y del regex base64 del script sobre las carpetas nuevas).
4. Decisión registrada sobre la copia del 13-nov: se acepta el residuo hasta su vencimiento, o se decide otra cosa por escrito en el acta.
5. Discrepancia conocida documentada: el `SHA256SUMS` de `evidence/azure/2026-11-13/` del repo no coincide con la versión subida en Blob de `f7-5-prevent-destroy.log`. El acta final lo declara.
6. Dejar `Unlocked` como plan de vuelta: si algo falla en los puntos 1-5, no se bloquea.

## Procedimiento (NO ejecutado)

Opción A, CLI (verificar flags con `az storage container immutability-policy lock --help` antes):
```
az storage container immutability-policy show --account-name socesisevidencia01 --container-name evidencia-soc-tesis --resource-group rg-soc-tesis-evidence      # anotar el ETag
az storage container immutability-policy lock --account-name socesisevidencia01 --container-name evidencia-soc-tesis --resource-group rg-soc-tesis-evidence --if-match "<ETag>"
```
Opción B, Terraform: en `terraform/evidence/storage.tf`, añadir `locked = true` al recurso `azurerm_storage_container_immutability_policy.evidence` (el atributo `locked` existe en el state actual, con valor `false`), luego `terraform plan` (debe mostrar solo un cambio en la política) y `apply` con confirmación explícita. Actualizar el comentario del `.tf` y `.knowledge/19` §6 ("sin bloquear") en el mismo commit.

Tras bloquear: registrar la fecha y el ETag en esta nota y en el acta final; `terraform plan` debe quedar sin cambios.

## Consecuencias aceptadas

- La política no se puede quitar; el contenedor no se puede borrar hasta vencer todos sus blobs (`Locked`).
- Los blobs expirados se pueden borrar a mano después de su vencimiento (doc 19 §8).
- Si la tesis exige borrar datos antes (protección de datos), no será posible hasta vencimiento. Revisar antes de bloquear.
