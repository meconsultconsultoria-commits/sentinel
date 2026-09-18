# SENTINEL — Cloudflare production architecture

Target: Cloudflare only. Vercel is not part of the production architecture.

## Resources
- Cloudflare Workers/Pages: application and API
- D1 binding: DB / database sentinel-db
- R2 binding: EVIDENCE / bucket sentinel-evidence
- GitHub: meconsultconsultoria-commits/sentinel

## Provisioning
1. Create D1 database sentinel-db.
2. Replace REPLACE_WITH_D1_DATABASE_ID in wrangler.jsonc.
3. Apply schema.sql to D1.
4. Create R2 bucket sentinel-evidence.
5. Configure authentication secrets only in Cloudflare; never commit credentials.
6. Connect GitHub main branch to Cloudflare build/deploy.
7. Configure production custom domain after validation.

## RBAC
ADMIN: full administration.
SSMA: classification, investigation, validation and closure.
GESTOR: registration, investigation participation and action execution.
CONSULTA: read-only.

## Data model
Multi-company and multi-unit from the first production schema. Occurrences, third parties, investigations, actions, attachments, closures and audit history are centralized in D1. Evidence binaries belong in R2.