# BetCashback MVP — Revised Implementation Plan (Constraint-Aligned)

## 1) Repository analysis (current baseline)

### Current architecture
- Backend is a **single Express server** with direct SQL queries in `backend/server.js`.
- User mini app is a **single static page** with inline JS in `frontend/index.html`.
- Admin panel is a **single static page** with inline JS in `backend/admin/index.html`.
- DB baseline is managed by bootstrap SQL in `backend/schema.sql` (no migration tooling yet).

### Existing reusable logic
- Telegram WebApp auth verification middleware already exists and works for user identity.
- `bookmaker_accounts` table already exists and is the right base for bookmaker-account verification state.
- Claims and attachments flow already exists (including screenshot upload/rehash/duplicate detection).
- Admin claim review UI/API exists and can be extended.
- Basic payout primitives exist (`payout_methods`, `payouts`), but user withdrawal workflow is incomplete.

### Current gaps relevant to MVP
- No tracked bookmaker registration link generation/storage.
- No partner import subsystem for bookmaker player data.
- No admin workflow focused on **bookmaker account verification** (currently review is claim-centric).
- Claim submission is currently available regardless of bookmaker account verification status.
- DB evolution workflow (migrations) is missing.

---

## 2) MVP model decisions (updated per constraints)

## Verification model (critical)
Verification is **NOT claim-based**. It is **bookmaker-account-based** for each `(user_id, bookmaker_id)` pair:
1. User selects bookmaker.
2. System generates tracked registration link.
3. User registers using that link.
4. User submits bookmaker `player_id`.
5. Admin reviews import/match suggestions and verifies the bookmaker account manually.
6. Only after account status is verified, user can submit claims for that bookmaker.

## MVP simplicity constraints
For MVP we use only the following workflow entities (plus existing core tables):
- `bookmaker_accounts` (verification state source of truth)
- `bookmaker_link_generations` (tracked link generation history)
- `partner_import_batches`
- `partner_player_rows`
- `claims`
- `payout_requests`
- `internal_notes`
- `admin_audit_log`

Do **not** add in MVP unless absolutely required:
- `verification_cases`
- `partner_matches` (separate table)
- `claim_events`
- `payout_batches`

## Refactor constraints
Before MVP features:
- ✅ Do: migration support, SQL parameterization fixes, small targeted modularization for new logic.
- ❌ Avoid: large architecture rewrite into full layered backend.

---

## 3) Simplified DB scope for MVP

## Keep and reuse existing
- `users`, `bookmakers`, `bookmaker_accounts`, `claims`, `claim_attachments`, `payout_methods`, `payouts` (or pivot to `payout_requests` for MVP withdrawal flow), referral/audit where still useful.

## Minimal DB additions/changes
1. **`bookmaker_accounts` enhancements**
   - Add fields for tracked registration and verification metadata, e.g.:
     - `tracking_code` / `tracking_link`
     - `verification_status` (or reuse `status` with strict enum)
     - `verification_source` (`manual`, `partner_import`)
     - `verified_by_admin_id`, `verified_at`, `rejection_reason`
     - `last_import_batch_id` (nullable reference)

2. **`partner_import_batches`**
   - One row per manual upload/import run:
     - bookmaker_id, period/date metadata, uploaded_by, file name/checksum, created_at
     - optional summary counters (rows_total, rows_matched, rows_unmatched)

3. **`partner_player_rows`**
   - Normalized rows from imported partner data:
     - batch_id, bookmaker_id, imported_player_id, registration markers, activity markers
     - optional lightweight suggestion fields for admin assistance:
       - `suggested_user_id`, `suggested_bookmaker_account_id`, `match_confidence`, `match_reason`
   - Note: suggestions are for UI support only; not auto-verification.

4. **`payout_requests`**
   - User withdrawal requests:
     - user_id, requested_amount_rub, payout_method_id/address snapshot, status, admin_note, tx_hash, processed_by, processed_at

5. **`internal_notes`**
   - Admin notes attached to entity (`bookmaker_account`, `claim`, `payout_request`, etc.).

6. **`admin_audit_log`**
   - Explicit admin action log for verification and payout decisions.

## Not in MVP DB
- No dedicated workflow orchestration tables for verification/payout batching/event sourcing.

---

## 4) Updated phased implementation order

## Phase 0 — Safe foundation (small, required)
- Add SQL migration support (versioned migration files).
- Patch unsafe SQL interpolation (parameterize admin claim filters, etc.).
- Add minimal helper modules only where needed for new import/verification logic.

## Phase 1 — Bookmaker account verification foundation
- Update `bookmaker_accounts` schema + API so verification state is authoritative.
- Add endpoint to generate/get tracked bookmaker registration link per user-bookmaker.
- Update mini app bookmaker flow:
  - Select bookmaker
  - Get tracked link
  - Submit player_id
  - Show verification status badge (pending/verified/rejected)
- Enforce backend rule: claims can be submitted only for verified bookmaker account.

## Phase 2 — Partner import MVP (manual, bookmaker-specific)
- Admin uploads partner report manually.
- Parser is bookmaker-specific and normalizes data into `partner_player_rows`.
- Store import run metadata in `partner_import_batches`.
- Compute diff vs previous batch for same bookmaker (new/removed/changed players).
- Expose admin screen with verification candidates and confidence hints.
- Keep final verification action manual by admin.

## Phase 3 — Admin verification workflow (manual finalization)
- Admin UI/API for bookmaker account verification queue:
  - pending accounts
  - suggested matches from import rows
  - approve/reject with reason
- Write `internal_notes` and `admin_audit_log` entries for decisions.
- Notify user on verification result.

## Phase 4 — Claims and mini app gating integration
- Claims form uses verified bookmaker accounts only.
- If unverified account: show clear CTA to complete bookmaker verification flow.
- Keep existing claim risk scoring and attachment checks for MVP.
- Admin claims workflow remains mostly current, with minor UX alignment.

## Phase 5 — Payout request MVP
- Implement user withdrawal requests via `payout_requests` (manual admin processing).
- Admin UI/API for payout request review (approve/reject/process + tx hash).
- Update user wallet/withdrawal screen to show request statuses.
- Record all admin decisions in `admin_audit_log` and optional `internal_notes`.

---

## 5) Partner matching policy for MVP

- Matching is **decision support only**.
- System provides confidence suggestions (high/medium/low) using strong signals:
  - exact generated `subid` match
  - exact generated `clickid` match
  - exact submitted `player_id` match
  - bookmaker match
  - registration date proximity
- System must **not auto-verify bookmaker account by default**.
- Final verification is always explicit admin action in MVP.

---

## 6) Files/modules likely to change (MVP-focused)

### Database and migrations
- `backend/schema.sql` (keep bootstrap aligned)
- New migration files under `backend/migrations/*`

### Backend (targeted changes, no large rewrite)
- `backend/server.js` (new endpoints + gating + import handling)
- Optional small new modules for maintainability, e.g.:
  - `backend/lib/importParsers/*.js` (bookmaker-specific parsers)
  - `backend/lib/matching.js`
  - `backend/lib/bookmakerVerification.js`

### User mini app
- `frontend/index.html`
  - bookmaker registration link UX
  - player_id submit/status
  - claim gating by verification status
  - payout request status UX

### Admin panel
- `backend/admin/index.html`
  - partner import upload UI
  - verification candidates list
  - bookmaker account verify/reject actions
  - payout requests queue

---

## 7) What is postponed until post-MVP (explicit)

1. Full workflow decomposition into many specialized entities (`verification_cases`, `claim_events`, `partner_matches`, `payout_batches`).
2. Full async job platform with worker queues/retries/schedulers.
3. Broad backend architecture rewrite into complete routes/services/repositories layering.
4. Auto-finalizing verification based on matching confidence.
5. Advanced payout batching/orchestration and reconciliation subsystem.
6. Deep event-sourcing style audit/timeline model.

---

## 8) Migration strategy (MVP-safe)

1. Add migration tooling first (no behavior changes).
2. Introduce only additive schema changes for MVP tables/columns.
3. Backfill minimal defaults for existing `bookmaker_accounts` and claims gating compatibility.
4. Roll out verification gating behind feature flag:
   - soft-warning mode first
   - hard-block claims for unverified accounts after validation period
5. Release partner import/admin verification flow before enabling hard claim gating globally.
6. Ship payout_requests after verification+claims gating is stable.
