# CHECKPOINT 02 — Player ID Verification and Claim Eligibility

## Status
- Completed

## Goal
- Закрыть onboarding букмекера через отправку `player ID` и ручную верификацию в админке.
- Обеспечить, что claims доступны только для `verified` bookmaker account.
- Устранить SQL-ошибку при смене статуса верификации в admin queue.

## Final implementation
- Пользователь может отправить `player ID` из Mini App для выбранного букмекера.
- Запись попадает в `bookmaker_accounts` и отображается в admin verification queue.
- Админ может изменить статус аккаунта букмекера (включая `verified`).
- Статус верификации возвращается в Mini App и влияет на доступность claim flow.
- Claim submission остаётся доступным только после верификации аккаунта букмекера.
- Исправлена ошибка `inconsistent types deduced for parameter $1` в маршруте смены статуса:
  - SQL-параметры в `PATCH /admin/bookmaker-accounts/:id/status` разделены безопасно по контекстам.
- Milestone вручную проверен end-to-end.

## Changed files
- `backend/server.js`
- `frontend/index.html`
- `backend/admin/index.html`
- `project-docs/checkpoints/CHECKPOINT_02_PLAYER_ID_VERIFICATION_AND_CLAIM_ELIGIBILITY.md`

## Key prompt used
- "Fix admin bookmaker account status update error (`inconsistent types deduced for parameter $1`) while preserving verification flow and notifications."

## Important UX/business notes
- Пользовательский сценарий теперь прозрачен: сначала `player ID` + `verified`, потом claim.
- Операторская верификация остаётся ручным контролем качества перед открытием claim eligibility.
- Ошибка смены статуса в админке больше не должна блокировать verification queue.

## Assumptions
- End-to-end проверка выполнена вручную по целевому сценарию: submit player ID -> verify in admin -> claim becomes available.
- Ручная проверка включала переход статуса в Mini App после действия админа.

## Known limitations
- Milestone подтверждён на текущем рабочем окружении; повторная проверка в каждом новом deploy остаётся обязательной.
- Отдельный cross-browser matrix для admin панели в этот checkpoint не включён.

## Next recommended step
- Добавить короткий регресс-набор smoke-check для verification queue:
  1. submit `player ID` в Mini App;
  2. `verified` в admin;
  3. проверить доступность claim;
  4. проверить `rejected` сценарий и сообщение пользователю.
