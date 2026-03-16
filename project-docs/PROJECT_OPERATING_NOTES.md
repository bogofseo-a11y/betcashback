# BetCashback — Project Operating Notes

## Repository snapshot (for owner)
- `frontend/index.html` — Mini App (bookmakers, player ID, claims, payout requests).
- `backend/server.js` — backend API and business rules.
- `backend/admin/index.html` — admin panel (bookmakers, verification, imports, claims, payouts, notes).
- `backend/schema.sql` + `backend/migrations/*` — DB structure/evolution.

## Branch model: when to use `main` vs `codex`
- `main`: только стабильное состояние (release-ready).
- `codex`: рабочая ветка для задач через Codex (сейчас активная ветка проекта).
- Практика:
  - не делать прямые risky-правки в `main`;
  - завершать задачу в `codex`, проверять, затем переносить в `main` через ваш обычный merge flow.
- TODO: зафиксировать формальную branch policy команды (например, отдельные `codex/<task>` ветки для параллельной работы).

## Recommended working loop with ChatGPT + Codex
1. Вы формулируете задачу: цель, ограничения, “что считаем готово”.
2. ChatGPT помогает уточнить scope и check-список проверки (если нужно).
3. Codex делает диагностику, затем минимальные правки.
4. Codex возвращает: что изменено, root cause, ручные тесты.
5. Вы проходите ручные тесты по факту (Mini App + admin panel).
6. Если ок: создаёте checkpoint в `project-docs/checkpoints/`.
7. После этого делаете merge/deploy.

## After Codex finishes a task
1. Прочитать summary от Codex.
2. Отправить результат в ChatGPT на быстрый review.
3. Если review ок, сделать commit в ветке `codex`.
4. Push ветки `codex` в remote.
5. Сделать merge/PR в `main` по вашему обычному процессу.
6. Подтвердить commit SHA в `main`.
7. Проверить, что Render задеплоил именно этот SHA.
8. Прогнать ручной smoke test Mini App + admin panel.

## Deploy / environment notes
- Минимальные обязательные env: `BOT_TOKEN`, `DATABASE_URL`, `ADMIN_SECRET`, `ADMIN_CHAT_ID`, `NODE_ENV`, `PORT`.
- Источник шаблона env: `backend/env.example`.
- В `NODE_ENV=development` включён auth bypass для Mini App: в production использовать нельзя.
- `PORT` обычно выставляется хостингом автоматически (не фиксировать вручную без необходимости).
- TODO: добавить ссылку на реальный deploy runbook (кто деплоит, кто аппрувит, как делать rollback).

## Manual tests after deploy (owner-friendly)
1. Открыть `TODO_BACKEND_URL/health` -> должен вернуть `ok`.
2. В Mini App:
   - список букмекеров загружается;
   - “Зарегистрироваться” открывает ссылку, а не `load failed`;
   - отправка `player ID` сохраняется.
3. В admin panel:
   - виден verification queue;
   - можно изменить статус bookmaker account.
4. Проверить gate claims:
   - у `unverified` claim не должен проходить;
   - у `verified` claim должен создаваться.
5. Проверить payout:
   - пользователь создаёт payout request;
   - админ меняет статус, для `paid` указывает `tx_hash`.

## When to create a checkpoint
- После каждого важного milestone (не реже чем после каждой завершённой задачи, влияющей на продуктовый flow).
- Перед merge в `main`.
- После deploy (с фиксацией smoke test результата).
- После инцидента/горячего фикса.

## Do not panic: common issues
### Branch confusion
- Симптом: непонятно, где последние правки.
- Действие: проверить текущую ветку и `git status`; убедиться, что работа идёт в `codex`, а `main` остаётся чистой.

### Render deployed old commit
- Симптом: изменения есть в git, но на проде старая версия.
- Действие: проверить SHA последнего деплоя в Render и сравнить с локальным commit SHA, затем перезапустить deploy нужного коммита.

### Mini App shows backend error
- Симптом: в Mini App текст `Ошибка: {...}`.
- Действие: читать текст ошибки как реальную причину; частый кейс — у букмекера не заполнен `affiliate_url_template`.

### Admin works but Mini App does not
- Симптом: админка доступна, Mini App падает/не грузит данные.
- Действие: проверить `BOT_TOKEN`, `BACKEND_URL`, Telegram WebApp initData path и CORS/доступность `/api/*` с прод-URL.

## Important product URLs / placeholders
- Backend URL: `TODO_BACKEND_URL`
- Mini App URL: `TODO_FRONTEND_URL`
- Admin panel URL: `TODO_ADMIN_PANEL_URL` (обычно `TODO_BACKEND_URL/admin-panel`)
- Telegram bot: `https://t.me/TODO_BOT_USERNAME`
- Health check: `TODO_BACKEND_URL/health`

## TODO values to fill manually
- `TODO_PROJECT_OWNER`
- `TODO_TECH_OWNER`
- `TODO_RELEASE_APPROVER`
- `TODO_SUPPORT_CONTACT`
- `TODO_INCIDENT_CHANNEL`
- `TODO_RENDER_SERVICE_URL`
- `TODO_NEON_PROJECT_URL`
- `TODO_ANALYTICS_DASHBOARD_URL`
- `TODO_ROLLBACK_RUNBOOK_URL`
