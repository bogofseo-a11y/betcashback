# CHECKPOINT 05 — Payout Notifications And Mini App Refresh

## Status
- Completed

## Goal
- Восстановить Telegram-уведомления при создании payout request и улучшить авто-обновление Mini App состояния (claims + home/profile summary) без полного reload.

## Final implementation
- Новый payout request снова отправляет Telegram-уведомление в admin chat.
- Новый payout request снова отправляет Telegram-уведомление пользователю.
- Статусы claim в Mini App обновляются без полного перезапуска страницы.
- Home/Profile summary в Mini App обновляется без полного перезапуска страницы.
- Применена MVP-safe стратегия обновления: события экрана/фокуса/видимости (без websocket realtime).
- Milestone вручную проверен после deploy.

## Changed files
- `backend/server.js`
- `frontend/index.html`
- `project-docs/checkpoints/CHECKPOINT_05_PAYOUT_NOTIFICATIONS_AND_MINIAPP_REFRESH.md`

## Key prompt used
- "Restore payout request notification and make claim/home state refresh without full reload."

## Important UX/business notes
- Уведомления о payout request снова работают в обе стороны (оператор и пользователь) и остаются best-effort, не блокируя бизнес-операцию.
- Пользователь теперь видит более актуальные статусы claim и сводку без ручного обновления страницы.
- Выбран событийный refresh-подход для MVP: низкий риск, без внедрения realtime-инфраструктуры.

## Assumptions
- `ADMIN_CHAT_ID` и BOT конфигурация корректно заданы в production окружении.
- Ручная постдеплой-проверка покрыла создание payout request и обновление claim/home состояния при возврате фокуса/открытии нужных экранов.

## Known limitations
- Обновление не realtime push: изменения подтягиваются по событиям (screen open / focus / visibility).
- При длительном отсутствии пользователь увидит обновление при следующем релевантном событии, а не мгновенно.

## Next recommended step
- Добавить короткий release smoke-check:
- создать payout request и подтвердить оба Telegram-уведомления;
- сменить статус claim в admin и подтвердить auto-refresh в Mini App при focus/visibility/screen open.
