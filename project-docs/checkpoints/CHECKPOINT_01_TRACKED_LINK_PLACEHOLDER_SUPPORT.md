# CHECKPOINT 01 — Tracked Link Placeholder Support

## Status
- Completed

## Goal
- Добавить поддержку placeholder-шаблонов в `affiliate_url_template` для tracked registration links.
- Сохранить обратную совместимость со старым param-based режимом.
- Стабилизировать сохранение bookmaker-конфига с placeholders в admin.

## Final implementation
- В runtime генерации ссылок поддержаны placeholders:
  - `{subid}`
  - `{clickid}`
- Поддержан partner-style шаблон вида:
  - `https://refpa14435.com/L?tag=s_5364725m_1234c_{subid}&site=5364725&ad=1234`
- Если placeholder для токена есть в шаблоне, используется замена в шаблоне.
- Если placeholder отсутствует, сохраняется старое поведение через `searchParams.set(...)`.
- Событие генерации ссылки сохраняется в `bookmaker_link_generations` с `generated_subid` / `generated_clickid` / `final_url`.
- Валидация шаблона для save-пути сделана parser-safe для `{subid}` / `{clickid}`.
- В admin save-пути добавлены targeted diagnostics и более явная error-сигнализация, чтобы вместо "Load failed" видеть причину.

## Changed files
- `backend/server.js`
- `backend/admin/index.html`
- `project-docs/checkpoints/CHECKPOINT_01_TRACKED_LINK_PLACEHOLDER_SUPPORT.md`

## Key prompt used
- "Support placeholder-based tracked link generation for affiliate URL templates"
- "Add targeted diagnostics and safe error handling for admin bookmaker save with placeholder templates"

## Important UX/business notes
- Конфиги с placeholders теперь поддержаны для MVP-партнёрских URL, где динамична только часть значения параметра.
- Старые конфиги без placeholders продолжают работать.
- Для операционной проверки admin-save сейчас использовать Chrome как основной браузер.
- Safari в ходе отладки показывал нестабильное поведение сохранения; не использовать как primary admin test browser на текущем этапе.

## Assumptions
- Ручная проверка в БД подтверждает корректное сохранение `generated_subid` и `final_url` для generation events.
- Placeholder-формат ограничен literal значениями `{subid}` и `{clickid}`.

## Known limitations
- Safari поведение сохранения в admin остаётся менее предсказуемым, чем в Chrome.
- Нужен отдельный follow-up на кросс-браузерную диагностику admin save (если Safari обязателен для оператора).

## Next recommended step
- Провести короткий регресс smoke-check в Chrome:
  1. Сохранить bookmaker с placeholder-шаблоном.
  2. Сгенерировать ссылку в Mini App.
  3. Проверить запись в `bookmaker_link_generations` (`generated_subid`, `final_url`).
  4. Проверить, что старый param-based букмекер работает без изменений.
