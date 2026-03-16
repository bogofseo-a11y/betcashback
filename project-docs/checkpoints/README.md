# Checkpoints README

## Why checkpoints exist
Checkpoint-файлы нужны, чтобы фиксировать состояние проекта по этапам:
- что уже готово;
- что ещё не закрыто;
- что проверено руками;
- какие риски или блокеры остались.

Это снижает хаос в запуске и упрощает коммуникацию между продуктом, оператором и разработкой.

## When to create a checkpoint
Создавайте checkpoint:
- после каждого важного milestone (обязательно, не пропускать);
- после завершения заметной задачи (например, “починили регистрацию букмекера”);
- перед soft launch и перед full launch;
- после инцидента или горячего фикса;
- в конце недели, если идёт активная подготовка к релизу.
- Когда практично, коммитьте checkpoint в репозиторий вместе с изменениями этого milestone.

## Where checkpoint files must live
- Все checkpoint-файлы хранятся только в `project-docs/checkpoints/`.
- Не хранить checkpoint в корне репозитория или в случайных папках.

## Recommended filename format (with numeric order)
Используйте формат:

`NN_YYYY-MM-DD_short-topic.md`

Примеры:
- `01_2026-03-16_register-link-fix.md`
- `02_2026-03-17_verified-claim-gating-check.md`
- `03_2026-03-18_soft-launch-readiness.md`

## Required sections in every checkpoint
Каждый checkpoint должен содержать ровно эти секции:
1. **Status**
2. **Goal**
3. **Final implementation**
4. **Changed files**
5. **Key prompt used**
6. **Important UX/business notes**
7. **Assumptions**
8. **Known limitations**
9. **Next recommended step**

## Suggested checkpoint template
```md
# <Checkpoint title>

## Status
- Completed / Partially completed / Blocked

## Goal
- Что именно хотели получить

## Final implementation
- Что в итоге реализовано

## Changed files
- <file path 1>
- <file path 2>

## Key prompt used
- Ключевой prompt/инструкция для Codex

## Important UX/business notes
- Важные последствия для пользователя или оператора

## Assumptions
- Какие допущения были сделаны

## Known limitations
- Что пока не покрыто

## Next recommended step
- Следующий практический шаг
```

## Short example milestone list for BetCashback
- Milestone 1: Bookmaker onboarding flow stable (`generate-link`, `player ID`, статус).
- Milestone 2: Claim flow stable (submit -> admin review -> user status updates).
- Milestone 3: Import + verification operations stable (CSV + manual verification).
- Milestone 4: Payout flow stable (request -> processing -> paid/rejected).
- Milestone 5: Soft launch readiness confirmed.
- Milestone 6: Full launch readiness confirmed.
