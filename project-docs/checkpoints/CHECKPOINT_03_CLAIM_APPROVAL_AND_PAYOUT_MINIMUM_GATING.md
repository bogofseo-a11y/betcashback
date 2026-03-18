# CHECKPOINT 03 — Claim Approval and Payout Minimum Gating

## Status
- Completed

## Goal
- Подтвердить рабочий контур: отправка claim для `verified` букмекера, одобрение в админке, возврат approved-баланса в Mini App и корректное min-payout gating.

## Final implementation
- Пользователь может отправить claim из Mini App для `verified` bookmaker account.
- Claim появляется в admin claims queue.
- Админ может одобрить claim.
- Approved cashback/баланс отображается обратно в Mini App.
- Если approved amount ниже минимального порога выплаты, payout request недоступен.
- Disabled действие payout request в этом кейсе является ожидаемым поведением.
- Milestone вручную проверен.

## Changed files
- `backend/server.js`
- `frontend/index.html`
- `backend/admin/index.html`
- `project-docs/checkpoints/CHECKPOINT_03_CLAIM_APPROVAL_AND_PAYOUT_MINIMUM_GATING.md`

## Key prompt used
- "Verify claim approval flow and payout minimum gating, ensuring payout request stays disabled below threshold."

## Important UX/business notes
- Gating по минимальной сумме защищает от преждевременного запроса на выплату.
- Пользователь видит, что claim обработан, но payout action остаётся заблокирован до достижения минимума.
- Для оператора это ожидаемая бизнес-логика, а не ошибка UI.

## Assumptions
- Ручная проверка выполнена по целевому сценарию: verified claim -> admin approve -> approved balance visible -> payout action disabled below minimum.

## Known limitations
- Проверка зафиксирована как ручная; автоматизированный e2e тест для этого сценария в checkpoint не добавлялся.
- Порог minimum payout считается текущим значением из backend/app settings и должен контролироваться при каждом релизе.

## Next recommended step
- Провести дополнительный smoke-check для сценария выше порога:
  1. довести approved balance до/выше minimum;
  2. убедиться, что payout request становится доступным;
  3. проверить создание payout request и отображение в admin queue.
