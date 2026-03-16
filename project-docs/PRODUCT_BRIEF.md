# BetCashback — Product Brief

## Product overview
BetCashback — это Telegram Mini App и админ-панель для возврата части проигрыша у букмекеров.  
Ключевой принцип MVP: верификация идёт по связке `(user_id, bookmaker_id)`, а не по отдельной claim-заявке.

## Target user
- Пользователь Telegram, который делает ставки у поддерживаемых букмекеров.
- Готов пройти onboarding: регистрация по ссылке -> отправка `player ID` -> ожидание верификации.
- Хочет простой сценарий “проиграл -> подал заявку -> получил выплату”.

## Core value proposition
- Cashback по подтверждённым правилам (текущая tier-логика: 5% / 7% / 10%).
- Прозрачные статусы по каждому шагу: bookmaker account, claim, payout request.
- Весь путь в Telegram Mini App + понятная ручная обработка через admin panel.

## Why users should trust the product
- Claim нельзя подать без `verified` bookmaker account, поэтому процесс не строится на “самоподтверждении”.
- Пользователь видит понятные статусы: по аккаунту букмекера, заявке и выплате.
- Ключевые решения в MVP делаются вручную оператором (verification, claim review, payout processing).
- Выплата идёт через явный payout request flow со статусами и проверкой в админке.
- Операционная прозрачность есть через notes/audit и предсказуемый support-процесс (TODO: зафиксировать публичный канал поддержки).

## Main user flow (current MVP)
1. Пользователь открывает Mini App.
2. Выбирает букмекера.
3. Нажимает “Зарегистрироваться” и получает tracked link (`/api/bookmakers/:id/generate-link`).
4. Регистрируется у букмекера по этой ссылке.
5. Возвращается в Mini App и отправляет `player ID` (`/api/bookmaker-accounts`).
6. Ждёт ручную верификацию аккаунта букмекера админом (`pending` -> `verified`/`rejected`).
7. После `verified` подаёт claim со скриншотами (`/api/claims`).
8. Админ проверяет claim и выставляет статус.
9. Одобренный баланс становится доступен для вывода.
10. Пользователь создаёт payout request, админ обрабатывает выплату вручную.

## Main admin flow (current MVP)
1. Bookmaker CRUD: создать/редактировать/активировать букмекера.
2. Проверить, что у букмекера заполнены `affiliate_url_template` и tracking-настройки.
3. Вести queue bookmaker account verification (`pending`/`verified`/`rejected`).
4. Загружать partner CSV imports.
5. Смотреть partner match suggestions и использовать их как decision support.
6. Финально верифицировать/отклонять аккаунт вручную (без auto-verify по умолчанию).
7. Модерировать claim-заявки и вести internal notes.
8. Обрабатывать payout requests вручную, включая `tx_hash` для `paid`.

## Current admin building blocks in MVP
- Bookmaker CRUD.
- Bookmaker verification queue.
- Partner imports.
- Partner match suggestions.
- Internal notes (claim / bookmaker account / payout request).
- Payout request processing.

## Monetization / business logic (high-level)
- Основа: affiliate-модель через tracked registration links (`subid` / `clickid` / `subid_clickid`).
- Cashback начисляется по внутренним правилам продукта и статусам claim.
- Реферальная модель присутствует в Mini App (текущая формулировка: 20% от cashback рефералов).
- TODO: зафиксировать финальную unit-экономику (маржа сервиса, комиссии вывода, лимиты).

## Trust / risk considerations
- Проверка Telegram init data на backend.
- Backend gate: claim доступен только для `verified` bookmaker account.
- Валидации файлов/формы + rate limit API.
- Risk score для claim и ручная админ-модерация.
- Notes и audit-след в операционных действиях.
- Payout остаётся ручным процессом в MVP.

## Current MVP scope
- Mini App: bookmakers list, tracked register link, player ID submit, claims, payout requests.
- Admin: bookmakers, verification, imports/suggestions, claim moderation, payout queue.
- Database/API: опора на `bookmaker_accounts`, `bookmaker_link_generations`, `claims`, `payout_requests`.

## Post-MVP opportunities
- Больше автоматизации проверки без потери контроля на риск-кейсах.
- Улучшенная операционная аналитика воронки.
- Более детальная продуктовая аналитика по каждому букмекеру.
- Расширение payout-способов и SLA-автоматизация.

## Open questions / TODOs
- TODO: финальный список букмекеров для soft launch.
- TODO: кто финально принимает решение `go/no-go` по full launch.
- TODO: подтверждённые KPI soft launch (verified conversion, claim approve rate, payout SLA).
- TODO: юридические тексты (disclaimer, privacy, terms) и где они показываются пользователю.
- TODO: финальные контакты поддержки для Mini App и операторов.
