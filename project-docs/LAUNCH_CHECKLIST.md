# BetCashback — Launch Checklist (MVP)

## Pre-merge / deploy sanity
- [ ] Задача закрыта в рабочей ветке (`codex`) и не содержит лишних файлов.
- [ ] Создан checkpoint по задаче в `project-docs/checkpoints/`.
- [ ] После merge проверен commit SHA, который должен попасть в deploy.
- [ ] В Render/хостинге подтверждён deploy именно нужного SHA.

## Manual E2E smoke scenario
- [ ] Открыть Mini App.
- [ ] Открыть карточку букмекера.
- [ ] Нажать “Зарегистрироваться” и убедиться, что tracked link открывается.
- [ ] Отправить `player ID`.
- [ ] В админке верифицировать bookmaker account.
- [ ] Вернуться в Mini App и отправить claim.
- [ ] В админке одобрить claim.
- [ ] В Mini App создать payout request.
- [ ] В админке обработать payout request (для `paid` указать `tx_hash`).

## Product flow
- [ ] Пользователь видит список активных букмекеров в Mini App.
- [ ] Кнопка “Зарегистрироваться” вызывает generate-link и открывает URL без `load failed`.
- [ ] Отправка `player ID` работает и обновляет статус bookmaker account.
- [ ] Claim можно подать только для `verified` bookmaker account.
- [ ] Статусы claim и payout корректно отображаются в UI.

## UX / copy clarity
- [ ] Все критичные ошибки показываются понятным языком.
- [ ] Есть короткие инструкции “что делать дальше” после каждого шага.
- [ ] Тексты в модалке букмекера и claim-форме согласованы (без противоречий).
- [ ] FAQ/подсказки не содержат устаревших правил.

## Admin operations
- [ ] В админке доступно создание/редактирование букмекера.
- [ ] Есть доступ к verification queue, claims, payout requests, imports.
- [ ] Важные действия оставляют trace (internal notes/audit).
- [ ] Оператор знает стандартный ежедневный ритуал обработки очередей.

## Bookmaker onboarding flow
- [ ] Для каждого launch-букмекера заполнен `affiliate_url_template`.
- [ ] Для каждого launch-букмекера проверен `tracking_mode` и параметры трекинга.
- [ ] Тестовый клик по ссылке регистрации проходит для каждого launch-букмекера.
- [ ] Отправка `player ID` создаёт/обновляет bookmaker account по `(user, bookmaker)`.
- [ ] Статусы `pending/verified/rejected` видны и понятны в Mini App.

## Claim flow
- [ ] Валидации claim-формы отрабатывают ожидаемо (сумма, дата, bet ID, скриншоты).
- [ ] Загрузка файлов работает (тип/размер/лимиты).
- [ ] Claim создаётся в backend и появляется в admin queue.
- [ ] approve/reject flow в админке протестирован вручную.
- [ ] Verified-only gating проверен: `unverified` claim блокируется, `verified` проходит.

## Import / verification operations
- [ ] CSV импорт проходит без ошибки на реальном примере файла.
- [ ] Match suggestions формируются и отображаются оператору.
- [ ] Выбор suggestion не делает auto-verify без решения админа.
- [ ] verify/reject bookmaker account с причиной работает end-to-end.

## Payout operations
- [ ] Добавление payout method пользователем работает.
- [ ] Запрос на вывод создаётся только при достаточном доступном балансе.
- [ ] Запрос на вывод появляется в admin payout queue.
- [ ] В админке статус payout меняется по правилам transition.
- [ ] Для `paid` обязателен `tx_hash`.

## Notifications
- [ ] Пользователь получает уведомления о ключевых изменениях статусов.
- [ ] Ошибки отправки уведомлений не ломают бизнес-операцию.
- [ ] TODO: подтвердить финальные тексты уведомлений с продуктом.

## Internal notes
- [ ] Оператор может добавить и прочитать заметки по claim.
- [ ] Оператор может добавить и прочитать заметки по bookmaker account.
- [ ] Оператор может добавить и прочитать заметки по payout request.

## Tech / infra
- [ ] Заполнены production env values (`BOT_TOKEN`, `DATABASE_URL`, `ADMIN_SECRET`, и т.д.).
- [ ] Выполнены и проверены миграции на целевой БД.
- [ ] `health` endpoint доступен извне.
- [ ] Есть базовый rollback-план на случай неудачного deploy.
- [ ] После deploy проведён smoke test Mini App + admin panel.

## Support / ops
- [ ] Назначен owner линии поддержки.
- [ ] Есть шаблоны ответов на частые кейсы (link issue, pending verification, reject reason).
- [ ] Зафиксированы SLA по ответу пользователям и операторам.
- [ ] TODO: добавить канал эскалации инцидентов.

## Analytics / measurement
- [ ] Определены минимум KPI для soft launch.
- [ ] Есть способ собирать воронку: register click -> verified -> first claim -> first payout.
- [ ] Есть weekly review ритуал по качеству заявок и выплат.
- [ ] TODO: подтвердить источник truth для ключевых метрик.

## Legal / compliance placeholders
- [ ] TODO: финальный дисклеймер по правилам сервиса.
- [ ] TODO: privacy/terms ссылки и актуальные тексты.
- [ ] TODO: требования по хранению и доступу к данным пользователей.

## Soft launch readiness
- [ ] Пройдён smoke test на ограниченной группе пользователей.
- [ ] Нет блокирующих дефектов по onboarding/claims/payout.
- [ ] Операторы готовы к ручной нагрузке в первые дни.
- [ ] Есть список “go/no-go” критериев и owner решения.

## Full launch readiness
- [ ] Soft launch KPI достигнуты или принято осознанное исключение.
- [ ] Закрыты критичные TODO из product/ops/legal.
- [ ] Команда поддержки и операторы готовы к росту трафика.
- [ ] Утверждена дата full launch и коммуникационный план.
