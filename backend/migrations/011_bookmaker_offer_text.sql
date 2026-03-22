-- Fill offer_text for existing bookmakers (only where it's currently NULL)
UPDATE bookmakers SET offer_text = 'Фрибет до 10 000 ₽' WHERE short_name = '1X' AND offer_text IS NULL;
UPDATE bookmakers SET offer_text = 'Фрибет до 15 000 ₽' WHERE short_name = 'FB' AND offer_text IS NULL;
UPDATE bookmakers SET offer_text = 'Бонус 100% на депозит' WHERE short_name = 'BC' AND offer_text IS NULL;
UPDATE bookmakers SET offer_text = 'Фрибет до 10 000 ₽' WHERE short_name = 'MB' AND offer_text IS NULL;
UPDATE bookmakers SET offer_text = 'Фрибет 2 000 ₽' WHERE short_name = 'BB' AND offer_text IS NULL;
