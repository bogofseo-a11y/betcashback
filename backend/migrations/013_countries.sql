BEGIN;

-- Таблица стран
CREATE TABLE IF NOT EXISTS countries (
  code VARCHAR(2) PRIMARY KEY,          -- ISO 3166-1 alpha-2: RU, KZ, BY...
  name VARCHAR(100) NOT NULL,           -- Название на русском
  flag VARCHAR(10) NOT NULL,            -- Эмодзи флаг: 🇷🇺
  currency VARCHAR(3) NOT NULL,         -- Код валюты: RUB, KZT, BYN, USD
  currency_symbol VARCHAR(5) NOT NULL,  -- Символ: ₽, ₸, Br, $
  language_code VARCHAR(5) NOT NULL,    -- Telegram language_code для автодетекта: ru, kk, be...
  sort_order INTEGER DEFAULT 0,         -- Порядок в списке
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Заполняем 9 стран СНГ
INSERT INTO countries (code, name, flag, currency, currency_symbol, language_code, sort_order)
VALUES
  ('RU', 'Россия',       '🇷🇺', 'RUB', '₽',  'ru', 1),
  ('KZ', 'Казахстан',    '🇰🇿', 'KZT', '₸',  'kk', 2),
  ('BY', 'Беларусь',     '🇧🇾', 'BYN', 'Br', 'be', 3),
  ('UZ', 'Узбекистан',   '🇺🇿', 'USD', '$',  'uz', 4),
  ('KG', 'Кыргызстан',   '🇰🇬', 'USD', '$',  'ky', 5),
  ('TJ', 'Таджикистан',  '🇹🇯', 'USD', '$',  'tg', 6),
  ('AM', 'Армения',      '🇦🇲', 'USD', '$',  'hy', 7),
  ('GE', 'Грузия',       '🇬🇪', 'USD', '$',  'ka', 8),
  ('AZ', 'Азербайджан',  '🇦🇿', 'USD', '$',  'az', 9)
ON CONFLICT (code) DO NOTHING;

-- Добавляем country_code к юзерам (nullable — у существующих юзеров пока NULL)
ALTER TABLE users ADD COLUMN IF NOT EXISTS country_code VARCHAR(2) REFERENCES countries(code);

-- Таблица bookmaker_countries (many-to-many, на будущее — пока не используем для фильтрации)
CREATE TABLE IF NOT EXISTS bookmaker_countries (
  bookmaker_id INTEGER REFERENCES bookmakers(id) ON DELETE CASCADE,
  country_code VARCHAR(2) REFERENCES countries(code) ON DELETE CASCADE,
  PRIMARY KEY (bookmaker_id, country_code)
);

COMMIT;
