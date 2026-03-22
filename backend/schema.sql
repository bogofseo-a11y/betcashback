-- BetCashback Database Schema
-- Run this in your PostgreSQL database

-- COUNTRIES
CREATE TABLE IF NOT EXISTS countries (
  code VARCHAR(2) PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  flag VARCHAR(10) NOT NULL,
  currency VARCHAR(3) NOT NULL,
  currency_symbol VARCHAR(5) NOT NULL,
  language_code VARCHAR(5) NOT NULL,
  sort_order INTEGER DEFAULT 0,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- USERS
CREATE TABLE IF NOT EXISTS users (
  id BIGINT PRIMARY KEY, -- telegram_id
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100),
  username VARCHAR(100),
  referrer_id BIGINT REFERENCES users(id),
  country_code VARCHAR(2) REFERENCES countries(code),
  is_banned BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- BOOKMAKERS
CREATE TABLE IF NOT EXISTS bookmakers (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  short_name VARCHAR(10),
  logo_url TEXT,
  rules TEXT,
  required_proofs TEXT[], -- e.g. ['slip', 'profile']
  min_loss_rub INTEGER DEFAULT 500,
  is_active BOOLEAN DEFAULT TRUE,
  sort_order INTEGER DEFAULT 0,
  affiliate_url_template TEXT,
  tracking_mode VARCHAR(30) DEFAULT 'none' CHECK (tracking_mode IN ('none', 'subid', 'clickid', 'subid_clickid')), -- none, subid, clickid, subid_clickid
  tracking_subid_param VARCHAR(50) DEFAULT 'subid',
  tracking_clickid_param VARCHAR(50) DEFAULT 'clickid',
  offer_text TEXT,
  cashback_label VARCHAR(100),
  instruction_asset_url TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- BOOKMAKER COUNTRIES (many-to-many)
CREATE TABLE IF NOT EXISTS bookmaker_countries (
  bookmaker_id INTEGER REFERENCES bookmakers(id) ON DELETE CASCADE,
  country_code VARCHAR(2) REFERENCES countries(code) ON DELETE CASCADE,
  PRIMARY KEY (bookmaker_id, country_code)
);

-- BOOKMAKER ACCOUNTS (user's accounts at bookmakers)
CREATE TABLE IF NOT EXISTS bookmaker_accounts (
  id SERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
  bookmaker_id INTEGER REFERENCES bookmakers(id),
  affiliate_player_id VARCHAR(200),
  status VARCHAR(20) DEFAULT 'pending', -- pending, verified, rejected
  verification_source VARCHAR(30), -- manual, partner_import
  verified_by_admin_id BIGINT,
  verified_at TIMESTAMPTZ,
  rejected_at TIMESTAMPTZ,
  rejection_reason TEXT,
  last_import_batch_id BIGINT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, bookmaker_id)
);

-- BOOKMAKER LINK GENERATIONS
CREATE TABLE IF NOT EXISTS bookmaker_link_generations (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
  bookmaker_id INTEGER REFERENCES bookmakers(id) ON DELETE CASCADE,
  bookmaker_account_id INTEGER REFERENCES bookmaker_accounts(id) ON DELETE SET NULL,
  affiliate_url_template_snapshot TEXT,
  tracking_mode VARCHAR(30) DEFAULT 'none',
  generated_subid VARCHAR(200),
  generated_clickid VARCHAR(200),
  final_url TEXT NOT NULL,
  generation_context VARCHAR(30) DEFAULT 'manual_open', -- manual_open, reconnect, reverify
  metadata_json JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- PARTNER IMPORT BATCHES
CREATE TABLE IF NOT EXISTS partner_import_batches (
  id BIGSERIAL PRIMARY KEY,
  bookmaker_id INTEGER REFERENCES bookmakers(id) ON DELETE CASCADE,
  uploaded_by_admin_id BIGINT, -- stored as BIGINT identifier; no FK (no admins table yet)
  source_name VARCHAR(120), -- e.g. CSV, XLSX, API_EXPORT
  original_filename TEXT,
  file_checksum VARCHAR(128),
  period_from DATE,
  period_to DATE,
  rows_total INTEGER DEFAULT 0,
  rows_new INTEGER DEFAULT 0,
  rows_changed INTEGER DEFAULT 0,
  rows_unchanged INTEGER DEFAULT 0,
  status VARCHAR(20) DEFAULT 'uploaded' CHECK (status IN ('uploaded', 'processed', 'failed')), -- uploaded, processed, failed
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  processed_at TIMESTAMPTZ
);

-- PARTNER PLAYER ROWS
CREATE TABLE IF NOT EXISTS partner_player_rows (
  id BIGSERIAL PRIMARY KEY,
  batch_id BIGINT REFERENCES partner_import_batches(id) ON DELETE CASCADE,
  bookmaker_id INTEGER REFERENCES bookmakers(id) ON DELETE CASCADE,
  external_row_id VARCHAR(200),
  imported_player_id VARCHAR(200),
  imported_subid VARCHAR(200),
  imported_clickid VARCHAR(200),
  registration_date TIMESTAMPTZ,
  last_activity_at TIMESTAMPTZ,
  total_deposit_rub DECIMAL(12,2),
  total_ggr_rub DECIMAL(12,2),
  raw_payload_json JSONB,
  is_diff_new BOOLEAN DEFAULT FALSE,
  is_diff_changed BOOLEAN DEFAULT FALSE,
  prev_row_id BIGINT REFERENCES partner_player_rows(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- CLAIMS
CREATE TABLE IF NOT EXISTS claims (
  id SERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id),
  bookmaker_id INTEGER REFERENCES bookmakers(id),
  bookmaker_account_id INTEGER REFERENCES bookmaker_accounts(id),
  affiliate_player_id VARCHAR(200),
  loss_amount_rub DECIMAL(12,2) NOT NULL,
  bet_id VARCHAR(200),
  bet_date DATE,
  comment TEXT,
  status VARCHAR(20) DEFAULT 'submitted',
  -- submitted → in_review → approved / rejected → paid
  cashback_percent DECIMAL(5,2) NOT NULL,
  cashback_amount_rub DECIMAL(12,2) NOT NULL,
  risk_score INTEGER DEFAULT 0, -- 0-100
  admin_note TEXT,
  tx_hash VARCHAR(200),
  payout_method_id INTEGER,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- CLAIM ATTACHMENTS
CREATE TABLE IF NOT EXISTS claim_attachments (
  id SERIAL PRIMARY KEY,
  claim_id INTEGER REFERENCES claims(id) ON DELETE CASCADE,
  file_url TEXT NOT NULL,
  file_hash VARCHAR(64),
  mime_type VARCHAR(100),
  file_size_bytes INTEGER,
  is_duplicate BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- PAYOUT METHODS
CREATE TABLE IF NOT EXISTS payout_methods (
  id SERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id),
  type VARCHAR(20) DEFAULT 'external', -- external / telegram_wallet
  asset VARCHAR(30) NOT NULL, -- USDT_TRC20, USDT_TON, TON, TG_WALLET
  address TEXT NOT NULL,
  is_default BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- PAYOUT REQUESTS (MVP withdrawal workflow)
CREATE TABLE IF NOT EXISTS payout_requests (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id),
  payout_method_id INTEGER REFERENCES payout_methods(id),
  amount_rub DECIMAL(12,2) NOT NULL,
  asset VARCHAR(30),
  address_snapshot TEXT,
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'processing', 'paid', 'failed')), -- pending, approved, rejected, processing, paid, failed
  admin_note TEXT,
  tx_hash VARCHAR(200),
  processed_by_admin_id BIGINT, -- stored as BIGINT identifier; no FK (no admins table yet)
  processed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- PAYOUTS (legacy/current table kept for backward compatibility)
CREATE TABLE IF NOT EXISTS payouts (
  id SERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id),
  claim_id INTEGER REFERENCES claims(id),
  amount_rub DECIMAL(12,2) NOT NULL,
  asset VARCHAR(30) NOT NULL,
  address TEXT,
  payout_method_id INTEGER REFERENCES payout_methods(id),
  status VARCHAR(20) DEFAULT 'pending', -- pending / sent / confirmed / failed
  tx_hash VARCHAR(200),
  batch_date DATE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- SUPPORT TICKETS (MVP)
CREATE TABLE IF NOT EXISTS support_tickets (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'waiting_user', 'closed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  closed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS support_ticket_messages (
  id BIGSERIAL PRIMARY KEY,
  ticket_id BIGINT NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
  sender_type VARCHAR(10) NOT NULL CHECK (sender_type IN ('user', 'admin')),
  sender_admin_id BIGINT,
  message TEXT NOT NULL,
  attachments_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- REFERRAL LEDGER
CREATE TABLE IF NOT EXISTS referral_ledger (
  id SERIAL PRIMARY KEY,
  referrer_user_id BIGINT REFERENCES users(id),
  referred_user_id BIGINT REFERENCES users(id),
  claim_id INTEGER REFERENCES claims(id),
  level INTEGER NOT NULL, -- 1 or 2
  amount_rub DECIMAL(12,2) NOT NULL,
  status VARCHAR(20) DEFAULT 'pending', -- pending / paid
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(referrer_user_id, claim_id, level)
);

-- INTERNAL NOTES
CREATE TABLE IF NOT EXISTS internal_notes (
  id BIGSERIAL PRIMARY KEY,
  entity_type VARCHAR(40) NOT NULL, -- bookmaker_account, claim, payout_request, import_batch
  entity_id BIGINT NOT NULL,
  note TEXT NOT NULL,
  is_private BOOLEAN DEFAULT TRUE,
  created_by_admin_id BIGINT, -- stored as BIGINT identifier; no FK (no admins table yet)
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- PARTNER MATCH SUGGESTIONS (bookmaker_account <-> imported partner row)
CREATE TABLE IF NOT EXISTS partner_match_suggestions (
  id BIGSERIAL PRIMARY KEY,
  bookmaker_account_id INTEGER REFERENCES bookmaker_accounts(id) ON DELETE CASCADE,
  partner_player_row_id BIGINT REFERENCES partner_player_rows(id) ON DELETE CASCADE,
  confidence_score INTEGER NOT NULL DEFAULT 0,
  confidence_level VARCHAR(20) NOT NULL DEFAULT 'low', -- low, medium, high
  reasons TEXT[],
  suggestion_payload_json JSONB,
  is_selected BOOLEAN DEFAULT FALSE,
  selected_by_admin_id BIGINT, -- stored as BIGINT identifier; no FK (no admins table yet)
  selected_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(bookmaker_account_id, partner_player_row_id)
);

-- ADMIN AUDIT LOG
CREATE TABLE IF NOT EXISTS admin_audit_log (
  id BIGSERIAL PRIMARY KEY,
  admin_id BIGINT, -- stored as BIGINT identifier; no FK (no admins table yet)
  action VARCHAR(120) NOT NULL,
  entity_type VARCHAR(50),
  entity_id BIGINT,
  payload_json JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- APP SETTINGS
CREATE TABLE IF NOT EXISTS app_settings (
  key VARCHAR(100) PRIMARY KEY,
  value TEXT NOT NULL,
  value_type VARCHAR(20) NOT NULL DEFAULT 'string', -- string, number, boolean, json
  description TEXT,
  updated_by_admin_id BIGINT, -- stored as BIGINT identifier; no FK (no admins table yet)
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- AUDIT LOG (legacy/current)
CREATE TABLE IF NOT EXISTS audit_log (
  id SERIAL PRIMARY KEY,
  actor_type VARCHAR(20) NOT NULL, -- user / admin / system
  actor_id BIGINT,
  action VARCHAR(100) NOT NULL,
  entity VARCHAR(50),
  entity_id BIGINT,
  payload_json JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- SEED COUNTRIES
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

-- DEFAULT SETTINGS
INSERT INTO app_settings (key, value, value_type, description)
VALUES ('min_payout_amount_rub', '500', 'number', 'Minimum payout amount in RUB')
ON CONFLICT (key) DO NOTHING;

-- SEED DEFAULT BOOKMAKERS
INSERT INTO bookmakers (name, short_name, rules, min_loss_rub, sort_order) VALUES
  ('1xBet', '1X', 'Кэшбэк до 10% от проигрышей. Для заявки нужен скриншот ставки и скрин личного кабинета.', 500, 1),
  ('Fonbet', 'FB', 'Кэшбэк до 10% от проигрышей. Для заявки нужен скриншот ставки и история операций.', 500, 2),
  ('Betcity', 'BC', 'Кэшбэк до 10% от проигрышей. Для заявки нужен скриншот из личного кабинета.', 500, 3),
  ('Melbet', 'MB', 'Кэшбэк до 10% от проигрышей. Лимит 30 000 ₽ в месяц.', 500, 4),
  ('BetBoom', 'BB', 'Кэшбэк до 10% от проигрышей.', 500, 5)
ON CONFLICT DO NOTHING;

-- SAFE FK ADDITION (bookmaker_accounts -> partner_import_batches)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'fk_bookmaker_accounts_last_import_batch'
  ) THEN
    ALTER TABLE bookmaker_accounts
      ADD CONSTRAINT fk_bookmaker_accounts_last_import_batch
      FOREIGN KEY (last_import_batch_id)
      REFERENCES partner_import_batches(id)
      ON DELETE SET NULL;
  END IF;
END $$;

-- INDEXES
CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(id);
CREATE INDEX IF NOT EXISTS idx_users_referrer ON users(referrer_id);

CREATE INDEX IF NOT EXISTS idx_bookmaker_accounts_user_id ON bookmaker_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_bookmaker_accounts_bookmaker_id ON bookmaker_accounts(bookmaker_id);
CREATE INDEX IF NOT EXISTS idx_bookmaker_accounts_player_id ON bookmaker_accounts(affiliate_player_id);
CREATE INDEX IF NOT EXISTS idx_bookmaker_accounts_status ON bookmaker_accounts(status);

CREATE INDEX IF NOT EXISTS idx_link_gen_user_id ON bookmaker_link_generations(user_id);
CREATE INDEX IF NOT EXISTS idx_link_gen_bookmaker_id ON bookmaker_link_generations(bookmaker_id);
CREATE INDEX IF NOT EXISTS idx_link_gen_subid ON bookmaker_link_generations(generated_subid);
CREATE INDEX IF NOT EXISTS idx_link_gen_clickid ON bookmaker_link_generations(generated_clickid);

CREATE INDEX IF NOT EXISTS idx_partner_batches_bookmaker_id ON partner_import_batches(bookmaker_id);
CREATE INDEX IF NOT EXISTS idx_partner_rows_batch_id ON partner_player_rows(batch_id);
CREATE INDEX IF NOT EXISTS idx_partner_rows_bookmaker_id ON partner_player_rows(bookmaker_id);
CREATE INDEX IF NOT EXISTS idx_partner_rows_player_id ON partner_player_rows(imported_player_id);
CREATE INDEX IF NOT EXISTS idx_partner_rows_subid ON partner_player_rows(imported_subid);
CREATE INDEX IF NOT EXISTS idx_partner_rows_clickid ON partner_player_rows(imported_clickid);

CREATE INDEX IF NOT EXISTS idx_claims_user_id ON claims(user_id);
CREATE INDEX IF NOT EXISTS idx_claims_bookmaker_id ON claims(bookmaker_id);
CREATE INDEX IF NOT EXISTS idx_claims_status ON claims(status);
CREATE INDEX IF NOT EXISTS idx_claims_bet_id ON claims(bet_id);
CREATE INDEX IF NOT EXISTS idx_claim_attachments_hash ON claim_attachments(file_hash);

CREATE INDEX IF NOT EXISTS idx_payout_requests_user_id ON payout_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_payout_requests_status ON payout_requests(status);

CREATE INDEX IF NOT EXISTS idx_support_tickets_user_id ON support_tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON support_tickets(status);
CREATE INDEX IF NOT EXISTS idx_support_tickets_updated_at ON support_tickets(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_messages_ticket_id ON support_ticket_messages(ticket_id);
CREATE INDEX IF NOT EXISTS idx_support_messages_created_at ON support_ticket_messages(created_at);

CREATE INDEX IF NOT EXISTS idx_internal_notes_entity ON internal_notes(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_partner_match_suggestions_account ON partner_match_suggestions(bookmaker_account_id);
CREATE INDEX IF NOT EXISTS idx_partner_match_suggestions_row ON partner_match_suggestions(partner_player_row_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_entity ON admin_audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity, entity_id);
CREATE INDEX IF NOT EXISTS idx_referral_ledger_referrer ON referral_ledger(referrer_user_id);
