-- BetCashback Database Schema
-- Run this in your PostgreSQL database

-- USERS
CREATE TABLE IF NOT EXISTS users (
  id BIGINT PRIMARY KEY, -- telegram_id
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100),
  username VARCHAR(100),
  referrer_id BIGINT REFERENCES users(id),
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
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- BOOKMAKER ACCOUNTS (user's accounts at bookmakers)
CREATE TABLE IF NOT EXISTS bookmaker_accounts (
  id SERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
  bookmaker_id INTEGER REFERENCES bookmakers(id),
  affiliate_player_id VARCHAR(200),
  status VARCHAR(20) DEFAULT 'pending', -- pending, verified, rejected
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, bookmaker_id)
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

-- PAYOUTS
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

-- AUDIT LOG
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

-- SEED DEFAULT BOOKMAKERS
INSERT INTO bookmakers (name, short_name, rules, min_loss_rub, sort_order) VALUES
  ('1xBet', '1X', 'Кэшбэк 5-10% от проигрышей. Нужны: скрин купона + скрин ЛК с историей.', 500, 1),
  ('Fonbet', 'FB', 'Кэшбэк 5-10% от проигрышей. Нужны: скрин ставки + история транзакций.', 500, 2),
  ('Betcity', 'BC', 'Кэшбэк 5-10% от проигрышей. Нужны: скрин из ЛК.', 500, 3),
  ('Melbet', 'MB', 'Кэшбэк 5-10% от проигрышей. Лимит 30 000₽/мес.', 500, 4),
  ('BetBoom', 'BB', 'Кэшбэк 5-10% от проигрышей.', 500, 5)
ON CONFLICT DO NOTHING;

-- INDEXES
CREATE INDEX IF NOT EXISTS idx_claims_user_id ON claims(user_id);
CREATE INDEX IF NOT EXISTS idx_claims_status ON claims(status);
CREATE INDEX IF NOT EXISTS idx_claims_bet_id ON claims(bet_id);
CREATE INDEX IF NOT EXISTS idx_claim_attachments_hash ON claim_attachments(file_hash);
CREATE INDEX IF NOT EXISTS idx_users_referrer ON users(referrer_id);
CREATE INDEX IF NOT EXISTS idx_referral_ledger_referrer ON referral_ledger(referrer_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity, entity_id);
