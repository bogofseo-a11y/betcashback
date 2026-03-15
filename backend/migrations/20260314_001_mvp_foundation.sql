-- MVP foundation migration (incremental, backward-compatible)

BEGIN;

-- ------------------------------------------------------------
-- BOOKMAKERS: admin/config fields
-- ------------------------------------------------------------
ALTER TABLE bookmakers ADD COLUMN IF NOT EXISTS affiliate_url_template TEXT;
ALTER TABLE bookmakers ADD COLUMN IF NOT EXISTS tracking_mode VARCHAR(30) DEFAULT 'none';
ALTER TABLE bookmakers ADD COLUMN IF NOT EXISTS tracking_subid_param VARCHAR(50) DEFAULT 'subid';
ALTER TABLE bookmakers ADD COLUMN IF NOT EXISTS tracking_clickid_param VARCHAR(50) DEFAULT 'clickid';
ALTER TABLE bookmakers ADD COLUMN IF NOT EXISTS offer_text TEXT;
ALTER TABLE bookmakers ADD COLUMN IF NOT EXISTS cashback_label VARCHAR(100);
ALTER TABLE bookmakers ADD COLUMN IF NOT EXISTS instruction_asset_url TEXT;
ALTER TABLE bookmakers ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- ------------------------------------------------------------
-- BOOKMAKER ACCOUNTS: verification metadata
-- ------------------------------------------------------------
ALTER TABLE bookmaker_accounts ADD COLUMN IF NOT EXISTS verification_source VARCHAR(30);
ALTER TABLE bookmaker_accounts ADD COLUMN IF NOT EXISTS verified_by_admin_id BIGINT;
ALTER TABLE bookmaker_accounts ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMPTZ;
ALTER TABLE bookmaker_accounts ADD COLUMN IF NOT EXISTS rejection_reason TEXT;
ALTER TABLE bookmaker_accounts ADD COLUMN IF NOT EXISTS last_import_batch_id BIGINT;

-- ------------------------------------------------------------
-- BOOKMAKER LINK GENERATIONS
-- ------------------------------------------------------------
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
  generation_context VARCHAR(30) DEFAULT 'manual_open',
  metadata_json JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ------------------------------------------------------------
-- PARTNER IMPORT TABLES
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS partner_import_batches (
  id BIGSERIAL PRIMARY KEY,
  bookmaker_id INTEGER REFERENCES bookmakers(id) ON DELETE CASCADE,
  uploaded_by_admin_id BIGINT, -- stored as BIGINT identifier; no FK (no admins table yet)
  source_name VARCHAR(120),
  original_filename TEXT,
  file_checksum VARCHAR(128),
  period_from DATE,
  period_to DATE,
  rows_total INTEGER DEFAULT 0,
  rows_new INTEGER DEFAULT 0,
  rows_changed INTEGER DEFAULT 0,
  rows_unchanged INTEGER DEFAULT 0,
  status VARCHAR(20) DEFAULT 'uploaded' CHECK (status IN ('uploaded', 'processed', 'failed')),
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  processed_at TIMESTAMPTZ
);

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

-- ------------------------------------------------------------
-- CLAIM ATTACHMENTS: optional metadata
-- ------------------------------------------------------------
ALTER TABLE claim_attachments ADD COLUMN IF NOT EXISTS mime_type VARCHAR(100);
ALTER TABLE claim_attachments ADD COLUMN IF NOT EXISTS file_size_bytes INTEGER;

-- ------------------------------------------------------------
-- PAYOUT REQUESTS
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS payout_requests (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id),
  payout_method_id INTEGER REFERENCES payout_methods(id),
  amount_rub DECIMAL(12,2) NOT NULL,
  asset VARCHAR(30),
  address_snapshot TEXT,
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'processing', 'paid', 'failed')),
  admin_note TEXT,
  tx_hash VARCHAR(200),
  processed_by_admin_id BIGINT, -- stored as BIGINT identifier; no FK (no admins table yet)
  processed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Keep runtime alignment for environments where table existed in earlier shape
ALTER TABLE payout_requests ADD COLUMN IF NOT EXISTS payout_method_id INTEGER REFERENCES payout_methods(id);
ALTER TABLE payout_requests ADD COLUMN IF NOT EXISTS amount_rub DECIMAL(12,2);
ALTER TABLE payout_requests ADD COLUMN IF NOT EXISTS asset VARCHAR(30);
ALTER TABLE payout_requests ADD COLUMN IF NOT EXISTS address_snapshot TEXT;
ALTER TABLE payout_requests ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'pending';
ALTER TABLE payout_requests ADD COLUMN IF NOT EXISTS admin_note TEXT;
ALTER TABLE payout_requests ADD COLUMN IF NOT EXISTS tx_hash VARCHAR(200);
ALTER TABLE payout_requests ADD COLUMN IF NOT EXISTS processed_by_admin_id BIGINT;
ALTER TABLE payout_requests ADD COLUMN IF NOT EXISTS processed_at TIMESTAMPTZ;
ALTER TABLE payout_requests ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- ------------------------------------------------------------
-- INTERNAL NOTES
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS internal_notes (
  id BIGSERIAL PRIMARY KEY,
  entity_type VARCHAR(40) NOT NULL,
  entity_id BIGINT NOT NULL,
  note TEXT NOT NULL,
  is_private BOOLEAN DEFAULT TRUE,
  created_by_admin_id BIGINT, -- stored as BIGINT identifier; no FK (no admins table yet)
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ------------------------------------------------------------
-- ADMIN AUDIT LOG
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_audit_log (
  id BIGSERIAL PRIMARY KEY,
  admin_id BIGINT, -- stored as BIGINT identifier; no FK (no admins table yet)
  action VARCHAR(120) NOT NULL,
  entity_type VARCHAR(50),
  entity_id BIGINT,
  payload_json JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ------------------------------------------------------------
-- MATCH SUGGESTIONS (account <-> imported row)
-- ------------------------------------------------------------
ALTER TABLE IF EXISTS bookmaker_suggestions RENAME TO partner_match_suggestions;

CREATE TABLE IF NOT EXISTS partner_match_suggestions (
  id BIGSERIAL PRIMARY KEY,
  bookmaker_account_id INTEGER REFERENCES bookmaker_accounts(id) ON DELETE CASCADE,
  partner_player_row_id BIGINT REFERENCES partner_player_rows(id) ON DELETE CASCADE,
  confidence_score INTEGER NOT NULL DEFAULT 0,
  confidence_level VARCHAR(20) NOT NULL DEFAULT 'low',
  reasons TEXT[],
  suggestion_payload_json JSONB,
  is_selected BOOLEAN DEFAULT FALSE,
  selected_by_admin_id BIGINT, -- stored as BIGINT identifier; no FK (no admins table yet)
  selected_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(bookmaker_account_id, partner_player_row_id)
);

-- ------------------------------------------------------------
-- APP SETTINGS (minimum payout configurable)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_settings (
  key VARCHAR(100) PRIMARY KEY,
  value TEXT NOT NULL,
  value_type VARCHAR(20) NOT NULL DEFAULT 'string',
  description TEXT,
  updated_by_admin_id BIGINT, -- stored as BIGINT identifier; no FK (no admins table yet)
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO app_settings (key, value, value_type, description)
VALUES ('min_payout_amount_rub', '500', 'number', 'Minimum payout amount in RUB')
ON CONFLICT (key) DO NOTHING;

-- ------------------------------------------------------------
-- Controlled-value CHECK constraints for existing tables
-- ------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_bookmakers_tracking_mode'
  ) THEN
    ALTER TABLE bookmakers
      ADD CONSTRAINT chk_bookmakers_tracking_mode
      CHECK (tracking_mode IN ('none', 'subid', 'clickid', 'subid_clickid')) NOT VALID;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_partner_import_batches_status'
  ) THEN
    ALTER TABLE partner_import_batches
      ADD CONSTRAINT chk_partner_import_batches_status
      CHECK (status IN ('uploaded', 'processed', 'failed')) NOT VALID;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_payout_requests_status'
  ) THEN
    ALTER TABLE payout_requests
      ADD CONSTRAINT chk_payout_requests_status
      CHECK (status IN ('pending', 'approved', 'rejected', 'processing', 'paid', 'failed')) NOT VALID;
  END IF;
END $$;

-- ------------------------------------------------------------
-- Add FK for bookmaker_accounts.last_import_batch_id (safe)
-- ------------------------------------------------------------
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

-- ------------------------------------------------------------
-- Indexes
-- ------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(id);

CREATE INDEX IF NOT EXISTS idx_bookmaker_accounts_user_id ON bookmaker_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_bookmaker_accounts_bookmaker_id ON bookmaker_accounts(bookmaker_id);
CREATE INDEX IF NOT EXISTS idx_bookmaker_accounts_player_id ON bookmaker_accounts(affiliate_player_id);

CREATE INDEX IF NOT EXISTS idx_link_gen_user_id ON bookmaker_link_generations(user_id);
CREATE INDEX IF NOT EXISTS idx_link_gen_bookmaker_id ON bookmaker_link_generations(bookmaker_id);
CREATE INDEX IF NOT EXISTS idx_link_gen_subid ON bookmaker_link_generations(generated_subid);
CREATE INDEX IF NOT EXISTS idx_link_gen_clickid ON bookmaker_link_generations(generated_clickid);

CREATE INDEX IF NOT EXISTS idx_partner_batches_bookmaker_id ON partner_import_batches(bookmaker_id);
CREATE INDEX IF NOT EXISTS idx_partner_rows_bookmaker_id ON partner_player_rows(bookmaker_id);
CREATE INDEX IF NOT EXISTS idx_partner_rows_player_id ON partner_player_rows(imported_player_id);
CREATE INDEX IF NOT EXISTS idx_partner_rows_subid ON partner_player_rows(imported_subid);
CREATE INDEX IF NOT EXISTS idx_partner_rows_clickid ON partner_player_rows(imported_clickid);

CREATE INDEX IF NOT EXISTS idx_claims_bookmaker_id ON claims(bookmaker_id);
CREATE INDEX IF NOT EXISTS idx_claims_status ON claims(status);
CREATE INDEX IF NOT EXISTS idx_claims_bet_id ON claims(bet_id);

CREATE INDEX IF NOT EXISTS idx_payout_requests_user_id ON payout_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_payout_requests_status ON payout_requests(status);

CREATE INDEX IF NOT EXISTS idx_internal_notes_entity ON internal_notes(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_partner_match_suggestions_account ON partner_match_suggestions(bookmaker_account_id);
CREATE INDEX IF NOT EXISTS idx_partner_match_suggestions_row ON partner_match_suggestions(partner_player_row_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_entity ON admin_audit_log(entity_type, entity_id);

COMMIT;
