-- Add base cashback percent to bookmakers
ALTER TABLE bookmakers ADD COLUMN IF NOT EXISTS base_cashback_pct DECIMAL(5,2) DEFAULT 5.00;

-- Set default 5% for all existing bookmakers
UPDATE bookmakers SET base_cashback_pct = 5.00 WHERE base_cashback_pct IS NULL;
