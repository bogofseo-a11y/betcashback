-- Add user_last_read_at to support_tickets
ALTER TABLE support_tickets ADD COLUMN IF NOT EXISTS user_last_read_at TIMESTAMPTZ DEFAULT NULL;

-- Initialize: set to ticket creation time (so existing messages show as unread)
UPDATE support_tickets SET user_last_read_at = created_at WHERE user_last_read_at IS NULL;
