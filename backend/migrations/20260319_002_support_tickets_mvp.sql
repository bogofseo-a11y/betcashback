-- Support tickets MVP (incremental, backward-compatible)

BEGIN;

-- ------------------------------------------------------------
-- SUPPORT TICKETS
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS support_tickets (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(20) NOT NULL DEFAULT 'open',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  closed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS support_ticket_messages (
  id BIGSERIAL PRIMARY KEY,
  ticket_id BIGINT NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
  sender_type VARCHAR(10) NOT NULL,
  sender_admin_id BIGINT,
  message TEXT NOT NULL,
  attachments_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_support_tickets_status'
  ) THEN
    ALTER TABLE support_tickets
      ADD CONSTRAINT chk_support_tickets_status
      CHECK (status IN ('open', 'in_progress', 'waiting_user', 'closed')) NOT VALID;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_support_ticket_messages_sender_type'
  ) THEN
    ALTER TABLE support_ticket_messages
      ADD CONSTRAINT chk_support_ticket_messages_sender_type
      CHECK (sender_type IN ('user', 'admin')) NOT VALID;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_support_tickets_user_id ON support_tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON support_tickets(status);
CREATE INDEX IF NOT EXISTS idx_support_tickets_updated_at ON support_tickets(updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_support_messages_ticket_id ON support_ticket_messages(ticket_id);
CREATE INDEX IF NOT EXISTS idx_support_messages_created_at ON support_ticket_messages(created_at);

COMMIT;
