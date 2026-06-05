-- VULNERABLE: RLS enabled but no CREATE POLICY
CREATE TABLE messages (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL,
  body text
);

ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
-- intentionally missing: CREATE POLICY ...