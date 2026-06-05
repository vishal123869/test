-- VULNERABLE: table created with no RLS
CREATE TABLE profiles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  email text NOT NULL,
  private_notes text
);

CREATE TABLE orders (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL,
  total numeric
);