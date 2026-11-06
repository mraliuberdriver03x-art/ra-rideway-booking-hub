
CREATE TABLE IF NOT EXISTS ra_customers (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  dob TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  email_verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ra_bookings (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  pickup_location TEXT NOT NULL,
  destination TEXT NOT NULL,
  pickup_at TEXT NOT NULL,
  passengers INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'requested',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (customer_id) REFERENCES ra_customers(id)
);
