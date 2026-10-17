-- Create a read-only role and a tiny sample schema for integration tests.

CREATE ROLE readonly WITH LOGIN PASSWORD 'readonly' NOSUPERUSER NOCREATEDB NOCREATEROLE;

CREATE TABLE public.users (
  id   serial PRIMARY KEY,
  name text NOT NULL,
  email text
);

CREATE TABLE public.orders (
  id      serial PRIMARY KEY,
  user_id int REFERENCES public.users(id),
  status  text NOT NULL,
  amount  numeric(10,2) NOT NULL DEFAULT 0
);

INSERT INTO public.users (name, email) VALUES
  ('alice', 'alice@example.com'),
  ('bob',   'bob@example.com'),
  ('carol', 'carol@example.com');

INSERT INTO public.orders (user_id, status, amount) VALUES
  (1, 'paid',    42.00),
  (1, 'pending', 15.50),
  (2, 'paid',    99.00),
  (3, 'refunded', 7.25);

GRANT CONNECT ON DATABASE sandbox TO readonly;
GRANT USAGE ON SCHEMA public TO readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly;

-- Explicitly revoke write privileges (defense in depth)
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM readonly;
