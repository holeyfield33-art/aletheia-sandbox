-- Sample schema + a read-only role, a deliberately-writable role, and a
-- persistent write-canary, for integration tests (local Docker and CI).
-- Runs in database `sandbox` as the admin user.

CREATE TABLE public.users (
  id    serial PRIMARY KEY,
  name  text NOT NULL,
  email text
);

CREATE TABLE public.orders (
  id      serial PRIMARY KEY,
  user_id int REFERENCES public.users(id),
  status  text NOT NULL,
  amount  numeric(10,2) NOT NULL DEFAULT 0
);

-- Persistent canary: MUST stay empty. Any row means an unauthorized write landed.
CREATE TABLE public.write_canary (
  id   serial PRIMARY KEY,
  note text,
  at   timestamptz DEFAULT now()
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

-- Read-only role: SELECT only, no DDL, no write.
CREATE ROLE readonly WITH LOGIN PASSWORD 'readonly' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE sandbox TO readonly;
GRANT USAGE ON SCHEMA public TO readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM readonly;
REVOKE CREATE ON SCHEMA public FROM readonly;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Deliberately writable role: used to prove the startup probe REFUSES it, and
-- that the READ ONLY transaction blocks writes even for a writable role.
CREATE ROLE writable WITH LOGIN PASSWORD 'writable' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE sandbox TO writable;
GRANT USAGE, CREATE ON SCHEMA public TO writable;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO writable;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO writable;

-- Writable ONLY through an automatically-updatable VIEW (no base-table grant):
-- the probe must still refuse it (write privilege on a view persists writes).
CREATE VIEW public.users_v AS SELECT id, name, email FROM public.users;
CREATE ROLE writable_view WITH LOGIN PASSWORD 'writable_view' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE sandbox TO writable_view;
GRANT USAGE ON SCHEMA public TO writable_view;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.users_v TO writable_view;
GRANT USAGE, SELECT ON SEQUENCE public.users_id_seq TO writable_view;

-- CREATE on the DATABASE (but not the CREATEDB attribute, no schema grant):
-- the probe must refuse it (it can add a schema then write there).
CREATE ROLE writable_dbcreate WITH LOGIN PASSWORD 'writable_dbcreate' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE sandbox TO writable_dbcreate;
GRANT CREATE ON DATABASE sandbox TO writable_dbcreate;
GRANT USAGE ON SCHEMA public TO writable_dbcreate;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO writable_dbcreate;
