-- +goose Up
CREATE TABLE _email_conflict_check (
  ok INTEGER NOT NULL CHECK (ok = 1)
);

INSERT INTO _email_conflict_check(ok)
VALUES (
  CASE
    WHEN EXISTS (
      SELECT 1
      FROM users u
      JOIN clients c ON LOWER(u.email) = LOWER(c.email)
    ) THEN 0
    ELSE 1
  END
);

DROP TABLE _email_conflict_check;

CREATE UNIQUE INDEX idx_users_email_ci_unique ON users(LOWER(email));
CREATE UNIQUE INDEX idx_clients_email_ci_unique ON clients(LOWER(email));

-- +goose StatementBegin
CREATE TRIGGER trg_users_email_cross_unique_insert
BEFORE INSERT ON users
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM clients WHERE LOWER(email) = LOWER(NEW.email))
BEGIN
  SELECT RAISE(ABORT, 'email already exists on clients');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER trg_users_email_cross_unique_update
BEFORE UPDATE OF email ON users
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM clients WHERE LOWER(email) = LOWER(NEW.email))
BEGIN
  SELECT RAISE(ABORT, 'email already exists on clients');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER trg_clients_email_cross_unique_insert
BEFORE INSERT ON clients
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM users WHERE LOWER(email) = LOWER(NEW.email))
BEGIN
  SELECT RAISE(ABORT, 'email already exists on users');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER trg_clients_email_cross_unique_update
BEFORE UPDATE OF email ON clients
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM users WHERE LOWER(email) = LOWER(NEW.email))
BEGIN
  SELECT RAISE(ABORT, 'email already exists on users');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS trg_clients_email_cross_unique_update;
DROP TRIGGER IF EXISTS trg_clients_email_cross_unique_insert;
DROP TRIGGER IF EXISTS trg_users_email_cross_unique_update;
DROP TRIGGER IF EXISTS trg_users_email_cross_unique_insert;
DROP INDEX IF EXISTS idx_clients_email_ci_unique;
DROP INDEX IF EXISTS idx_users_email_ci_unique;
