package db

import "context"

const upsertUserByID = `
INSERT INTO users (id, email, full_name, is_active)
VALUES (?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  email = excluded.email,
  full_name = excluded.full_name,
  is_active = excluded.is_active,
  updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
`

type UpsertUserByIDParams struct {
	ID       string
	Email    string
	FullName string
	IsActive int64
}

func (q *Queries) UpsertUserByID(ctx context.Context, arg UpsertUserByIDParams) error {
	_, err := q.db.ExecContext(ctx, upsertUserByID, arg.ID, arg.Email, arg.FullName, arg.IsActive)
	return err
}
