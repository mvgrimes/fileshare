package db

import (
	"context"
	"database/sql"
)

type CreatePasswordResetParams struct {
	ID        string
	ActorType string
	ActorID   string
	Email     string
	TokenHash string
	ExpiresAt string
}

type PasswordReset struct {
	ID         string
	ActorType  string
	ActorID    string
	Email      string
	TokenHash  string
	ExpiresAt  string
	ConsumedAt sql.NullString
	CreatedAt  string
}

const createPasswordReset = `
INSERT INTO password_resets (id, actor_type, actor_id, email, token_hash, expires_at, consumed_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
`

func (q *Queries) CreatePasswordReset(ctx context.Context, arg CreatePasswordResetParams) error {
	_, err := q.db.ExecContext(
		ctx,
		createPasswordReset,
		arg.ID,
		arg.ActorType,
		arg.ActorID,
		arg.Email,
		arg.TokenHash,
		arg.ExpiresAt,
		sql.NullString{},
	)
	return err
}

const getPasswordResetByTokenHash = `
SELECT id, actor_type, actor_id, email, token_hash, expires_at, consumed_at, created_at
FROM password_resets
WHERE token_hash = ?
`

func (q *Queries) GetPasswordResetByTokenHash(
	ctx context.Context,
	tokenHash string,
) (PasswordReset, error) {
	row := q.db.QueryRowContext(ctx, getPasswordResetByTokenHash, tokenHash)
	var i PasswordReset
	err := row.Scan(
		&i.ID,
		&i.ActorType,
		&i.ActorID,
		&i.Email,
		&i.TokenHash,
		&i.ExpiresAt,
		&i.ConsumedAt,
		&i.CreatedAt,
	)
	return i, err
}

const listPasswordResetsByActor = `
SELECT id, actor_type, actor_id, email, token_hash, expires_at, consumed_at, created_at
FROM password_resets
WHERE actor_type = ? AND actor_id = ?
ORDER BY created_at DESC
`

func (q *Queries) ListPasswordResetsByActor(
	ctx context.Context,
	actorType, actorID string,
) ([]PasswordReset, error) {
	rows, err := q.db.QueryContext(ctx, listPasswordResetsByActor, actorType, actorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []PasswordReset{}
	for rows.Next() {
		var i PasswordReset
		if err := rows.Scan(
			&i.ID,
			&i.ActorType,
			&i.ActorID,
			&i.Email,
			&i.TokenHash,
			&i.ExpiresAt,
			&i.ConsumedAt,
			&i.CreatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const consumePasswordResetIfActive = `
UPDATE password_resets
SET consumed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ? AND consumed_at IS NULL
`

func (q *Queries) ConsumePasswordResetIfActive(ctx context.Context, id string) (bool, error) {
	result, err := q.db.ExecContext(ctx, consumePasswordResetIfActive, id)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows == 1, nil
}

const updateUserPasswordHashByID = `
UPDATE users
SET password_hash = ?,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?
`

func (q *Queries) UpdateUserPasswordHashByID(
	ctx context.Context,
	id string,
	passwordHash sql.NullString,
) error {
	_, err := q.db.ExecContext(ctx, updateUserPasswordHashByID, passwordHash, id)
	return err
}

const updateClientPasswordHashByID = `
UPDATE clients
SET password_hash = ?,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?
`

func (q *Queries) UpdateClientPasswordHashByID(
	ctx context.Context,
	id string,
	passwordHash sql.NullString,
) error {
	_, err := q.db.ExecContext(ctx, updateClientPasswordHashByID, passwordHash, id)
	return err
}
