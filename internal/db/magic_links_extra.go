package db

import "context"

const consumeMagicLinkIfActive = `
UPDATE magic_links
SET consumed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ? AND consumed_at IS NULL
`

func (q *Queries) ConsumeMagicLinkIfActive(ctx context.Context, id string) (bool, error) {
	result, err := q.db.ExecContext(ctx, consumeMagicLinkIfActive, id)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows == 1, nil
}
