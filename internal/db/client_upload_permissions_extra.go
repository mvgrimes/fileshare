package db

import "context"

const clientCanUploadToTarget = `
SELECT EXISTS (
  SELECT 1
  FROM client_upload_permissions
  WHERE owner_type = 'client'
    AND owner_id = ?
    AND target_type = ?
    AND target_id = ?
)
`

type ClientCanUploadToTargetParams struct {
	ClientID   string
	TargetType string
	TargetID   string
}

func (q *Queries) ClientCanUploadToTarget(
	ctx context.Context,
	arg ClientCanUploadToTargetParams,
) (bool, error) {
	row := q.db.QueryRowContext(
		ctx,
		clientCanUploadToTarget,
		arg.ClientID,
		arg.TargetType,
		arg.TargetID,
	)
	var allowed bool
	if err := row.Scan(&allowed); err != nil {
		return false, err
	}
	return allowed, nil
}
