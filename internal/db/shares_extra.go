package db

import "context"

const clientCanAccessFile = `
SELECT EXISTS (
  SELECT 1
  FROM shares s
  WHERE s.file_id = ?
    AND (
      (s.target_type = 'client' AND s.target_id = ?)
      OR (
        s.target_type = 'client_group'
        AND EXISTS (
          SELECT 1
          FROM client_group_members cgm
          WHERE cgm.client_group_id = s.target_id
            AND cgm.client_id = ?
        )
      )
    )
)
`

type ClientCanAccessFileParams struct {
	FileID   string
	ClientID string
}

func (q *Queries) ClientCanAccessFile(ctx context.Context, arg ClientCanAccessFileParams) (bool, error) {
	row := q.db.QueryRowContext(ctx, clientCanAccessFile, arg.FileID, arg.ClientID, arg.ClientID)
	var allowed bool
	if err := row.Scan(&allowed); err != nil {
		return false, err
	}
	return allowed, nil
}
