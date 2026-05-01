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

const listClientAccessibleShares = `
SELECT s.id, s.file_id, s.shared_by_type, s.shared_by_id, s.target_type, s.target_id, s.message, s.created_at
FROM shares s
WHERE (s.target_type = 'client' AND s.target_id = ?)
   OR (
     s.target_type = 'client_group'
     AND EXISTS (
       SELECT 1
       FROM client_group_members cgm
       WHERE cgm.client_group_id = s.target_id
         AND cgm.client_id = ?
     )
   )
ORDER BY s.created_at DESC
LIMIT ? OFFSET ?
`

type ListClientAccessibleSharesParams struct {
	ClientID string
	Limit    int64
	Offset   int64
}

func (q *Queries) ListClientAccessibleShares(ctx context.Context, arg ListClientAccessibleSharesParams) ([]Share, error) {
	rows, err := q.db.QueryContext(ctx, listClientAccessibleShares, arg.ClientID, arg.ClientID, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]Share, 0)
	for rows.Next() {
		var s Share
		if err := rows.Scan(&s.ID, &s.FileID, &s.SharedByType, &s.SharedByID, &s.TargetType, &s.TargetID, &s.Message, &s.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
