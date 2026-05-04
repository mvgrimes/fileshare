package db

import "context"

const updateFileNameByID = `
UPDATE files
SET original_filename = ?
WHERE id = ?
`

type UpdateFileNameByIDParams struct {
	ID               string
	OriginalFilename string
}

func (q *Queries) UpdateFileNameByID(ctx context.Context, arg UpdateFileNameByIDParams) error {
	_, err := q.db.ExecContext(ctx, updateFileNameByID, arg.OriginalFilename, arg.ID)
	return err
}
