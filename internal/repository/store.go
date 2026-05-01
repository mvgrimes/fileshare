package repository

import (
	"context"
	"database/sql"

	"sharefile/internal/db"
)

type Store struct {
	db      *sql.DB
	queries *db.Queries
}

type TxStore struct {
	tx      *sql.Tx
	queries *db.Queries
}

func NewStore(sqlDB *sql.DB) *Store {
	return &Store{
		db:      sqlDB,
		queries: db.New(sqlDB),
	}
}

func (s *Store) Queries() *db.Queries {
	return s.queries
}

func (s *Store) WithTx(ctx context.Context, fn func(*TxStore) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	txStore := &TxStore{tx: tx, queries: db.New(tx)}
	if err := fn(txStore); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	return tx.Commit()
}

func (t *TxStore) Queries() *db.Queries {
	return t.queries
}
