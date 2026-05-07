package mail

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fileshare/internal/db"

	"github.com/google/uuid"
)

const (
	EmailEventStatusPending   = "pending"
	EmailEventStatusDelivered = "delivered"
	EmailEventStatusFailed    = "failed"
)

type emailEventQuerier interface {
	CreateEmailEvent(ctx context.Context, arg db.CreateEmailEventParams) error
	UpdateEmailEventStatus(ctx context.Context, arg db.UpdateEmailEventStatusParams) error
}

type EventStore struct {
	queries emailEventQuerier
	now     func() time.Time
}

type DeliveryMetadata struct {
	CorrelationID string         `json:"correlation_id"`
	AttemptedAt   string         `json:"attempted_at"`
	ProviderID    sql.NullString `json:"provider_message_id"`
	ErrorText     sql.NullString `json:"error_text"`
}

func NewEventStore(queries emailEventQuerier) *EventStore {
	return &EventStore{queries: queries, now: time.Now}
}

func (s *EventStore) RecordPending(
	ctx context.Context,
	eventType, recipientEmail, correlationID string,
	payload map[string]any,
) (string, error) {
	if strings.TrimSpace(eventType) == "" || strings.TrimSpace(recipientEmail) == "" {
		return "", fmt.Errorf("event type and recipient email are required")
	}

	payloadJSON, err := marshalPayload(payload)
	if err != nil {
		return "", err
	}

	id := uuid.NewString()
	err = s.queries.CreateEmailEvent(ctx, db.CreateEmailEventParams{
		ID:                id,
		EventType:         eventType,
		RecipientEmail:    recipientEmail,
		ProviderMessageID: sql.NullString{},
		Status:            EmailEventStatusPending,
		ErrorText:         sql.NullString{},
		PayloadJson:       payloadJSON,
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

func (s *EventStore) MarkDelivered(ctx context.Context, id, providerMessageID string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("id is required")
	}
	return s.queries.UpdateEmailEventStatus(ctx, db.UpdateEmailEventStatusParams{
		ID:                id,
		Status:            EmailEventStatusDelivered,
		ProviderMessageID: nullString(providerMessageID),
		ErrorText:         sql.NullString{},
	})
}

func (s *EventStore) MarkFailed(
	ctx context.Context,
	id, errorText, providerMessageID string,
) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("id is required")
	}
	return s.queries.UpdateEmailEventStatus(ctx, db.UpdateEmailEventStatusParams{
		ID:                id,
		Status:            EmailEventStatusFailed,
		ProviderMessageID: nullString(providerMessageID),
		ErrorText:         nullString(errorText),
	})
}

func marshalPayload(payload map[string]any) (sql.NullString, error) {
	if len(payload) == 0 {
		return sql.NullString{}, nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{Valid: true, String: string(b)}, nil
}

func nullString(v string) sql.NullString {
	v = strings.TrimSpace(v)
	if v == "" {
		return sql.NullString{}
	}
	return sql.NullString{Valid: true, String: v}
}
