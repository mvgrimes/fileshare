package mail

import (
	"context"
	"errors"
	"testing"

	"sharefile/internal/db"
)

type stubEmailEventQuerier struct {
	createArg db.CreateEmailEventParams
	updateArg db.UpdateEmailEventStatusParams
	createErr error
	updateErr error
}

func (s *stubEmailEventQuerier) CreateEmailEvent(_ context.Context, arg db.CreateEmailEventParams) error {
	s.createArg = arg
	return s.createErr
}

func (s *stubEmailEventQuerier) UpdateEmailEventStatus(_ context.Context, arg db.UpdateEmailEventStatusParams) error {
	s.updateArg = arg
	return s.updateErr
}

func TestEventStoreRecordPending(t *testing.T) {
	t.Parallel()

	q := &stubEmailEventQuerier{}
	store := NewEventStore(q)

	id, err := store.RecordPending(t.Context(), "auth.magic.request", "client@example.com", "corr-1", map[string]any{"flow": "magic"})
	if err != nil {
		t.Fatalf("RecordPending() error: %v", err)
	}
	if id == "" {
		t.Fatal("RecordPending() id = empty, want value")
	}
	if q.createArg.Status != EmailEventStatusPending {
		t.Fatalf("status = %q, want %q", q.createArg.Status, EmailEventStatusPending)
	}
	if !q.createArg.PayloadJson.Valid {
		t.Fatal("payload json should be set")
	}
}

func TestEventStoreMarkDeliveredAndFailed(t *testing.T) {
	t.Parallel()

	q := &stubEmailEventQuerier{}
	store := NewEventStore(q)

	if err := store.MarkDelivered(t.Context(), "evt-1", "msg-1"); err != nil {
		t.Fatalf("MarkDelivered() error: %v", err)
	}
	if q.updateArg.Status != EmailEventStatusDelivered {
		t.Fatalf("status = %q, want %q", q.updateArg.Status, EmailEventStatusDelivered)
	}
	if !q.updateArg.ProviderMessageID.Valid {
		t.Fatal("provider message id should be set")
	}

	if err := store.MarkFailed(t.Context(), "evt-2", "delivery failed", ""); err != nil {
		t.Fatalf("MarkFailed() error: %v", err)
	}
	if q.updateArg.Status != EmailEventStatusFailed {
		t.Fatalf("status = %q, want %q", q.updateArg.Status, EmailEventStatusFailed)
	}
	if !q.updateArg.ErrorText.Valid {
		t.Fatal("error text should be set")
	}
}

func TestEventStoreValidationAndErrors(t *testing.T) {
	t.Parallel()

	q := &stubEmailEventQuerier{}
	store := NewEventStore(q)

	if _, err := store.RecordPending(t.Context(), "", "x@example.com", "", nil); err == nil {
		t.Fatal("RecordPending() expected validation error")
	}
	if err := store.MarkDelivered(t.Context(), "", "msg"); err == nil {
		t.Fatal("MarkDelivered() expected validation error")
	}

	q.createErr = errors.New("write failed")
	if _, err := store.RecordPending(t.Context(), "event", "x@example.com", "", nil); err == nil {
		t.Fatal("RecordPending() expected create error")
	}

	q.updateErr = errors.New("update failed")
	if err := store.MarkFailed(t.Context(), "evt-1", "oops", ""); err == nil {
		t.Fatal("MarkFailed() expected update error")
	}

	if _, err := marshalPayload(map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("marshalPayload() expected marshal error")
	}

	if ns := nullString("  "); ns.Valid {
		t.Fatal("nullString() expected invalid for blank input")
	}
	if ns := nullString("ok"); !ns.Valid || ns.String != "ok" {
		t.Fatalf("nullString() unexpected value: %+v", ns)
	}

}
