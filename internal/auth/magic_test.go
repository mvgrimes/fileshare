package auth

import (
	"context"
	"testing"
	"time"
)

func TestMagicLinkCreateAndConsume(t *testing.T) {
	m := NewMagicManager(15*time.Minute, 30*time.Second)
	token, _, err := m.Create(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	if _, err := m.Consume(context.Background(), "client-1", token); err != nil {
		t.Fatalf("Consume() unexpected error: %v", err)
	}

	if _, err := m.Consume(context.Background(), "client-1", token); err != ErrMagicLinkConsumed {
		t.Fatalf("Consume() second call error = %v, want %v", err, ErrMagicLinkConsumed)
	}
}

func TestMagicLinkThrottle(t *testing.T) {
	m := NewMagicManager(15*time.Minute, time.Minute)
	if _, _, err := m.Create(context.Background(), "client-1"); err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}
	if _, _, err := m.Create(context.Background(), "client-1"); err != ErrMagicLinkThrottled {
		t.Fatalf("Create() second call error = %v, want %v", err, ErrMagicLinkThrottled)
	}
}

func TestMagicLinkExpiration(t *testing.T) {
	m := NewMagicManager(time.Minute, 0)
	now := time.Now()
	m.now = func() time.Time { return now }
	token, _, err := m.Create(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	m.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := m.Consume(context.Background(), "client-1", token); err != ErrMagicLinkExpired {
		t.Fatalf("Consume() error = %v, want %v", err, ErrMagicLinkExpired)
	}
}
