package mail

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMailgunSenderSendMagicLink(t *testing.T) {
	var gotAuth string
	var gotBody url.Values

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/v3/mg.example/messages" {
			t.Fatalf("path = %q, want %q", r.URL.Path, "/v3/mg.example/messages")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error: %v", err)
		}
		gotBody = r.Form
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sender, err := NewMailgunSender(ts.URL, "mg.example", "key-123", "ShareFile <noreply@example.com>", ts.Client())
	if err != nil {
		t.Fatalf("NewMailgunSender() error: %v", err)
	}

	if err := sender.SendMagicLink(t.Context(), "client@example.com", "tok-1"); err != nil {
		t.Fatalf("SendMagicLink() error: %v", err)
	}

	if gotAuth == "" || !strings.HasPrefix(gotAuth, "Basic ") {
		t.Fatalf("Authorization header = %q, want Basic auth", gotAuth)
	}
	if gotBody.Get("to") != "client@example.com" {
		t.Fatalf("to = %q, want %q", gotBody.Get("to"), "client@example.com")
	}
	if gotBody.Get("from") == "" || !strings.Contains(gotBody.Get("from"), "noreply@example.com") {
		t.Fatalf("from = %q, want sender email", gotBody.Get("from"))
	}
	if !strings.Contains(gotBody.Get("text"), "tok-1") {
		t.Fatalf("text = %q, want token", gotBody.Get("text"))
	}
}

func TestMailgunSenderRejectsNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	sender, err := NewMailgunSender(ts.URL, "mg.example", "key-123", "noreply@example.com", ts.Client())
	if err != nil {
		t.Fatalf("NewMailgunSender() error: %v", err)
	}

	if err := sender.SendMagicLink(t.Context(), "client@example.com", "tok-1"); err == nil {
		t.Fatal("SendMagicLink() error = nil, want error")
	}
}
