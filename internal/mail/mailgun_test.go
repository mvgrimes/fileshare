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

	renderer, err := NewHermesRenderer("ShareFile", "https://sharefile.example", "")
	if err != nil {
		t.Fatalf("NewHermesRenderer() error: %v", err)
	}

	sender, err := NewMailgunSender(ts.URL, "mg.example", "key-123", "ShareFile <noreply@example.com>", ts.Client(), renderer)
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
	if !strings.Contains(gotBody.Get("html"), "https://sharefile.example/verify-token?client_id=client%40example.com&amp;token=tok-1") {
		t.Fatalf("html = %q, want verify link with embedded client and token", gotBody.Get("html"))
	}
	if gotBody.Get("html") == "" {
		t.Fatalf("html = %q, want non-empty html", gotBody.Get("html"))
	}
}

func TestMailgunSenderRejectsNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	renderer, err := NewHermesRenderer("ShareFile", "https://sharefile.example", "")
	if err != nil {
		t.Fatalf("NewHermesRenderer() error: %v", err)
	}

	sender, err := NewMailgunSender(ts.URL, "mg.example", "key-123", "noreply@example.com", ts.Client(), renderer)
	if err != nil {
		t.Fatalf("NewMailgunSender() error: %v", err)
	}

	if err := sender.SendMagicLink(t.Context(), "client@example.com", "tok-1"); err == nil {
		t.Fatal("SendMagicLink() error = nil, want error")
	}
}

func TestMailgunSenderSendValidation(t *testing.T) {
	t.Parallel()

	renderer, err := NewHermesRenderer("ShareFile", "https://sharefile.example", "")
	if err != nil {
		t.Fatalf("NewHermesRenderer() error: %v", err)
	}

	sender, err := NewMailgunSender("https://api.example.test", "mg.example", "key-123", "noreply@example.com", http.DefaultClient, renderer)
	if err != nil {
		t.Fatalf("NewMailgunSender() error: %v", err)
	}

	if err := sender.Send(t.Context(), Message{To: "", Subject: "x", Text: "ok"}); err == nil {
		t.Fatal("Send() error=nil, want validation error for empty recipient")
	}
	if err := sender.Send(t.Context(), Message{To: "to@example.com", Subject: "", Text: "ok"}); err == nil {
		t.Fatal("Send() error=nil, want validation error for empty subject")
	}
	if err := sender.Send(t.Context(), Message{To: "to@example.com", Subject: "x"}); err == nil {
		t.Fatal("Send() error=nil, want validation error for missing body")
	}
}
