package mail

import (
	"strings"
	"testing"
)

func TestNewHermesRendererValidation(t *testing.T) {
	t.Parallel()

	if _, err := NewHermesRenderer("", "https://sharefile.example", ""); err == nil {
		t.Fatal("NewHermesRenderer() error = nil, want error for missing product name")
	}

	if _, err := NewHermesRenderer("ShareFile", "", ""); err == nil {
		t.Fatal("NewHermesRenderer() error = nil, want error for missing product link")
	}
}

func TestHermesRendererRenderMagicLink(t *testing.T) {
	t.Parallel()

	renderer, err := NewHermesRenderer("ShareFile", "https://sharefile.example", "")
	if err != nil {
		t.Fatalf("NewHermesRenderer() error: %v", err)
	}

	rendered, err := renderer.RenderMagicLink(MagicLinkTemplateData{
		ToName:       "Casey",
		LoginURL:     "https://sharefile.example/auth/magic/verify?token=abc",
		SupportEmail: "support@example.com",
	})
	if err != nil {
		t.Fatalf("RenderMagicLink() error: %v", err)
	}

	if rendered.Subject != "Your ShareFile magic login link" {
		t.Fatalf("subject = %q, want %q", rendered.Subject, "Your ShareFile magic login link")
	}
	if !strings.Contains(rendered.HTML, "Sign in to ShareFile") {
		t.Fatalf("HTML missing expected CTA: %q", rendered.HTML)
	}
	if !strings.Contains(rendered.HTML, "https://sharefile.example/auth/magic/verify?token=abc") {
		t.Fatalf("HTML missing login url: %q", rendered.HTML)
	}
	if !strings.Contains(rendered.Text, "support@example.com") {
		t.Fatalf("text missing support email: %q", rendered.Text)
	}
}

func TestHermesRendererRenderMagicLinkRequiresLoginURL(t *testing.T) {
	t.Parallel()

	renderer, err := NewHermesRenderer("ShareFile", "https://sharefile.example", "")
	if err != nil {
		t.Fatalf("NewHermesRenderer() error: %v", err)
	}

	if _, err := renderer.RenderMagicLink(MagicLinkTemplateData{}); err == nil {
		t.Fatal("RenderMagicLink() error = nil, want validation error")
	}
}

func TestHermesRendererRenderMagicLinkDefaultNameAndOutro(t *testing.T) {
	t.Parallel()

	renderer, err := NewHermesRenderer("ShareFile", "https://sharefile.example", "")
	if err != nil {
		t.Fatalf("NewHermesRenderer() error: %v", err)
	}

	rendered, err := renderer.RenderMagicLink(MagicLinkTemplateData{LoginURL: "https://sharefile.example/login"})
	if err != nil {
		t.Fatalf("RenderMagicLink() error: %v", err)
	}

	if !strings.Contains(rendered.Text, "Hi there") {
		t.Fatalf("text missing default greeting name: %q", rendered.Text)
	}
	if !strings.Contains(rendered.Text, "If you did not request this link") {
		t.Fatalf("text missing fallback outro: %q", rendered.Text)
	}
}
