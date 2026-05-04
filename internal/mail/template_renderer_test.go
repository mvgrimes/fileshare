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

func TestHermesRendererRenderMagicLinkRequiresLoginURLOrToken(t *testing.T) {
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

	rendered, err := renderer.RenderMagicLink(MagicLinkTemplateData{Token: "tok-123"})
	if err != nil {
		t.Fatalf("RenderMagicLink() error: %v", err)
	}

	if !strings.Contains(rendered.Text, "Hi there") {
		t.Fatalf("text missing default greeting name: %q", rendered.Text)
	}
	if !strings.Contains(rendered.Text, "If you did not request this link") {
		t.Fatalf("text missing fallback outro: %q", rendered.Text)
	}
	if !strings.Contains(rendered.Text, "tok-123") {
		t.Fatalf("text missing token: %q", rendered.Text)
	}
}

func TestHermesRendererRenderInvitation(t *testing.T) {
	t.Parallel()
	renderer, err := NewHermesRenderer("ShareFile", "https://sharefile.example", "")
	if err != nil {
		t.Fatalf("NewHermesRenderer() error: %v", err)
	}

	out, err := renderer.RenderInvitation(InvitationTemplateData{ToName: "Sam", InviteURL: "https://sharefile.example/invite/abc", InviterLabel: "Admin"})
	if err != nil {
		t.Fatalf("RenderInvitation() error: %v", err)
	}
	if out.Subject != "You are invited to ShareFile" {
		t.Fatalf("subject = %q", out.Subject)
	}
	if !strings.Contains(out.Text, "https://sharefile.example/invite/abc") {
		t.Fatalf("text missing invite url: %q", out.Text)
	}

	if _, err := renderer.RenderInvitation(InvitationTemplateData{}); err == nil {
		t.Fatal("RenderInvitation() expected validation error")
	}
}

func TestHermesRendererRenderFileShared(t *testing.T) {
	t.Parallel()
	renderer, err := NewHermesRenderer("ShareFile", "https://sharefile.example", "")
	if err != nil {
		t.Fatalf("NewHermesRenderer() error: %v", err)
	}

	out, err := renderer.RenderFileShared(FileSharedTemplateData{
		ToName:      "Chris",
		ActorLabel:  "user-17",
		FileName:    "q1-report.pdf",
		Message:     "Please review before Friday",
		FileListURL: "/client/files",
	})
	if err != nil {
		t.Fatalf("RenderFileShared() error: %v", err)
	}
	if out.Subject != "A file was shared with you" {
		t.Fatalf("subject = %q", out.Subject)
	}
	if !strings.Contains(out.Text, "user-17 shared q1-report.pdf with you") {
		t.Fatalf("text missing share details: %q", out.Text)
	}
	if !strings.Contains(out.Text, "https://sharefile.example/client/files") {
		t.Fatalf("text missing file list url: %q", out.Text)
	}
	if !strings.Contains(out.Text, "asked to log in") {
		t.Fatalf("text missing login guidance: %q", out.Text)
	}

	if _, err := renderer.RenderFileShared(FileSharedTemplateData{}); err == nil {
		t.Fatal("RenderFileShared() expected validation error")
	}
}
