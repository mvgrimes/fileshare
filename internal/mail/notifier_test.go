package mail

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type stubRenderer struct {
	err      error
	rendered RenderedTemplate
}

func (s stubRenderer) RenderMagicLink(MagicLinkTemplateData) (RenderedTemplate, error) {
	if s.err != nil {
		return RenderedTemplate{}, s.err
	}
	return s.rendered, nil
}

func (s stubRenderer) RenderInvitation(InvitationTemplateData) (RenderedTemplate, error) {
	if s.err != nil {
		return RenderedTemplate{}, s.err
	}
	return s.rendered, nil
}

func (s stubRenderer) RenderFileShared(FileSharedTemplateData) (RenderedTemplate, error) {
	if s.err != nil {
		return RenderedTemplate{}, s.err
	}
	return s.rendered, nil
}

func (s stubRenderer) RenderPasswordReset(PasswordResetTemplateData) (RenderedTemplate, error) {
	if s.err != nil {
		return RenderedTemplate{}, s.err
	}
	return s.rendered, nil
}

type stubMessageSender struct {
	err  error
	last Message
}

type captureFileSharedRenderer struct {
	stubRenderer
	lastFileSharedData FileSharedTemplateData
}

func (r *captureFileSharedRenderer) RenderFileShared(
	data FileSharedTemplateData,
) (RenderedTemplate, error) {
	r.lastFileSharedData = data
	if r.err != nil {
		return RenderedTemplate{}, r.err
	}
	return r.rendered, nil
}

func (s *stubMessageSender) Send(_ context.Context, msg Message) error {
	s.last = msg
	return s.err
}

func TestNotifierNotifyFileShared(t *testing.T) {
	t.Parallel()

	sender := &stubMessageSender{}
	renderer := &captureFileSharedRenderer{
		stubRenderer: stubRenderer{
			rendered: RenderedTemplate{Subject: "base", Text: "text", HTML: "<p>ok</p>"},
		},
	}
	n := NewNotifier(
		renderer,
		sender,
		nil,
	)
	err := n.NotifyFileShared(t.Context(), FileSharedNotification{
		RecipientEmail: "client@example.com",
		ActorLabel:     "user-1",
		FileName:       "report.pdf",
	})
	if err != nil {
		t.Fatalf("NotifyFileShared() error: %v", err)
	}
	if sender.last.Subject != "base" {
		t.Fatalf("subject = %q", sender.last.Subject)
	}
	if renderer.lastFileSharedData.FileListURL != "/login?email=client%40example.com" {
		t.Fatalf("file list url = %q", renderer.lastFileSharedData.FileListURL)
	}
}

func TestNotifierNotifyClientUploadError(t *testing.T) {
	t.Parallel()

	sender := &stubMessageSender{err: errors.New("send fail")}
	n := NewNotifier(
		stubRenderer{rendered: RenderedTemplate{Subject: "base", Text: "text", HTML: "<p>ok</p>"}},
		sender,
		nil,
	)
	err := n.NotifyClientUpload(
		t.Context(),
		ClientUploadNotification{
			RecipientEmail: "user@example.com",
			ClientLabel:    "client-1",
			TargetType:     "user",
		},
	)
	if err == nil {
		t.Fatal("NotifyClientUpload() error=nil, want error")
	}
}

func TestNotifierNotifyClientUploadUsesClientUploadContent(t *testing.T) {
	t.Parallel()

	sender := &stubMessageSender{}
	n := NewNotifier(
		stubRenderer{
			rendered: RenderedTemplate{Subject: "base", Text: "template text", HTML: "<p>ok</p>"},
		},
		sender,
		nil,
	)
	err := n.NotifyClientUpload(
		t.Context(),
		ClientUploadNotification{
			RecipientEmail: "user@example.com",
			ClientLabel:    "Acme Corp",
			FileName:       "report.pdf",
			Message:        "please review",
			TargetType:     "user",
		},
	)
	if err != nil {
		t.Fatalf("NotifyClientUpload() error: %v", err)
	}
	if sender.last.Subject != "Client upload notification" {
		t.Fatalf("subject = %q, want %q", sender.last.Subject, "Client upload notification")
	}
	if !strings.Contains(sender.last.Text, "Acme Corp submitted a file for user.") {
		t.Fatalf("text = %q, want upload context", sender.last.Text)
	}
	if !strings.Contains(sender.last.Text, "template text") {
		t.Fatalf("text = %q, want rendered body", sender.last.Text)
	}
}

func TestNotifierNotifyPasswordReset(t *testing.T) {
	t.Parallel()

	sender := &stubMessageSender{}
	n := NewNotifier(
		stubRenderer{rendered: RenderedTemplate{Subject: "reset", Text: "text", HTML: "<p>ok</p>"}},
		sender,
		nil,
	)
	err := n.NotifyPasswordReset(
		t.Context(),
		PasswordResetNotification{
			RecipientEmail: "u@example.com",
			RecipientName:  "U",
			ActorType:      "user",
			Token:          "tok-1",
		},
	)
	if err != nil {
		t.Fatalf("NotifyPasswordReset() error: %v", err)
	}
	if sender.last.Subject != "reset" {
		t.Fatalf("subject = %q", sender.last.Subject)
	}
}
