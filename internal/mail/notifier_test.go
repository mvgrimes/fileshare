package mail

import (
	"context"
	"errors"
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

type stubMessageSender struct {
	err  error
	last Message
}

func (s *stubMessageSender) Send(_ context.Context, msg Message) error {
	s.last = msg
	return s.err
}

func TestNotifierNotifyFileShared(t *testing.T) {
	t.Parallel()

	sender := &stubMessageSender{}
	n := NewNotifier(stubRenderer{rendered: RenderedTemplate{Subject: "base", Text: "text", HTML: "<p>ok</p>"}}, sender, nil)
	err := n.NotifyFileShared(t.Context(), FileSharedNotification{
		RecipientEmail: "client@example.com",
		ActorLabel:     "user-1",
		FileName:       "report.pdf",
	})
	if err != nil {
		t.Fatalf("NotifyFileShared() error: %v", err)
	}
	if sender.last.Subject != "A file was shared with you" {
		t.Fatalf("subject = %q", sender.last.Subject)
	}
}

func TestNotifierNotifyClientUploadError(t *testing.T) {
	t.Parallel()

	sender := &stubMessageSender{err: errors.New("send fail")}
	n := NewNotifier(stubRenderer{rendered: RenderedTemplate{Subject: "base", Text: "text", HTML: "<p>ok</p>"}}, sender, nil)
	err := n.NotifyClientUpload(t.Context(), ClientUploadNotification{RecipientEmail: "user@example.com", ClientLabel: "client-1", TargetType: "user"})
	if err == nil {
		t.Fatal("NotifyClientUpload() error=nil, want error")
	}
}
