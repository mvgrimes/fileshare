package mail

import (
	"context"
	"fmt"
	"strings"
)

type MessageSender interface {
	Send(ctx context.Context, msg Message) error
}

type NoopMessageSender struct{}

func (NoopMessageSender) Send(context.Context, Message) error { return nil }

type Notifier struct {
	renderer TemplateRenderer
	sender   MessageSender
	events   *EventStore
}

type FileSharedNotification struct {
	RecipientEmail string
	RecipientName  string
	ActorLabel     string
	FileName       string
	Message        string
	TargetType     string
	TargetID       string
}

type ClientUploadNotification struct {
	RecipientEmail string
	RecipientName  string
	ClientLabel    string
	TargetType     string
	TargetID       string
}

func NewNotifier(renderer TemplateRenderer, sender MessageSender, events *EventStore) *Notifier {
	if sender == nil {
		sender = NoopMessageSender{}
	}
	return &Notifier{renderer: renderer, sender: sender, events: events}
}

func (n *Notifier) NotifyFileShared(ctx context.Context, in FileSharedNotification) error {
	rendered, err := n.renderer.RenderFileShared(FileSharedTemplateData{
		ToName:      in.RecipientName,
		ActorLabel:  in.ActorLabel,
		FileName:    in.FileName,
		Message:     in.Message,
		FileListURL: "/client/files",
	})
	if err != nil {
		return err
	}

	eventID := ""
	if n.events != nil {
		eventID, _ = n.events.RecordPending(ctx, "file.shared", in.RecipientEmail, "", map[string]any{"target_type": in.TargetType, "target_id": in.TargetID})
	}
	err = n.sender.Send(ctx, Message{To: in.RecipientEmail, Subject: rendered.Subject, Text: rendered.Text, HTML: rendered.HTML})
	if n.events != nil && eventID != "" {
		if err != nil {
			_ = n.events.MarkFailed(ctx, eventID, err.Error(), "")
		} else {
			_ = n.events.MarkDelivered(ctx, eventID, "")
		}
	}
	return err
}

func (n *Notifier) NotifyClientUpload(ctx context.Context, in ClientUploadNotification) error {
	rendered, err := n.renderer.RenderMagicLink(MagicLinkTemplateData{
		ToName:       in.RecipientName,
		Token:        "A client upload was submitted for your attention.",
		SupportEmail: "",
	})
	if err != nil {
		return err
	}
	rendered.Subject = "Client upload notification"
	rendered.Text = strings.Join([]string{
		fmt.Sprintf("%s submitted an upload to %s.", in.ClientLabel, in.TargetType),
		rendered.Text,
	}, "\n")

	eventID := ""
	if n.events != nil {
		eventID, _ = n.events.RecordPending(ctx, "client.upload", in.RecipientEmail, "", map[string]any{"target_type": in.TargetType, "target_id": in.TargetID})
	}
	err = n.sender.Send(ctx, Message{To: in.RecipientEmail, Subject: rendered.Subject, Text: rendered.Text, HTML: rendered.HTML})
	if n.events != nil && eventID != "" {
		if err != nil {
			_ = n.events.MarkFailed(ctx, eventID, err.Error(), "")
		} else {
			_ = n.events.MarkDelivered(ctx, eventID, "")
		}
	}
	return err
}
