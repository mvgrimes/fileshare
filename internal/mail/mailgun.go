package mail

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type MailgunSender struct {
	apiBaseURL string
	domain     string
	apiKey     string
	fromEmail  string
	httpClient *http.Client
	renderer   TemplateRenderer
}

type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

func NewMailgunSender(apiBaseURL, domain, apiKey, fromEmail string, httpClient *http.Client, renderer TemplateRenderer) (*MailgunSender, error) {
	if strings.TrimSpace(apiBaseURL) == "" || strings.TrimSpace(domain) == "" || strings.TrimSpace(apiKey) == "" || strings.TrimSpace(fromEmail) == "" {
		return nil, fmt.Errorf("mailgun sender requires api base url, domain, api key, and from email")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if renderer == nil {
		return nil, fmt.Errorf("mailgun sender requires renderer")
	}
	return &MailgunSender{
		apiBaseURL: strings.TrimRight(apiBaseURL, "/"),
		domain:     domain,
		apiKey:     apiKey,
		fromEmail:  fromEmail,
		httpClient: httpClient,
		renderer:   renderer,
	}, nil
}

func (s *MailgunSender) SendMagicLink(ctx context.Context, clientID, token string) error {
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(token) == "" {
		return fmt.Errorf("client id and token are required")
	}
	rendered, err := s.renderer.RenderMagicLink(MagicLinkTemplateData{ToName: clientID, Token: token})
	if err != nil {
		return err
	}
	return s.Send(ctx, Message{To: clientID, Subject: rendered.Subject, Text: rendered.Text, HTML: rendered.HTML})
}

func (s *MailgunSender) Send(ctx context.Context, msg Message) error {
	if strings.TrimSpace(msg.To) == "" || strings.TrimSpace(msg.Subject) == "" {
		return fmt.Errorf("message to and subject are required")
	}
	if strings.TrimSpace(msg.Text) == "" && strings.TrimSpace(msg.HTML) == "" {
		return fmt.Errorf("message text or html is required")
	}

	v := url.Values{}
	v.Set("from", s.fromEmail)
	v.Set("to", msg.To)
	v.Set("subject", msg.Subject)
	if strings.TrimSpace(msg.Text) != "" {
		v.Set("text", msg.Text)
	}
	if strings.TrimSpace(msg.HTML) != "" {
		v.Set("html", msg.HTML)
	}

	endpoint := fmt.Sprintf("%s/v3/%s/messages", s.apiBaseURL, s.domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth("api", s.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("mailgun request failed with status %d", resp.StatusCode)
	}
	return nil
}
