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
}

func NewMailgunSender(apiBaseURL, domain, apiKey, fromEmail string, httpClient *http.Client) (*MailgunSender, error) {
	if strings.TrimSpace(apiBaseURL) == "" || strings.TrimSpace(domain) == "" || strings.TrimSpace(apiKey) == "" || strings.TrimSpace(fromEmail) == "" {
		return nil, fmt.Errorf("mailgun sender requires api base url, domain, api key, and from email")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &MailgunSender{
		apiBaseURL: strings.TrimRight(apiBaseURL, "/"),
		domain:     domain,
		apiKey:     apiKey,
		fromEmail:  fromEmail,
		httpClient: httpClient,
	}, nil
}

func (s *MailgunSender) SendMagicLink(ctx context.Context, clientID, token string) error {
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(token) == "" {
		return fmt.Errorf("client id and token are required")
	}

	v := url.Values{}
	v.Set("from", s.fromEmail)
	v.Set("to", clientID)
	v.Set("subject", "Your ShareFile magic login link")
	v.Set("text", fmt.Sprintf("Use this token to sign in: %s", token))

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
