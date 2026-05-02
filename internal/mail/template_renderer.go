package mail

import (
	"fmt"
	"strings"

	"github.com/matcornic/hermes/v2"
)

type TemplateRenderer interface {
	RenderMagicLink(data MagicLinkTemplateData) (RenderedTemplate, error)
}

type RenderedTemplate struct {
	Subject string
	HTML    string
	Text    string
}

type MagicLinkTemplateData struct {
	ToName      string
	LoginURL    string
	SupportEmail string
}

type HermesRenderer struct {
	engine hermes.Hermes
}

func NewHermesRenderer(productName, productLink, productLogo string) (*HermesRenderer, error) {
	if strings.TrimSpace(productName) == "" {
		return nil, fmt.Errorf("product name is required")
	}
	if strings.TrimSpace(productLink) == "" {
		return nil, fmt.Errorf("product link is required")
	}

	return &HermesRenderer{
		engine: hermes.Hermes{
			Product: hermes.Product{
				Name: productName,
				Link: productLink,
				Logo: strings.TrimSpace(productLogo),
			},
		},
	}, nil
}

func (r *HermesRenderer) RenderMagicLink(data MagicLinkTemplateData) (RenderedTemplate, error) {
	if strings.TrimSpace(data.LoginURL) == "" {
		return RenderedTemplate{}, fmt.Errorf("login url is required")
	}

	name := strings.TrimSpace(data.ToName)
	if name == "" {
		name = "there"
	}

	body := hermes.Email{
		Body: hermes.Body{
			Name: name,
			Intros: []string{
				"Use the secure link below to sign in to ShareFile.",
			},
			Actions: []hermes.Action{
				{
					Instructions: "This sign-in link expires soon for your security:",
					Button: hermes.Button{
						Color: "#1A7F64",
						Text:  "Sign in to ShareFile",
						Link:  data.LoginURL,
					},
				},
			},
			Outros: magicOutro(data.SupportEmail),
		},
	}

	htmlBody, err := r.engine.GenerateHTML(body)
	if err != nil {
		return RenderedTemplate{}, err
	}

	textBody, err := r.engine.GeneratePlainText(body)
	if err != nil {
		return RenderedTemplate{}, err
	}

	return RenderedTemplate{
		Subject: "Your ShareFile magic login link",
		HTML:    htmlBody,
		Text:    textBody,
	}, nil
}

func magicOutro(supportEmail string) []string {
	supportEmail = strings.TrimSpace(supportEmail)
	if supportEmail == "" {
		return []string{"If you did not request this link, you can safely ignore this email."}
	}
	return []string{
		fmt.Sprintf("Need help? Contact %s.", supportEmail),
		"If you did not request this link, you can safely ignore this email.",
	}
}
