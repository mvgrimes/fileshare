package mail

import (
	"fmt"
	"strings"

	"github.com/matcornic/hermes/v2"
)

type TemplateRenderer interface {
	RenderMagicLink(data MagicLinkTemplateData) (RenderedTemplate, error)
	RenderInvitation(data InvitationTemplateData) (RenderedTemplate, error)
	RenderFileShared(data FileSharedTemplateData) (RenderedTemplate, error)
	RenderPasswordReset(data PasswordResetTemplateData) (RenderedTemplate, error)
}

type RenderedTemplate struct {
	Subject string
	HTML    string
	Text    string
}

type MagicLinkTemplateData struct {
	ToName       string
	LoginURL     string
	Token        string
	SupportEmail string
}

type HermesRenderer struct {
	engine hermes.Hermes
}

type InvitationTemplateData struct {
	ToName       string
	InviteURL    string
	InviterLabel string
}

type FileSharedTemplateData struct {
	ToName      string
	ActorLabel  string
	FileName    string
	Message     string
	FileListURL string
}

type PasswordResetTemplateData struct {
	ToName    string
	ResetURL  string
	ActorType string
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
	hasURL := strings.TrimSpace(data.LoginURL) != ""
	hasToken := strings.TrimSpace(data.Token) != ""
	if !hasURL && !hasToken {
		return RenderedTemplate{}, fmt.Errorf("login url or token is required")
	}
	loginURL := strings.TrimSpace(data.LoginURL)
	if strings.HasPrefix(loginURL, "/") {
		loginURL = strings.TrimRight(r.engine.Product.Link, "/") + loginURL
	}

	name := strings.TrimSpace(data.ToName)
	if name == "" {
		name = "there"
	}

	actions := []hermes.Action{}
	productName := strings.TrimSpace(r.engine.Product.Name)
	if productName == "" {
		productName = "FileShare"
	}
	intro := fmt.Sprintf("Use the secure link below to sign in to %s.", productName)
	if hasURL {
		actions = append(actions, hermes.Action{
			Instructions: "This sign-in link expires soon for your security:",
			Button: hermes.Button{
				Color: "#1A7F64",
				Text:  fmt.Sprintf("Sign in to %s", productName),
				Link:  loginURL,
			},
		})
	} else {
		intro = fmt.Sprintf("Use the one-time token below to sign in to %s.", productName)
		actions = append(actions, hermes.Action{
			Instructions: "Enter this one-time token to sign in:",
			InviteCode:   data.Token,
		})
	}

	body := hermes.Email{
		Body: hermes.Body{
			Name: name,
			Intros: []string{
				intro,
			},
			Actions: actions,
			Outros:  magicOutro(data.SupportEmail),
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
		Subject: fmt.Sprintf("Your %s magic login link", productName),
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

func (r *HermesRenderer) RenderInvitation(data InvitationTemplateData) (RenderedTemplate, error) {
	if strings.TrimSpace(data.InviteURL) == "" {
		return RenderedTemplate{}, fmt.Errorf("invite url is required")
	}
	name := strings.TrimSpace(data.ToName)
	if name == "" {
		name = "there"
	}
	inviter := strings.TrimSpace(data.InviterLabel)
	productName := strings.TrimSpace(r.engine.Product.Name)
	if productName == "" {
		productName = "FileShare"
	}
	if inviter == "" {
		inviter = fmt.Sprintf("A %s administrator", productName)
	}
	body := hermes.Email{Body: hermes.Body{
		Name:   name,
		Intros: []string{fmt.Sprintf("%s invited you to access files in %s.", inviter, productName)},
		Actions: []hermes.Action{{
			Instructions: "Use the button below to complete your setup:",
			Button:       hermes.Button{Color: "#1A7F64", Text: "Complete setup", Link: data.InviteURL},
		}},
		Outros: []string{"If this was unexpected, you can ignore this message."},
	}}

	htmlBody, err := r.engine.GenerateHTML(body)
	if err != nil {
		return RenderedTemplate{}, err
	}
	textBody, err := r.engine.GeneratePlainText(body)
	if err != nil {
		return RenderedTemplate{}, err
	}
	return RenderedTemplate{Subject: fmt.Sprintf("You are invited to %s", productName), HTML: htmlBody, Text: textBody}, nil
}

func (r *HermesRenderer) RenderFileShared(data FileSharedTemplateData) (RenderedTemplate, error) {
	if strings.TrimSpace(data.FileListURL) == "" {
		return RenderedTemplate{}, fmt.Errorf("file list url is required")
	}
	fileListURL := strings.TrimSpace(data.FileListURL)
	if strings.HasPrefix(fileListURL, "/") {
		fileListURL = strings.TrimRight(r.engine.Product.Link, "/") + fileListURL
	}

	name := strings.TrimSpace(data.ToName)
	if name == "" {
		name = "there"
	}
	actor := strings.TrimSpace(data.ActorLabel)
	if actor == "" {
		actor = "Someone"
	}
	fileName := strings.TrimSpace(data.FileName)
	if fileName == "" {
		fileName = "a file"
	}

	intros := []string{fmt.Sprintf("%s shared %s with you.", actor, fileName)}
	message := strings.TrimSpace(data.Message)
	if message != "" {
		intros = append(intros, fmt.Sprintf("Message: %s", message))
	}

	body := hermes.Email{Body: hermes.Body{
		Name:   name,
		Intros: intros,
		Actions: []hermes.Action{{
			Instructions: "Use the button below to view your shared files:",
			Button:       hermes.Button{Color: "#1A7F64", Text: "View shared files", Link: fileListURL},
		}},
		Outros: []string{"You may be asked to log in before you can view the file."},
	}}

	htmlBody, err := r.engine.GenerateHTML(body)
	if err != nil {
		return RenderedTemplate{}, err
	}
	textBody, err := r.engine.GeneratePlainText(body)
	if err != nil {
		return RenderedTemplate{}, err
	}

	return RenderedTemplate{Subject: "A file was shared with you", HTML: htmlBody, Text: textBody}, nil
}

func (r *HermesRenderer) RenderPasswordReset(data PasswordResetTemplateData) (RenderedTemplate, error) {
	if strings.TrimSpace(data.ResetURL) == "" {
		return RenderedTemplate{}, fmt.Errorf("reset url is required")
	}
	resetURL := strings.TrimSpace(data.ResetURL)
	if strings.HasPrefix(resetURL, "/") {
		resetURL = strings.TrimRight(r.engine.Product.Link, "/") + resetURL
	}
	name := strings.TrimSpace(data.ToName)
	if name == "" {
		name = "there"
	}
	actorType := strings.TrimSpace(data.ActorType)
	if actorType == "" {
		actorType = "account"
	}
	body := hermes.Email{Body: hermes.Body{
		Name:   name,
		Intros: []string{fmt.Sprintf("A password reset was requested for your %s.", actorType)},
		Actions: []hermes.Action{{
			Instructions: "Use the button below to set a new password:",
			Button:       hermes.Button{Color: "#1A7F64", Text: "Reset password", Link: resetURL},
		}},
		Outros: []string{"If you did not request this change, you can safely ignore this email."},
	}}

	htmlBody, err := r.engine.GenerateHTML(body)
	if err != nil {
		return RenderedTemplate{}, err
	}
	textBody, err := r.engine.GeneratePlainText(body)
	if err != nil {
		return RenderedTemplate{}, err
	}
	productName := strings.TrimSpace(r.engine.Product.Name)
	if productName == "" {
		productName = "FileShare"
	}
	return RenderedTemplate{Subject: fmt.Sprintf("Reset your %s password", productName), HTML: htmlBody, Text: textBody}, nil
}
