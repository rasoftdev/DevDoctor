package config

import (
	"errors"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// NotifyConfig configura los avisos a Telegram y Slack cuando aparece un problema nuevo.
type NotifyConfig struct {
	TelegramToken  string `json:"telegram_token,omitempty"`
	TelegramChatID string `json:"telegram_chat_id,omitempty"`
	SlackWebhook   string `json:"slack_webhook,omitempty"`
	MinSeverity    string `json:"min_severity,omitempty"` // "crit" (por defecto) o "warn"
	Lang           string `json:"lang,omitempty"`         // idioma de los mensajes: "en" o "es"
	Recovery       bool   `json:"recovery,omitempty"`     // avisar también cuando un problema se resuelve
}

func (n NotifyConfig) TelegramEnabled() bool { return n.TelegramToken != "" && n.TelegramChatID != "" }
func (n NotifyConfig) SlackEnabled() bool    { return n.SlackWebhook != "" }
func (n NotifyConfig) Enabled() bool         { return n.TelegramEnabled() || n.SlackEnabled() }

var (
	tgTokenRe = regexp.MustCompile(`^\d{6,12}:[A-Za-z0-9_-]{30,50}$`)
	tgChatRe  = regexp.MustCompile(`^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{3,31})$`)
)

// Validate comprueba el formato de las credenciales (sin conectar con nadie).
// El webhook de Slack debe ser de hooks.slack.com para que el servidor no pueda usarse contra direcciones internas.
func (n *NotifyConfig) Validate() error {
	n.TelegramToken = strings.TrimSpace(n.TelegramToken)
	n.TelegramChatID = strings.TrimSpace(n.TelegramChatID)
	n.SlackWebhook = strings.TrimSpace(n.SlackWebhook)
	if (n.TelegramToken != "") != (n.TelegramChatID != "") {
		return errors.New("telegram needs both the bot token and the chat ID")
	}
	if n.TelegramToken != "" {
		if !tgTokenRe.MatchString(n.TelegramToken) {
			return errors.New("invalid Telegram bot token format")
		}
		if !tgChatRe.MatchString(n.TelegramChatID) {
			return errors.New("invalid Telegram chat ID (use the numeric ID or @channelname)")
		}
	}
	if n.SlackWebhook != "" {
		u, err := url.Parse(n.SlackWebhook)
		testMode := os.Getenv("DEVDOCTOR_NOTIFY_TEST") == "1" // sólo para pruebas automáticas
		ok := err == nil && u.Scheme == "https" && u.Host == "hooks.slack.com" && strings.HasPrefix(u.Path, "/services/")
		if testMode && err == nil && strings.HasPrefix(u.Host, "127.0.0.1") {
			ok = true
		}
		if !ok {
			return errors.New("invalid Slack webhook URL (it must look like https://hooks.slack.com/services/...)")
		}
	}
	switch n.MinSeverity {
	case "", "crit", "warn":
	default:
		return errors.New("invalid minimum severity")
	}
	switch n.Lang {
	case "", "en", "es":
	default:
		return errors.New("invalid language")
	}
	return nil
}
