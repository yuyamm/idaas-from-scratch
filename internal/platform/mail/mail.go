// Package mail sends email. Sender is the seam used by authn flows.
package mail

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
)

type Sender interface {
	Send(ctx context.Context, to, subject, body string) error
}

// Log writes mails to the log instead of sending them (development).
type Log struct{}

func (Log) Send(_ context.Context, to, subject, body string) error {
	slog.Info("mail (not sent)", "to", to, "subject", subject, "body", body)
	return nil
}

// SMTP sends mail through an SMTP server. net/smtp upgrades the connection
// with STARTTLS whenever the server offers it.
type SMTP struct {
	Addr     string // host:port
	From     string
	Username string
	Password string
}

func (s SMTP) Send(_ context.Context, to, subject, body string) error {
	host, _, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return err
	}
	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, host)
	}
	msg := strings.Join([]string{
		"From: " + s.From, "To: " + to, "Subject: " + subject,
		"MIME-Version: 1.0", "Content-Type: text/plain; charset=UTF-8", "", body,
	}, "\r\n")
	if err := smtp.SendMail(s.Addr, auth, s.From, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("mail: send: %w", err)
	}
	return nil
}
