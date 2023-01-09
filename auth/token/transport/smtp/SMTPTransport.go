package smtp

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/go-logr/logr"
)

type SMTPTransport struct {
	Username string
	Password string
	Host     string
	Port     int
	Headers  map[string]string

	Logger     logr.Logger
	CtxRqIDKey interface{}
}

// Send
// By default only "From" and "To" headers will be added to the email
// Any other headers including "Subject" should be configured
// With SMTPTransport.Headers field
func (t *SMTPTransport) Send(ctx context.Context, msg, receiver string) error {
	t.Logger.V(10).Info("auth.token.smtp.Send() started", "rquid", ctx.Value(t.CtxRqIDKey))
	defer t.Logger.V(10).Info("auth.token.smtp.Send() finished", "rquid", ctx.Value(t.CtxRqIDKey))

	auth := smtp.PlainAuth("", t.Username, t.Password, t.Host)

	to := []string{receiver}
	from := t.Username

	body := t.buildBody(from, receiver, msg)
	err := smtp.SendMail(fmt.Sprintf("%v:%v", t.Host, t.Port), auth, from, to, body)
	if err != nil {
		err = fmt.Errorf("auth.token.smtp.Send() SendMail error: %w", err)
		t.Logger.V(0).Info(
			"auth.token.smtp.Send() SendMail error",
			"rquid", ctx.Value(t.CtxRqIDKey),
			"err", err,
		)
	}
	return err
}

func (t *SMTPTransport) buildBody(from, to, msg string) []byte {
	builder := strings.Builder{}
	builder.WriteString(fmt.Sprintf("From: %v\r\n", from))
	builder.WriteString(fmt.Sprintf("To: %v\r\n", to))
	for k, v := range t.Headers {
		builder.WriteString(fmt.Sprintf("%v: %v\r\n", k, v))
	}
	builder.WriteString("\r\n")
	builder.WriteString(fmt.Sprintf("%v\r\n", msg))
	return []byte(builder.String())
}
