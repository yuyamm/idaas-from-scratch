// Command idaas runs the IdaaS server.
//
//	idaas serve      apply migrations and serve HTTP (with the outbox relay)
//	idaas migrate    apply migrations only
//	idaas bootstrap  create an Admin API client and print its credentials
//
// Configuration is read from environment variables; see README.md.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yuyamm/idaas-from-scratch/internal/app"
	"github.com/yuyamm/idaas-from-scratch/internal/authn"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/mail"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if err := run(cmd); err != nil {
		slog.Error("idaas", "err", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parseKeys reads ENCRYPTION_KEYS ("id1:base64key,id2:base64key").
func parseKeys(s string) (map[string][]byte, error) {
	keys := map[string][]byte{}
	for _, part := range strings.Split(s, ",") {
		id, b64, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok {
			return nil, errors.New("ENCRYPTION_KEYS must be id:base64key[,id:base64key]")
		}
		k, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("ENCRYPTION_KEYS %s: %w", id, err)
		}
		keys[id] = k
	}
	return keys, nil
}

func run(cmd string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.Open(ctx, env("DATABASE_URL", "postgres://idaas:idaas@localhost:54329/idaas?sslmode=disable"))
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := postgres.Migrate(ctx, pool); err != nil {
		return err
	}
	if cmd == "migrate" {
		slog.Info("migrations applied")
		return nil
	}

	rawKeys := os.Getenv("ENCRYPTION_KEYS")
	if rawKeys == "" {
		return errors.New("ENCRYPTION_KEYS is required (generate a key with: openssl rand -base64 32)")
	}
	keys, err := parseKeys(rawKeys)
	if err != nil {
		return err
	}
	active := env("ACTIVE_KEY_ID", strings.SplitN(strings.SplitN(rawKeys, ",", 2)[0], ":", 2)[0])

	var mailer mail.Sender = mail.Log{}
	if addr := os.Getenv("SMTP_ADDR"); addr != "" {
		mailer = mail.SMTP{Addr: addr, From: env("SMTP_FROM", "idaas@localhost"), Username: os.Getenv("SMTP_USERNAME"), Password: os.Getenv("SMTP_PASSWORD")}
	}
	cfg := app.Config{
		Pool: pool, BaseURL: env("BASE_URL", "http://localhost:8080"), EncryptionKeys: keys, ActiveKeyID: active, Mailer: mailer,
	}
	if os.Getenv("HIBP_DISABLED") == "" {
		cfg.BreachCheck = authn.NewHIBPClient(os.Getenv("HIBP_URL"), &http.Client{Timeout: 5 * time.Second})
	}
	a, err := app.New(cfg)
	if err != nil {
		return err
	}

	switch cmd {
	case "bootstrap":
		id, secret, err := a.Bootstrap(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("Admin API client created.\n  token_url:     %s/t/admin/token\n  client_id:     %s\n  client_secret: %s\n", cfg.BaseURL, id, secret)
		return nil
	case "serve":
		go a.RunBackground(ctx)
		srv := &http.Server{Addr: env("LISTEN_ADDR", ":8080"), Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			srv.Shutdown(shutdown)
		}()
		slog.Info("listening", "addr", srv.Addr, "base_url", cfg.BaseURL)
		var err error
		if cert := os.Getenv("TLS_CERT_FILE"); cert != "" {
			err = srv.ListenAndServeTLS(cert, os.Getenv("TLS_KEY_FILE"))
		} else {
			err = srv.ListenAndServe()
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	default:
		return fmt.Errorf("unknown command %q (serve, migrate, bootstrap)", cmd)
	}
}
