package authn

import (
	"context"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/yuyamm/idaas-from-scratch/internal/audit"
	"github.com/yuyamm/idaas-from-scratch/internal/identity"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/crypto"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/postgres"
	"github.com/yuyamm/idaas-from-scratch/internal/platform/secret"
)

var ErrInvalidOTP = errors.New("authn: invalid one-time code")

const (
	totpPeriod        = 30
	recoveryCodeCount = 10
)

func WithEncrypter(e crypto.Encrypter) Option { return func(s *Service) { s.enc = e } }

type TOTPEnrollment struct {
	ID     uuid.UUID
	Secret string // base32, shown to the user once
	URL    string // otpauth:// URL for QR codes
}

type MFAFactor struct {
	ID         uuid.UUID
	Type       string // totp, webauthn, recovery_codes
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

func totpAAD(tenantID, userID uuid.UUID) []byte {
	return []byte("totp:" + tenantID.String() + ":" + userID.String())
}

// EnrollTOTP creates an unconfirmed TOTP credential. Any previous unconfirmed
// enrollment is replaced.
func (s *Service) EnrollTOTP(ctx context.Context, tenant identity.Tenant, userID uuid.UUID) (TOTPEnrollment, error) {
	u, err := identity.GetUserTx(ctx, s.pool, tenant.ID, userID)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "IdaaS (" + tenant.Slug + ")", AccountName: u.LoginID})
	if err != nil {
		return TOTPEnrollment{}, err
	}
	ct, keyID, err := s.enc.Encrypt([]byte(key.Secret()), totpAAD(tenant.ID, userID))
	if err != nil {
		return TOTPEnrollment{}, err
	}
	id := uuid.New()
	err = postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM totp_credentials WHERE tenant_id = $1 AND user_id = $2 AND confirmed_at IS NULL`, tenant.ID, userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO totp_credentials (id, tenant_id, user_id, secret_encrypted, encryption_key_id) VALUES ($1, $2, $3, $4, $5)`,
			id, tenant.ID, userID, ct, keyID)
		return err
	})
	if err != nil {
		return TOTPEnrollment{}, err
	}
	return TOTPEnrollment{ID: id, Secret: key.Secret(), URL: key.URL()}, nil
}

// ConfirmTOTP activates the pending TOTP credential with a valid code and
// returns freshly generated recovery codes.
func (s *Service) ConfirmTOTP(ctx context.Context, tenant identity.Tenant, userID uuid.UUID, code string) ([]string, error) {
	var codes []string
	err := postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.checkTOTP(ctx, tx, tenant.ID, userID, code, false); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM totp_credentials WHERE tenant_id = $1 AND user_id = $2 AND confirmed_at IS NOT NULL`, tenant.ID, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE totp_credentials SET confirmed_at = $3 WHERE tenant_id = $1 AND user_id = $2`, tenant.ID, userID, s.Now()); err != nil {
			return err
		}
		var err error
		codes, err = s.replaceRecoveryCodes(ctx, tx, tenant.ID, userID)
		if err != nil {
			return err
		}
		return audit.Record(ctx, tx, audit.Event{
			TenantID: tenant.ID, Type: "user.mfa_enrolled", TargetType: "user", TargetID: userID.String(),
			Data: map[string]any{"type": "totp"},
		})
	})
	return codes, err
}

// VerifyTOTP checks a code against the confirmed TOTP credential. Each time
// step can be used once.
func (s *Service) VerifyTOTP(ctx context.Context, tenant identity.Tenant, userID uuid.UUID, code string) error {
	return postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		return s.checkTOTP(ctx, tx, tenant.ID, userID, code, true)
	})
}

func (s *Service) checkTOTP(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID, code string, confirmed bool) error {
	cond := "confirmed_at IS NULL"
	if confirmed {
		cond = "confirmed_at IS NOT NULL"
	}
	var (
		id       uuid.UUID
		ct       []byte
		keyID    string
		lastStep int64
	)
	err := tx.QueryRow(ctx, `SELECT id, secret_encrypted, encryption_key_id, last_used_step FROM totp_credentials
		WHERE tenant_id = $1 AND user_id = $2 AND `+cond+` FOR UPDATE`, tenantID, userID).Scan(&id, &ct, &keyID, &lastStep)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidOTP
	}
	if err != nil {
		return err
	}
	seed, err := s.enc.Decrypt(ct, keyID, totpAAD(tenantID, userID))
	if err != nil {
		return err
	}
	now := s.Now()
	current := now.Unix() / totpPeriod
	for _, step := range []int64{current, current - 1, current + 1} {
		if step <= lastStep {
			continue
		}
		want, err := totp.GenerateCodeCustom(string(seed), time.Unix(step*totpPeriod, 0),
			totp.ValidateOpts{Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(strings.TrimSpace(code))) == 1 {
			_, err := tx.Exec(ctx, `UPDATE totp_credentials SET last_used_step = $2 WHERE id = $1`, id, step)
			return err
		}
	}
	return ErrInvalidOTP
}

func (s *Service) replaceRecoveryCodes(ctx context.Context, q postgres.Querier, tenantID, userID uuid.UUID) ([]string, error) {
	if _, err := q.Exec(ctx, `DELETE FROM recovery_codes WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID); err != nil {
		return nil, err
	}
	codes := make([]string, recoveryCodeCount)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for i := range codes {
		raw := strings.ToLower(enc.EncodeToString(secret.RandomBytes(8)))[:12]
		codes[i] = raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12]
		if _, err := q.Exec(ctx, `INSERT INTO recovery_codes (id, tenant_id, user_id, code_hash) VALUES ($1, $2, $3, $4)`,
			uuid.New(), tenantID, userID, secret.HashToken(normalizeRecoveryCode(codes[i]))); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

func normalizeRecoveryCode(c string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c), "-", ""))
}

// UseRecoveryCode consumes a recovery code.
func (s *Service) UseRecoveryCode(ctx context.Context, tenant identity.Tenant, userID uuid.UUID, code string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE recovery_codes SET used_at = $4
		WHERE tenant_id = $1 AND user_id = $2 AND code_hash = $3 AND used_at IS NULL`,
		tenant.ID, userID, secret.HashToken(normalizeRecoveryCode(code)), s.Now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidOTP
	}
	return nil
}

// HasMFA reports whether the user has a confirmed second factor.
func (s *Service) HasMFA(ctx context.Context, tenantID, userID uuid.UUID) (bool, error) {
	var has bool
	err := s.pool.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM totp_credentials WHERE tenant_id = $1 AND user_id = $2 AND confirmed_at IS NOT NULL) OR
		EXISTS (SELECT 1 FROM webauthn_credentials WHERE tenant_id = $1 AND user_id = $2)`, tenantID, userID).Scan(&has)
	return has, err
}

func (s *Service) ListMFAFactors(ctx context.Context, tenantID, userID uuid.UUID) ([]MFAFactor, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, 'totp', '', created_at, NULL::timestamptz FROM totp_credentials WHERE tenant_id = $1 AND user_id = $2 AND confirmed_at IS NOT NULL
		UNION ALL
		SELECT id, 'webauthn', label, created_at, last_used_at FROM webauthn_credentials WHERE tenant_id = $1 AND user_id = $2
		ORDER BY 4`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	factors, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (MFAFactor, error) {
		var f MFAFactor
		return f, r.Scan(&f.ID, &f.Type, &f.Label, &f.CreatedAt, &f.LastUsedAt)
	})
	if err != nil {
		return nil, err
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE tenant_id = $1 AND user_id = $2 AND used_at IS NULL`, tenantID, userID).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		factors = append(factors, MFAFactor{ID: uuid.NewSHA1(userID, []byte("recovery_codes")), Type: "recovery_codes", Label: fmt.Sprintf("%d remaining", n)})
	}
	return factors, nil
}

// DeleteMFAFactor removes a factor. Removing the last factor also removes the
// recovery codes.
func (s *Service) DeleteMFAFactor(ctx context.Context, tenantID, userID, factorID uuid.UUID) error {
	return postgres.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var n int64
		for _, q := range []string{
			`DELETE FROM totp_credentials WHERE tenant_id = $1 AND user_id = $2 AND id = $3`,
			`DELETE FROM webauthn_credentials WHERE tenant_id = $1 AND user_id = $2 AND id = $3`,
		} {
			tag, err := tx.Exec(ctx, q, tenantID, userID, factorID)
			if err != nil {
				return err
			}
			n += tag.RowsAffected()
		}
		if factorID == uuid.NewSHA1(userID, []byte("recovery_codes")) {
			tag, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
			if err != nil {
				return err
			}
			n += tag.RowsAffected()
		}
		if n == 0 {
			return identity.ErrNotFound
		}
		var remaining bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM totp_credentials WHERE tenant_id = $1 AND user_id = $2 AND confirmed_at IS NOT NULL)
			OR EXISTS (SELECT 1 FROM webauthn_credentials WHERE tenant_id = $1 AND user_id = $2)`, tenantID, userID).Scan(&remaining); err != nil {
			return err
		}
		if !remaining {
			if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID); err != nil {
				return err
			}
		}
		return audit.Record(ctx, tx, audit.Event{
			TenantID: tenantID, Type: "user.mfa_removed", TargetType: "user", TargetID: userID.String(),
			Data: map[string]any{"factor_id": factorID},
		})
	})
}
