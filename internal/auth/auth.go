// Package auth handles password hashing, sessions and authorization.
//
// Passwords are hashed with Argon2id using per-password random salts, and the
// encoded hash carries its own parameters so they can be raised later without
// invalidating existing accounts. Session tokens are 256-bit random values;
// only their SHA-256 is stored, so a database copy does not let anyone log in.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/argon2"

	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/store"
)

// Errors returned by Authenticate.
var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountDisabled    = errors.New("account is disabled")
	ErrAccountLocked      = errors.New("account is temporarily locked after too many failed attempts")
	ErrWeakPassword       = errors.New("password is too weak")
)

// Argon2id parameters. Tuned for an interactive login on a laptop: ~60 ms.
const (
	argonTime    = 2
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// HashPassword returns an encoded Argon2id hash.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against an encoded hash in constant time.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory uint32
	var timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ValidatePassword enforces a minimal policy: long enough, and not a single
// character class. Deliberately permissive about symbols - length matters more.
func ValidatePassword(p string) error {
	if len(p) < 12 {
		return fmt.Errorf("%w: use at least 12 characters", ErrWeakPassword)
	}
	if len(p) > 256 {
		return fmt.Errorf("%w: at most 256 characters", ErrWeakPassword)
	}
	var classes int
	for _, check := range []func(rune) bool{unicode.IsLower, unicode.IsUpper, unicode.IsDigit} {
		if strings.ContainsFunc(p, check) {
			classes++
		}
	}
	if strings.ContainsFunc(p, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		classes++
	}
	if classes < 2 {
		return fmt.Errorf("%w: mix at least two character classes", ErrWeakPassword)
	}
	return nil
}

// GenerateToken returns a URL-safe 256-bit random token.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken is the storage form of a session token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Service ties the store to the session policy.
type Service struct {
	st             *store.Store
	sessionTTL     time.Duration
	sessionIdleTTL time.Duration
	maxAttempts    int
	lockoutWindow  time.Duration
}

// Config configures the auth service.
type Config struct {
	SessionTTL     time.Duration
	SessionIdleTTL time.Duration
	MaxAttempts    int
	LockoutWindow  time.Duration
}

// New builds the auth service.
func New(st *store.Store, cfg Config) *Service {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if cfg.SessionIdleTTL <= 0 || cfg.SessionIdleTTL > cfg.SessionTTL {
		cfg.SessionIdleTTL = cfg.SessionTTL
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 8
	}
	if cfg.LockoutWindow <= 0 {
		cfg.LockoutWindow = 15 * time.Minute
	}
	return &Service{
		st:             st,
		sessionTTL:     cfg.SessionTTL,
		sessionIdleTTL: cfg.SessionIdleTTL,
		maxAttempts:    cfg.MaxAttempts,
		lockoutWindow:  cfg.LockoutWindow,
	}
}

// Authenticate verifies credentials and applies the lockout policy.
func (s *Service) Authenticate(ctx context.Context, username, password string) (model.User, error) {
	user, err := s.st.UserByName(ctx, username)
	if err != nil {
		// Spend a comparable amount of time so a missing account is not
		// distinguishable from a wrong password by timing alone.
		_ = VerifyPassword("$argon2id$v=19$m=65536,t=2,p=4$"+
			base64.RawStdEncoding.EncodeToString(make([]byte, saltLen))+"$"+
			base64.RawStdEncoding.EncodeToString(make([]byte, argonKeyLen)), password)
		return model.User{}, ErrInvalidCredentials
	}
	if user.Disabled {
		return model.User{}, ErrAccountDisabled
	}
	state, err := s.st.LoginState(ctx, user.ID)
	if err != nil {
		return model.User{}, err
	}
	if state.LockedUntil != nil && state.LockedUntil.After(time.Now()) {
		return model.User{}, ErrAccountLocked
	}
	if !VerifyPassword(user.PasswordHash, password) {
		if _, err := s.st.RecordLoginFailure(ctx, user.ID, s.maxAttempts, s.lockoutWindow); err != nil {
			return model.User{}, err
		}
		return model.User{}, ErrInvalidCredentials
	}
	if err := s.st.RecordLoginSuccess(ctx, user.ID); err != nil {
		return model.User{}, err
	}
	user.PasswordHash = ""
	return user, nil
}

// StartSession creates a session and returns the raw token for the cookie.
func (s *Service) StartSession(ctx context.Context, userID int64, userAgent, remote string) (string, time.Time, error) {
	token, err := GenerateToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(s.sessionTTL)
	err = s.st.CreateSession(ctx, store.Session{
		ID:         HashToken(token),
		UserID:     userID,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  expires,
		UserAgent:  truncate(userAgent, 250),
		RemoteAddr: remote,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// ResolveSession validates a session token and returns its user. It refreshes
// the idle timestamp at most once a minute to keep writes cheap.
func (s *Service) ResolveSession(ctx context.Context, token string) (model.User, error) {
	if token == "" {
		return model.User{}, ErrInvalidCredentials
	}
	sess, err := s.st.Session(ctx, HashToken(token))
	if err != nil {
		return model.User{}, ErrInvalidCredentials
	}
	now := time.Now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > s.sessionIdleTTL {
		_ = s.st.DeleteSession(ctx, sess.ID)
		return model.User{}, ErrInvalidCredentials
	}
	user, err := s.st.UserByID(ctx, sess.UserID)
	if err != nil || user.Disabled {
		_ = s.st.DeleteSession(ctx, sess.ID)
		return model.User{}, ErrInvalidCredentials
	}
	if now.Sub(sess.LastSeenAt) > time.Minute {
		_ = s.st.TouchSession(ctx, sess.ID, now)
	}
	user.PasswordHash = ""
	return user, nil
}

// EndSession logs a session out.
func (s *Service) EndSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.st.DeleteSession(ctx, HashToken(token))
}

// ChangePassword verifies the current password and stores the new one,
// invalidating every other session of that user.
func (s *Service) ChangePassword(ctx context.Context, userID int64, current, next string) error {
	user, err := s.st.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !VerifyPassword(user.PasswordHash, current) {
		return ErrInvalidCredentials
	}
	if err := ValidatePassword(next); err != nil {
		return err
	}
	hash, err := HashPassword(next)
	if err != nil {
		return err
	}
	if err := s.st.SetPassword(ctx, userID, hash, false); err != nil {
		return err
	}
	return s.st.DeleteUserSessions(ctx, userID)
}

// SetPassword is the administrative reset path (no current password needed).
func (s *Service) SetPassword(ctx context.Context, userID int64, next string, mustChange bool) error {
	if err := ValidatePassword(next); err != nil {
		return err
	}
	hash, err := HashPassword(next)
	if err != nil {
		return err
	}
	if err := s.st.SetPassword(ctx, userID, hash, mustChange); err != nil {
		return err
	}
	return s.st.DeleteUserSessions(ctx, userID)
}

// PurgeExpired removes stale sessions; call it periodically.
func (s *Service) PurgeExpired(ctx context.Context) (int64, error) {
	return s.st.PurgeExpiredSessions(ctx, time.Now().Add(-s.sessionIdleTTL))
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

// CanAccessMission reports whether a user may read a mission.
func (s *Service) CanAccessMission(ctx context.Context, user model.User, missionID int64) (bool, error) {
	if user.Role == model.RoleAdmin {
		return true, nil
	}
	return s.st.IsMissionMember(ctx, missionID, user.ID)
}

// CanWrite reports whether a role may change data (run scans, edit assets).
func CanWrite(user model.User) bool {
	return user.Role == model.RoleAdmin || user.Role == model.RoleOperator
}

// IsAdmin reports whether a user is an administrator.
func IsAdmin(user model.User) bool { return user.Role == model.RoleAdmin }

// ValidRole reports whether r is a known role.
func ValidRole(r model.Role) bool {
	switch r {
	case model.RoleAdmin, model.RoleOperator, model.RoleViewer:
		return true
	}
	return false
}

// GeneratePassword returns a readable random password for bootstrapping and
// administrative resets.
//
// The alphabet omits the characters people misread when copying a password off
// a terminal (0/O, 1/l/I). Characters are drawn with rejection sampling rather
// than a modulo, which would bias the distribution, and the draw is repeated
// until it satisfies the policy instead of forcing fixed characters into known
// positions - that would hand an attacker two characters for free.
func GeneratePassword() (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const length = 20

	for range 100 {
		out := make([]byte, length)
		for i := range out {
			c, err := randomByte(alphabet)
			if err != nil {
				return "", err
			}
			out[i] = c
		}
		pw := string(out)
		if ValidatePassword(pw) == nil {
			return pw, nil
		}
	}
	// With this alphabet and length the policy is satisfied overwhelmingly
	// often; failing a hundred draws in a row means something is very wrong.
	return "", errors.New("auth: could not generate a compliant password")
}

// randomByte picks one character of the alphabet uniformly.
func randomByte(alphabet string) (byte, error) {
	n := big.NewInt(int64(len(alphabet)))
	v, err := rand.Int(rand.Reader, n)
	if err != nil {
		return 0, fmt.Errorf("auth: random: %w", err)
	}
	return alphabet[v.Int64()], nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
