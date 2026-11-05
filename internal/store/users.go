package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

const userCols = `id, username, display_name, role, password_hash, disabled,
	must_change_pw, created_at, last_login_at`

func scanUser(sc interface{ Scan(...any) error }) (model.User, error) {
	var (
		u        model.User
		created  int64
		lastSeen sql.NullInt64
		disabled int
		mustPW   int
	)
	err := sc.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.PasswordHash,
		&disabled, &mustPW, &created, &lastSeen)
	if err != nil {
		return model.User{}, err
	}
	u.Disabled = disabled != 0
	u.MustChangePW = mustPW != 0
	u.CreatedAt = toTime(created)
	u.LastLoginAt = toTimePtr(lastSeen)
	return u, nil
}

// CreateUser inserts a user. Returns ErrConflict if the username is taken.
func (s *Store) CreateUser(ctx context.Context, u model.User) (model.User, error) {
	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	if u.Role == "" {
		u.Role = model.RoleOperator
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO users (username, display_name, role, password_hash,
			                   disabled, must_change_pw, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			u.Username, u.DisplayName, string(u.Role), u.PasswordHash,
			boolInt(u.Disabled), boolInt(u.MustChangePW), ms(u.CreatedAt))
		if err != nil {
			return err
		}
		u.ID, err = res.LastInsertId()
		return err
	})
	if isUnique(err) {
		return model.User{}, fmt.Errorf("user %q: %w", u.Username, ErrConflict)
	}
	if err != nil {
		return model.User{}, fmt.Errorf("store: create user: %w", err)
	}
	return u, nil
}

// UserByName looks a user up by username (case-insensitive).
func (s *Store) UserByName(ctx context.Context, name string) (model.User, error) {
	row := s.r.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ? COLLATE NOCASE`, name)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("store: user by name: %w", err)
	}
	return u, nil
}

// UserByID looks a user up by id.
func (s *Store) UserByID(ctx context.Context, id int64) (model.User, error) {
	row := s.r.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("store: user by id: %w", err)
	}
	return u, nil
}

// ListUsers returns every user, ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list users: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers reports how many accounts exist (used to decide bootstrapping).
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}
	return n, nil
}

// UpdateUser updates the mutable profile fields (not the password).
func (s *Store) UpdateUser(ctx context.Context, u model.User) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE users SET display_name = ?, role = ?, disabled = ?, must_change_pw = ?
			WHERE id = ?`,
			u.DisplayName, string(u.Role), boolInt(u.Disabled), boolInt(u.MustChangePW), u.ID)
		if err != nil {
			return fmt.Errorf("store: update user: %w", err)
		}
		return affected(res)
	})
}

// SetPassword replaces the password hash and clears the change-required flag.
func (s *Store) SetPassword(ctx context.Context, userID int64, hash string, mustChange bool) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE users SET password_hash = ?, must_change_pw = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?`,
			hash, boolInt(mustChange), userID)
		if err != nil {
			return fmt.Errorf("store: set password: %w", err)
		}
		return affected(res)
	})
}

// DeleteUser removes a user and their sessions.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("store: delete user: %w", err)
		}
		return affected(res)
	})
}

// LoginState carries the brute-force protection counters.
type LoginState struct {
	FailedAttempts int
	LockedUntil    *time.Time
}

// LoginState reads the lockout counters of a user.
func (s *Store) LoginState(ctx context.Context, userID int64) (LoginState, error) {
	var (
		st     LoginState
		locked sql.NullInt64
	)
	err := s.r.QueryRowContext(ctx,
		`SELECT failed_attempts, locked_until FROM users WHERE id = ?`, userID).
		Scan(&st.FailedAttempts, &locked)
	if errors.Is(err, sql.ErrNoRows) {
		return st, ErrNotFound
	}
	if err != nil {
		return st, fmt.Errorf("store: login state: %w", err)
	}
	st.LockedUntil = toTimePtr(locked)
	return st, nil
}

// RecordLoginFailure increments the failure counter and locks the account when it reaches
// maxAttempts. It returns the updated state.
func (s *Store) RecordLoginFailure(ctx context.Context, userID int64, maxAttempts int, window time.Duration) (LoginState, error) {
	var st LoginState
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var attempts int
		if err := tx.QueryRowContext(ctx, `SELECT failed_attempts FROM users WHERE id = ?`, userID).Scan(&attempts); err != nil {
			return err
		}
		attempts++
		var lockedUntil *int64
		if maxAttempts > 0 && attempts >= maxAttempts {
			v := time.Now().Add(window).UnixMilli()
			lockedUntil = &v
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?`,
			attempts, lockedUntil, userID); err != nil {
			return err
		}
		st.FailedAttempts = attempts
		if lockedUntil != nil {
			t := time.UnixMilli(*lockedUntil).UTC()
			st.LockedUntil = &t
		}
		return nil
	})
	if err != nil {
		return st, fmt.Errorf("store: record login failure: %w", err)
	}
	return st, nil
}

// RecordLoginSuccess clears the counters and stamps the last login.
func (s *Store) RecordLoginSuccess(ctx context.Context, userID int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?`,
			time.Now().UnixMilli(), userID)
		return err
	})
}

// --------------------------------------------------------------------------- Sessions
// ---------------------------------------------------------------------------

// Session is a stored web session. ID is a hash of the cookie token.
type Session struct {
	ID         string
	UserID     int64
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	UserAgent  string
	RemoteAddr string
}

// CreateSession stores a new session.
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO sessions (id, user_id, created_at, last_seen_at, expires_at, user_agent, remote_addr)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			sess.ID, sess.UserID, ms(sess.CreatedAt), ms(sess.LastSeenAt),
			ms(sess.ExpiresAt), sess.UserAgent, sess.RemoteAddr)
		if err != nil {
			return fmt.Errorf("store: create session: %w", err)
		}
		return nil
	})
}

// Session loads a session by its id (token hash).
func (s *Store) Session(ctx context.Context, id string) (Session, error) {
	var (
		sess                      Session
		created, lastSeen, expiry int64
	)
	err := s.r.QueryRowContext(ctx, `
		SELECT id, user_id, created_at, last_seen_at, expires_at, user_agent, remote_addr
		FROM sessions WHERE id = ?`, id).
		Scan(&sess.ID, &sess.UserID, &created, &lastSeen, &expiry, &sess.UserAgent, &sess.RemoteAddr)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("store: session: %w", err)
	}
	sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt = toTime(created), toTime(lastSeen), toTime(expiry)
	return sess, nil
}

// TouchSession refreshes the idle timestamp.
func (s *Store) TouchSession(ctx context.Context, id string, at time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id = ?`, ms(at), id)
		return err
	})
}

// DeleteSession removes one session (logout).
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
		return err
	})
}

// DeleteUserSessions removes every session of a user (password change, lock).
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
		return err
	})
}

// PurgeExpiredSessions deletes sessions past their absolute expiry or idle deadline and
// returns how many rows were removed.
func (s *Store) PurgeExpiredSessions(ctx context.Context, idleDeadline time.Time) (int64, error) {
	var n int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?`,
			time.Now().UnixMilli(), ms(idleDeadline))
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: purge sessions: %w", err)
	}
	return n, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func affected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
