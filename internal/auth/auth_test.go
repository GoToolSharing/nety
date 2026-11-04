package auth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/store"
)

func newService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "auth.db"), nil)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, Config{SessionTTL: time.Hour, SessionIdleTTL: time.Hour, MaxAttempts: 3, LockoutWindow: time.Minute}), st
}

func createUser(t *testing.T, st *store.Store, name, password string) model.User {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u, err := st.CreateUser(context.Background(), model.User{
		Username: name, Role: model.RoleOperator, PasswordHash: hash,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("the correct password was rejected")
	}
	if VerifyPassword(hash, "wrong password entirely") {
		t.Fatal("a wrong password was accepted")
	}
	// Two hashes of the same password must differ (random salt).
	other, _ := HashPassword("correct horse battery staple")
	if other == hash {
		t.Fatal("hashes are not salted")
	}
	// Malformed hashes must never verify.
	for _, bad := range []string{"", "notahash", "$argon2id$v=19$bad$x$y", "$2y$10$abcdefgh"} {
		if VerifyPassword(bad, "anything") {
			t.Fatalf("malformed hash %q verified", bad)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	good := []string{"correct-horse-9", "Tr0ub4dor&3xyzab", "aaaaaaaaaaaaaaA1"}
	for _, p := range good {
		if err := ValidatePassword(p); err != nil {
			t.Fatalf("%q should be accepted: %v", p, err)
		}
	}
	bad := []string{"short", "alllowercaseonly", strings.Repeat("a", 300)}
	for _, p := range bad {
		if err := ValidatePassword(p); err == nil {
			t.Fatalf("%q should be rejected", p)
		}
	}
	if pw, err := GeneratePassword(); err != nil || ValidatePassword(pw) != nil {
		t.Fatalf("generated password must satisfy the policy: %q %v", pw, err)
	}
}

func TestAuthenticateAndLockout(t *testing.T) {
	ctx := context.Background()
	svc, st := newService(t)
	createUser(t, st, "alice", "correct-horse-9")

	if _, err := svc.Authenticate(ctx, "alice", "correct-horse-9"); err != nil {
		t.Fatalf("valid login rejected: %v", err)
	}
	// A wrong password must not leak whether the account exists.
	if _, err := svc.Authenticate(ctx, "nobody", "whatever"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user: got %v", err)
	}
	for range 3 {
		if _, err := svc.Authenticate(ctx, "alice", "bad"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("expected invalid credentials, got %v", err)
		}
	}
	// The account is now locked, even with the right password.
	if _, err := svc.Authenticate(ctx, "alice", "correct-horse-9"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("expected the account to be locked, got %v", err)
	}
}

func TestDisabledAccount(t *testing.T) {
	ctx := context.Background()
	svc, st := newService(t)
	u := createUser(t, st, "bob", "correct-horse-9")
	u.Disabled = true
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := svc.Authenticate(ctx, "bob", "correct-horse-9"); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("expected ErrAccountDisabled, got %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, st := newService(t)
	u := createUser(t, st, "carol", "correct-horse-9")

	token, expires, err := svc.StartSession(ctx, u.ID, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	if expires.Before(time.Now()) {
		t.Fatal("session already expired")
	}
	// Only the hash is stored, never the token itself.
	if _, err := st.Session(ctx, token); err == nil {
		t.Fatal("the raw token must not be a valid key in the store")
	}
	if _, err := st.Session(ctx, HashToken(token)); err != nil {
		t.Fatalf("the hashed token should resolve: %v", err)
	}

	got, err := svc.ResolveSession(ctx, token)
	if err != nil || got.ID != u.ID {
		t.Fatalf("resolve: %+v %v", got, err)
	}
	if got.PasswordHash != "" {
		t.Fatal("the password hash must never leave the auth layer")
	}
	if err := svc.EndSession(ctx, token); err != nil {
		t.Fatalf("end: %v", err)
	}
	if _, err := svc.ResolveSession(ctx, token); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("a logged-out session must not resolve, got %v", err)
	}
	if _, err := svc.ResolveSession(ctx, "garbage"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("a bogus token must not resolve")
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "idle.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := New(st, Config{SessionTTL: time.Hour, SessionIdleTTL: time.Millisecond})
	u := createUser(t, st, "dave", "correct-horse-9")

	token, _, err := svc.StartSession(ctx, u.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := svc.ResolveSession(ctx, token); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("an idle session must expire, got %v", err)
	}
}

func TestChangePasswordInvalidatesSessions(t *testing.T) {
	ctx := context.Background()
	svc, st := newService(t)
	u := createUser(t, st, "erin", "correct-horse-9")
	token, _, _ := svc.StartSession(ctx, u.ID, "", "")

	if err := svc.ChangePassword(ctx, u.ID, "wrong", "new-password-1A"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected the current password to be checked, got %v", err)
	}
	if err := svc.ChangePassword(ctx, u.ID, "correct-horse-9", "weak"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("expected the policy to be enforced, got %v", err)
	}
	if err := svc.ChangePassword(ctx, u.ID, "correct-horse-9", "new-password-1A"); err != nil {
		t.Fatalf("change: %v", err)
	}
	if _, err := svc.ResolveSession(ctx, token); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("changing the password must invalidate existing sessions")
	}
	if _, err := svc.Authenticate(ctx, "erin", "new-password-1A"); err != nil {
		t.Fatalf("the new password should work: %v", err)
	}
}

func TestMissionAuthorization(t *testing.T) {
	ctx := context.Background()
	svc, st := newService(t)
	admin := model.User{ID: 1, Role: model.RoleAdmin}
	operator := createUser(t, st, "frank", "correct-horse-9")
	other := createUser(t, st, "grace", "correct-horse-9")

	mission, err := st.CreateMission(ctx, model.Mission{Name: "m", CreatedBy: operator.ID})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := svc.CanAccessMission(ctx, admin, mission.ID); !ok {
		t.Fatal("an admin must see every mission")
	}
	if ok, _ := svc.CanAccessMission(ctx, operator, mission.ID); !ok {
		t.Fatal("the creator must be a member")
	}
	if ok, _ := svc.CanAccessMission(ctx, other, mission.ID); ok {
		t.Fatal("a non-member must not access the mission")
	}
	if !CanWrite(operator) || CanWrite(model.User{Role: model.RoleViewer}) {
		t.Fatal("write permission is wrong")
	}
	if !ValidRole(model.RoleViewer) || ValidRole(model.Role("root")) {
		t.Fatal("role validation is wrong")
	}
}
