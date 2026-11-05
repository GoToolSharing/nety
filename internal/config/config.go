// Package config holds build metadata and the runtime configuration of the NETY server.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Build metadata, injected with -ldflags at build time.
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// UserAgent is sent by every HTTP probe and by the web client.
func UserAgent() string {
	return "NETY/" + Version
}

// VersionString is the one-line version banner.
func VersionString() string {
	return fmt.Sprintf("NETY %s (commit %s, built %s, %s/%s, %s)",
		Version, Commit, BuildDate, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// Config is the server configuration. Every field can be set by flag or by the matching
// NETY_* environment variable.
type Config struct {
	// Storage
	DataDir string // directory holding the database, TLS material and exports

	// HTTP
	Listen       string        // ":8443"
	TLSCertFile  string        // empty => self-signed certificate generated in DataDir
	TLSKeyFile   string        //
	TLSDisabled  bool          // serve plain HTTP (only sensible behind a proxy)
	TrustedProxy bool          // honour X-Forwarded-For for audit logging
	ReadTimeout  time.Duration //
	WriteTimeout time.Duration // kept generous: exports can be large
	IdleTimeout  time.Duration //

	// Sessions
	SessionTTL      time.Duration // absolute lifetime of a session
	SessionIdleTTL  time.Duration // idle timeout
	SecureCookies   bool          // force the Secure attribute (default: !TLSDisabled)
	BootstrapAdmin  string        // username created on first start
	BootstrapPass   string        // password for it; empty => generated and printed once
	AllowSignup     bool          // open registration (off by default)
	MaxLoginAttempt int           // failed attempts before temporary lockout
	LockoutWindow   time.Duration //

	// Scanning defaults and safety limits
	MaxConcurrentScans int           // scans running at the same time
	DefaultRate        int           // packets per second
	MaxRate            int           // hard cap an operator cannot exceed
	DefaultTimeout     time.Duration // per probe
	WorkerCount        int           // service-detection workers per scan
	NmapProbesPath     string        // optional nmap-service-probes file

	// Logging
	LogLevel  string // debug | info | warn | error
	LogFormat string // text | json
	LogFile   string // empty => stderr
}

// Default returns the configuration with every default applied.
func Default() Config {
	return Config{
		DataDir:            defaultDataDir(),
		Listen:             ":8443",
		ReadTimeout:        30 * time.Second,
		WriteTimeout:       10 * time.Minute,
		IdleTimeout:        2 * time.Minute,
		SessionTTL:         12 * time.Hour,
		SessionIdleTTL:     2 * time.Hour,
		BootstrapAdmin:     "admin",
		MaxLoginAttempt:    8,
		LockoutWindow:      15 * time.Minute,
		MaxConcurrentScans: 2,
		DefaultRate:        5000,
		MaxRate:            200000,
		DefaultTimeout:     3 * time.Second,
		WorkerCount:        64,
		LogLevel:           "info",
		LogFormat:          "text",
	}
}

func defaultDataDir() string {
	if d := os.Getenv("NETY_DATA"); d != "" {
		return d
	}
	if _, err := os.Stat("/data"); err == nil {
		return "/data"
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".nety")
	}
	return "nety-data"
}

// ApplyEnv overlays NETY_* environment variables on top of c.
func (c *Config) ApplyEnv() error {
	var errs []error
	str := func(key string, dst *string) {
		if v, ok := os.LookupEnv(key); ok {
			*dst = v
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := os.LookupEnv(key); ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, err))
				return
			}
			*dst = b
		}
	}
	integer := func(key string, dst *int) {
		if v, ok := os.LookupEnv(key); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, err))
				return
			}
			*dst = n
		}
	}
	dur := func(key string, dst *time.Duration) {
		if v, ok := os.LookupEnv(key); ok {
			d, err := time.ParseDuration(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, err))
				return
			}
			*dst = d
		}
	}

	str("NETY_DATA", &c.DataDir)
	str("NETY_LISTEN", &c.Listen)
	str("NETY_TLS_CERT", &c.TLSCertFile)
	str("NETY_TLS_KEY", &c.TLSKeyFile)
	boolean("NETY_TLS_DISABLED", &c.TLSDisabled)
	boolean("NETY_TRUSTED_PROXY", &c.TrustedProxy)
	dur("NETY_SESSION_TTL", &c.SessionTTL)
	dur("NETY_SESSION_IDLE_TTL", &c.SessionIdleTTL)
	str("NETY_BOOTSTRAP_ADMIN", &c.BootstrapAdmin)
	str("NETY_BOOTSTRAP_PASSWORD", &c.BootstrapPass)
	boolean("NETY_ALLOW_SIGNUP", &c.AllowSignup)
	integer("NETY_MAX_CONCURRENT_SCANS", &c.MaxConcurrentScans)
	integer("NETY_DEFAULT_RATE", &c.DefaultRate)
	integer("NETY_MAX_RATE", &c.MaxRate)
	dur("NETY_DEFAULT_TIMEOUT", &c.DefaultTimeout)
	integer("NETY_WORKERS", &c.WorkerCount)
	str("NETY_NMAP_PROBES", &c.NmapProbesPath)
	str("NETY_LOG_LEVEL", &c.LogLevel)
	str("NETY_LOG_FORMAT", &c.LogFormat)
	str("NETY_LOG_FILE", &c.LogFile)

	return errors.Join(errs...)
}

// Normalize fills derived defaults and validates the configuration.
func (c *Config) Normalize() error {
	if c.DataDir == "" {
		c.DataDir = defaultDataDir()
	}
	abs, err := filepath.Abs(c.DataDir)
	if err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	c.DataDir = abs

	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if !strings.Contains(c.Listen, ":") {
		c.Listen = ":" + c.Listen
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("TLS certificate and key must be provided together")
	}
	if !c.TLSDisabled {
		c.SecureCookies = true
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = 12 * time.Hour
	}
	if c.SessionIdleTTL <= 0 || c.SessionIdleTTL > c.SessionTTL {
		c.SessionIdleTTL = min(2*time.Hour, c.SessionTTL)
	}
	if c.MaxConcurrentScans < 1 {
		c.MaxConcurrentScans = 1
	}
	if c.DefaultRate < 1 {
		c.DefaultRate = 5000
	}
	if c.MaxRate < c.DefaultRate {
		c.MaxRate = c.DefaultRate
	}
	if c.DefaultTimeout <= 0 {
		c.DefaultTimeout = 3 * time.Second
	}
	if c.WorkerCount < 1 {
		c.WorkerCount = 32
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	case "":
		c.LogLevel = "info"
	default:
		return fmt.Errorf("invalid log level %q", c.LogLevel)
	}
	switch c.LogFormat {
	case "text", "json":
	case "":
		c.LogFormat = "text"
	default:
		return fmt.Errorf("invalid log format %q", c.LogFormat)
	}
	if c.NmapProbesPath != "" {
		if _, err := os.Stat(c.NmapProbesPath); err != nil {
			return fmt.Errorf("nmap probes file: %w", err)
		}
	}
	return nil
}

// DBPath is the location of the SQLite database.
func (c Config) DBPath() string { return filepath.Join(c.DataDir, "nety.db") }

// CertPath and KeyPath are where a generated self-signed pair is stored.
func (c Config) CertPath() string { return filepath.Join(c.DataDir, "tls", "server.crt") }
func (c Config) KeyPath() string  { return filepath.Join(c.DataDir, "tls", "server.key") }

// EnsureDirs creates the data directory layout.
func (c Config) EnsureDirs() error {
	for _, d := range []string{c.DataDir, filepath.Join(c.DataDir, "tls")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	return nil
}
