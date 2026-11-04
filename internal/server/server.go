// Package server wires the HTTP server: TLS, security headers, the API and
// the embedded single-page application.
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/vaadata/nety/internal/config"
)

// dist holds the compiled SPA. `make web` writes it; a placeholder page is
// committed so the binary always builds.
//
//go:embed all:dist
var dist embed.FS

// Server owns the listener and its lifecycle.
type Server struct {
	cfg  config.Config
	log  *slog.Logger
	http *http.Server
}

// New builds the HTTP server around the API handler.
func New(cfg config.Config, api http.Handler, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	root, err := webRoot()
	if err != nil {
		return nil, err
	}
	spa := spaHandler(root)

	mux := http.NewServeMux()
	mux.Handle("/api/", api)
	mux.Handle("/", spa)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           securityHeaders(cfg, inlineScriptHashes(root), mux),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      0, // streaming exports and WebSockets must not be cut
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	return &Server{cfg: cfg, log: log, http: srv}, nil
}

// ListenAndServe starts serving and blocks until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.Listen, err)
	}

	scheme := "https"
	if s.cfg.TLSDisabled {
		scheme = "http"
	} else {
		tlsCfg, err := s.tlsConfig()
		if err != nil {
			ln.Close()
			return err
		}
		s.http.TLSConfig = tlsCfg
		ln = tls.NewListener(ln, tlsCfg)
	}

	s.log.Info("NETY is listening",
		"url", fmt.Sprintf("%s://%s/", scheme, displayAddr(ln.Addr().String())),
		"version", config.Version)
	for _, u := range localURLs(scheme, s.cfg.Listen) {
		s.log.Info("reachable from the local network", "url", u)
	}

	errCh := make(chan error, 1)
	go func() {
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.log.Info("shutting down the web server")
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			_ = s.http.Close()
			return err
		}
		return <-errCh
	}
}

// tlsConfig loads the configured certificate or generates a self-signed one in
// the data directory. A pentest laptop has no CA, so self-signed is the
// realistic default; the fingerprint is logged so the operator can tell a
// colleague what to expect in the browser warning.
func (s *Server) tlsConfig() (*tls.Config, error) {
	certFile, keyFile := s.cfg.TLSCertFile, s.cfg.TLSKeyFile
	if certFile == "" {
		certFile, keyFile = s.cfg.CertPath(), s.cfg.KeyPath()
		if err := s.ensureSelfSigned(certFile, keyFile); err != nil {
			return nil, err
		}
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS keypair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}, nil
}

func (s *Server) ensureSelfSigned(certFile, keyFile string) error {
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return err
	}
	s.log.Info("generating a self-signed TLS certificate", "path", certFile)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "nety"
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"NETY"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{host, "localhost"},
	}
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	for _, ip := range localIPs() {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	if err := writePEM(certFile, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(keyFile, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}

	sum := sha256Hex(der)
	s.log.Info("self-signed certificate ready — share this fingerprint with your colleagues",
		"sha256", sum)
	return nil
}

// ---------------------------------------------------------------------------
// static assets
// ---------------------------------------------------------------------------

// webRoot is the filesystem the SPA is served from: the embedded build, or a
// directory set with NETY_WEB_DIR during development.
func webRoot() (fs.FS, error) {
	if dir := os.Getenv("NETY_WEB_DIR"); dir != "" {
		return os.DirFS(dir), nil
	}
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, fmt.Errorf("embedded assets: %w", err)
	}
	return sub, nil
}

// spaHandler serves the SPA, falling back to index.html so client-side routes
// survive a reload.
func spaHandler(root fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(root))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean == "." || clean == "/" {
			clean = "index.html"
		}
		f, err := root.Open(clean)
		if err != nil {
			// Unknown path: hand it to the SPA router.
			serveIndex(w, r, root)
			return
		}
		info, statErr := f.Stat()
		f.Close()
		if statErr != nil || info.IsDir() {
			serveIndex(w, r, root)
			return
		}
		// Vite emits content-hashed asset names: they can be cached hard.
		if strings.HasPrefix(clean, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, root fs.FS) {
	data, err := fs.ReadFile(root, "index.html")
	if err != nil {
		http.Error(w, "web interface not built", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", time.Time{}, strings.NewReader(string(data)))
}

// securityHeaders applies the headers an internal tool should still set: the
// console often holds a client's whole network inventory.
func securityHeaders(cfg config.Config, inlineHashes []string, next http.Handler) http.Handler {
	// The SPA's theme bootstrap is inline; allow exactly its hash rather than
	// opening the policy to all inline scripts.
	scriptSrc := "script-src 'self'"
	if len(inlineHashes) > 0 {
		scriptSrc += " " + strings.Join(inlineHashes, " ")
	}
	csp := strings.Join([]string{
		"default-src 'self'",
		scriptSrc,
		// Vite injects a style element; hashing it per build is not worth it.
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: blob:",
		"font-src 'self' data:",
		"connect-src 'self' ws: wss:",
		"object-src 'none'",
		"base-uri 'none'",
		"frame-ancestors 'none'",
		"form-action 'self'",
	}, "; ")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		if !cfg.TLSDisabled {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func displayAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		return net.JoinHostPort("localhost", port)
	}
	return net.JoinHostPort(host, port)
}

// localURLs lists the addresses a colleague on the same VLAN can use, which is
// exactly how this tool is shared during an engagement.
func localURLs(scheme, listen string) []string {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil
	}
	var out []string
	for _, ip := range localIPs() {
		out = append(out, fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip.String(), port)))
	}
	return out
}

func localIPs() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 != nil {
				out = append(out, v4)
			}
		}
	}
	return out
}
