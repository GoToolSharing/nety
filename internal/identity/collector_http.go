package identity

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/vaadata/nety/internal/identity/ntlm"
	"github.com/vaadata/nety/internal/model"
)

// httpNTLMReq is one planned NTLM probe request.
type httpNTLMReq struct {
	Method string
	Path   string
	Scheme string // "NTLM" or "Negotiate"
}

const maxHTTPNTLMRequests = 3

func hasScheme(schemes []string, want string) bool {
	for _, s := range schemes {
		if strings.EqualFold(strings.TrimSpace(strings.Fields(s + " x")[0]), want) {
			return true
		}
	}
	return false
}

// httpNTLMPlan returns the (at most maxHTTPNTLMRequests) requests worth
// trying on s to obtain an NTLM CHALLENGE, or nil.
func httpNTLMPlan(s model.Service) []httpNTLMReq {
	if s.Protocol != model.TCP {
		return nil
	}
	n := svcName(s)
	isHTTP := s.HTTP != nil || strings.Contains(n, "http") || n == "wsman" || n == "winrm"
	winrm := n == "wsman" || n == "winrm" || s.Port == 5985 || s.Port == 5986 || s.Port == 47001
	if !isHTTP && !winrm {
		return nil
	}
	var plan []httpNTLMReq
	add := func(r httpNTLMReq) {
		for _, x := range plan {
			if x.Path == r.Path && x.Method == r.Method {
				return
			}
		}
		if len(plan) < maxHTTPNTLMRequests {
			plan = append(plan, r)
		}
	}
	if s.HTTP != nil && (hasScheme(s.HTTP.AuthSchemes, "NTLM") || hasScheme(s.HTTP.AuthSchemes, "Negotiate")) {
		scheme := "NTLM"
		if !hasScheme(s.HTTP.AuthSchemes, "NTLM") {
			scheme = "Negotiate"
		}
		path := "/"
		if u, err := url.Parse(s.HTTP.URL); err == nil && u.Path != "" {
			path = u.EscapedPath()
		}
		add(httpNTLMReq{Method: http.MethodGet, Path: path, Scheme: scheme})
	}
	if winrm {
		add(httpNTLMReq{Method: http.MethodPost, Path: "/wsman", Scheme: "Negotiate"})
	}
	if isIIS(s) {
		for _, p := range []string{"/EWS/Exchange.asmx", "/autodiscover/autodiscover.xml", "/rpc/rpcproxy.dll", "/Microsoft-Server-ActiveSync", "/OAB/"} {
			add(httpNTLMReq{Method: http.MethodGet, Path: p, Scheme: "NTLM"})
		}
	}
	return plan
}

func isIIS(s model.Service) bool {
	if strings.Contains(strings.ToLower(s.Product), "iis") || strings.Contains(strings.ToLower(s.Product), "exchange") {
		return true
	}
	if s.HTTP == nil {
		return false
	}
	if strings.Contains(strings.ToLower(s.HTTP.Server), "microsoft-iis") {
		return true
	}
	for k := range s.HTTP.Headers {
		lk := strings.ToLower(k)
		if lk == "x-owa-version" || lk == "x-feserver" || lk == "x-calculatedbetarget" {
			return true
		}
	}
	for _, t := range s.HTTP.Technologies {
		if strings.Contains(strings.ToLower(t), "exchange") || strings.Contains(strings.ToLower(t), "iis") {
			return true
		}
	}
	return false
}

// parseWWWAuthenticate finds an NTLM/Negotiate challenge token in the given
// WWW-Authenticate header values.
func parseWWWAuthenticate(values []string) (*ntlm.Challenge, error) {
	for _, hv := range values {
		// a header can carry several comma separated challenges
		for _, part := range strings.Split(hv, ",") {
			f := strings.Fields(strings.TrimSpace(part))
			if len(f) != 2 {
				continue
			}
			if !strings.EqualFold(f[0], "NTLM") && !strings.EqualFold(f[0], "Negotiate") {
				continue
			}
			if len(f[1]) > 64<<10 {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(f[1])
			if err != nil {
				raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(f[1], "="))
				if err != nil {
					continue
				}
			}
			if ch, err := ntlm.FindChallenge(raw); err == nil {
				return ch, nil
			}
		}
	}
	return nil, errors.New("http: no NTLM challenge in WWW-Authenticate")
}

// probeHTTPNTLM sends NTLM NEGOTIATE messages over HTTP(S).
func (c *collector) probeHTTPNTLM(ctx context.Context, sink *evidenceSink, ip string, s model.Service, plan []httpNTLMReq) error {
	scheme := "http"
	if isTLSService(s, 443, 5986, 8443) {
		scheme = "https"
	}
	host := net.JoinHostPort(ip, strconv.Itoa(s.Port))
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: c.ioTimeout}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // fingerprinting only
		TLSHandshakeTimeout:   c.ioTimeout,
		ResponseHeaderTimeout: c.ioTimeout,
		DisableKeepAlives:     true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		Timeout:       2 * c.ioTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	token := base64.StdEncoding.EncodeToString(ntlm.NegotiateMessage())
	var lastErr error = errors.New("http: no NTLM challenge")
	for _, r := range plan {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		u := scheme + "://" + host + r.Path
		var body io.Reader
		if r.Method == http.MethodPost {
			body = strings.NewReader("")
		}
		req, err := http.NewRequestWithContext(ctx, r.Method, u, body)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Authorization", r.Scheme+" "+token)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		if r.Method == http.MethodPost {
			req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
			req.ContentLength = 0
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		ch, err := parseWWWAuthenticate(resp.Header.Values("WWW-Authenticate"))
		if err != nil {
			lastErr = err
			continue
		}
		ntlmEvidence(sink, ch, "http-ntlm/"+strconv.Itoa(s.Port), map[string]string{"path": r.Path})
		return nil
	}
	return lastErr
}
