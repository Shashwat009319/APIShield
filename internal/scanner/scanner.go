package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalidTarget    = errors.New("invalid target URL")
	ErrTargetNotAllowed = errors.New("target is not allowed")
)

type Finding struct {
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	Endpoint    string `json:"endpoint"`
}

type Result struct {
	TargetURL  string    `json:"target_url"`
	HTTPStatus int       `json:"http_status"`
	CheckedAt  time.Time `json:"checked_at"`
	Findings   []Finding `json:"findings"`
}

type Scanner struct {
	client *http.Client
}

func New() *Scanner {
	return &Scanner{
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(
				req *http.Request,
				via []*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func validateTarget(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed URL", ErrInvalidTarget)
	}

	if !u.IsAbs() || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%w: absolute URL required", ErrInvalidTarget)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: HTTP or HTTPS required", ErrInvalidTarget)
	}

	host := u.Hostname()

	isLocalhost := strings.EqualFold(host, "localhost")
	ip := net.ParseIP(host)
	isLoopback := ip != nil && ip.IsLoopback()

	if !isLocalhost && !isLoopback {
		return nil, fmt.Errorf(
			"%w: only localhost targets are supported in this version",
			ErrTargetNotAllowed,
		)
	}

	if u.Fragment != "" {
		u.Fragment = ""
	}

	return u, nil
}

func (s *Scanner) Scan(
	ctx context.Context,
	rawURL string,
) (Result, error) {
	target, err := validateTarget(rawURL)
	if err != nil {
		return Result{}, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		target.String(),
		nil,
	)
	if err != nil {
		return Result{}, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "APIShield/0.2")
	req.Header.Set("Accept", "application/json, text/html, */*")

	resp, err := s.client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	endpoint := target.EscapedPath()
	if endpoint == "" {
		endpoint = "/"
	}

	result := Result{
		TargetURL:  target.String(),
		HTTPStatus: resp.StatusCode,
		CheckedAt:  time.Now().UTC(),
		Findings:   make([]Finding, 0),
	}

	addFinding := func(
		ruleID string,
		title string,
		severity string,
		category string,
		description string,
		evidence string,
		remediation string,
	) {
		result.Findings = append(result.Findings, Finding{
			RuleID:      ruleID,
			Title:       title,
			Severity:    severity,
			Category:    category,
			Description: description,
			Evidence:    evidence,
			Remediation: remediation,
			Endpoint:    endpoint,
		})
	}

	headers := resp.Header

	if headers.Get("Content-Security-Policy") == "" {
		addFinding(
			"API-001",
			"Missing Content Security Policy",
			"Medium",
			"Security Headers",
			"The response does not define a Content-Security-Policy header.",
			"Content-Security-Policy header was not present.",
			"Define a Content-Security-Policy appropriate for the application.",
		)
	}

	if headers.Get("X-Content-Type-Options") == "" {
		addFinding(
			"API-002",
			"Missing MIME sniffing protection",
			"Low",
			"Security Headers",
			"The response does not define X-Content-Type-Options.",
			"X-Content-Type-Options header was not present.",
			"Set X-Content-Type-Options to nosniff.",
		)
	}

	if headers.Get("X-Frame-Options") == "" &&
		!strings.Contains(
			strings.ToLower(headers.Get("Content-Security-Policy")),
			"frame-ancestors",
		) {
		addFinding(
			"API-003",
			"Missing clickjacking protection",
			"Medium",
			"Security Headers",
			"No X-Frame-Options or CSP frame-ancestors directive was detected.",
			"Neither supported framing protection was present.",
			"Set an appropriate X-Frame-Options header or CSP frame-ancestors directive.",
		)
	}

	if headers.Get("Referrer-Policy") == "" {
		addFinding(
			"API-004",
			"Missing Referrer Policy",
			"Low",
			"Security Headers",
			"The response does not define a Referrer-Policy header.",
			"Referrer-Policy header was not present.",
			"Choose a suitable Referrer-Policy, such as strict-origin-when-cross-origin.",
		)
	}

	if target.Scheme == "https" &&
		headers.Get("Strict-Transport-Security") == "" {
		addFinding(
			"API-005",
			"Missing HTTP Strict Transport Security",
			"Medium",
			"Transport Security",
			"The HTTPS response does not define Strict-Transport-Security.",
			"Strict-Transport-Security header was not present.",
			"Configure an appropriate HSTS policy after verifying HTTPS deployment.",
		)
	}

	if headers.Get("Server") != "" {
		addFinding(
			"API-006",
			"Server header information exposed",
			"Info",
			"Information Disclosure",
			"The response exposes server identification information.",
			"Server: "+headers.Get("Server"),
			"Consider removing unnecessary server identification details.",
		)
	}

	for _, cookie := range resp.Cookies() {
		if !cookie.HttpOnly {
			addFinding(
				"API-007",
				"Cookie missing HttpOnly attribute",
				"Medium",
				"Cookie Security",
				"A response cookie does not have the HttpOnly attribute.",
				"Cookie name: "+cookie.Name,
				"Set HttpOnly on cookies that do not need browser JavaScript access.",
			)
		}

		if target.Scheme == "https" && !cookie.Secure {
			addFinding(
				"API-008",
				"HTTPS cookie missing Secure attribute",
				"Medium",
				"Cookie Security",
				"A cookie received over HTTPS does not have the Secure attribute.",
				"Cookie name: "+cookie.Name,
				"Set the Secure attribute on cookies transmitted over HTTPS.",
			)
		}

		if cookie.SameSite == http.SameSiteDefaultMode {
			addFinding(
				"API-009",
				"Cookie missing SameSite attribute",
				"Low",
				"Cookie Security",
				"A response cookie does not specify a SameSite policy.",
				"Cookie name: "+cookie.Name,
				"Choose an appropriate SameSite policy for the cookie.",
			)
		}
	}

	return result, nil
}
