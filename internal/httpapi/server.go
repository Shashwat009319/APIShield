package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Shashwat009319/apishield/internal/scanner"
)

type API struct {
	scanner *scanner.Scanner
	mu      sync.RWMutex
	scans   []ScanRecord
}

type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
}

type ScanRecord struct {
	ID          string         `json:"id"`
	TargetURL   string         `json:"target_url"`
	Status      string         `json:"status"`
	StartedAt   time.Time      `json:"started_at"`
	CompletedAt time.Time      `json:"completed_at"`
	Result      scanner.Result `json:"result"`
}

type CreateScanRequest struct {
	TargetURL              string `json:"target_url"`
	AuthorizationConfirmed bool   `json:"authorization_confirmed"`
}

type DashboardSummary struct {
	Status           string     `json:"status"`
	HasAssessment    bool       `json:"has_assessment"`
	ScansCompleted   int        `json:"scans_completed"`
	URLsAssessed     int        `json:"urls_assessed"`
	OpenFindings     int        `json:"open_findings"`
	CriticalFindings int        `json:"critical_findings"`
	SecurityPosture  int        `json:"security_posture"`
	LastScan         *time.Time `json:"last_scan,omitempty"`
}

func New(addr string) *http.Server {
	api := &API{
		scanner: scanner.New(),
		scans:   make([]ScanRecord, 0),
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", api.health)
	mux.HandleFunc("GET /api/v1/dashboard/summary", api.dashboardSummary)
	mux.HandleFunc("GET /api/v1/scans", api.listScans)
	mux.HandleFunc("POST /api/v1/scans", api.createScan)

	return &http.Server{
		Addr:              addr,
		Handler:           api.middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{
		Status:  "ok",
		Service: "apishield",
		Version: "0.2.0",
	})
}

func (a *API) dashboardSummary(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	summary := DashboardSummary{
		Status:         "ok",
		ScansCompleted: len(a.scans),
		URLsAssessed:   len(a.scans),
	}

	if len(a.scans) == 0 {
		writeJSON(w, http.StatusOK, summary)
		return
	}

	summary.HasAssessment = true
	summary.LastScan = &a.scans[len(a.scans)-1].CompletedAt

	score := 100

	for _, scan := range a.scans {
		for _, finding := range scan.Result.Findings {
			summary.OpenFindings++

			switch finding.Severity {
			case "Critical":
				summary.CriticalFindings++
				score -= 20
			case "High":
				score -= 10
			case "Medium":
				score -= 5
			case "Low":
				score -= 2
			}
		}
	}

	if score < 0 {
		score = 0
	}

	summary.SecurityPosture = score

	writeJSON(w, http.StatusOK, summary)
}

func (a *API) listScans(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"scans": a.scans,
	})
}

func (a *API) createScan(w http.ResponseWriter, r *http.Request) {
	var request CreateScanRequest

	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !request.AuthorizationConfirmed {
		writeError(w, http.StatusBadRequest,
			"explicit authorization confirmation is required")
		return
	}

	if strings.TrimSpace(request.TargetURL) == "" {
		writeError(w, http.StatusBadRequest, "target_url is required")
		return
	}

	started := time.Now().UTC()

	result, err := a.scanner.Scan(r.Context(), request.TargetURL)
	if err != nil {
		if errors.Is(err, scanner.ErrInvalidTarget) ||
			errors.Is(err, scanner.ErrTargetNotAllowed) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	id, err := newScanID()
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"could not generate scan ID")
		return
	}

	record := ScanRecord{
		ID:          id,
		TargetURL:   result.TargetURL,
		Status:      "completed",
		StartedAt:   started,
		CompletedAt: result.CheckedAt,
		Result:      result,
	}

	a.mu.Lock()
	a.scans = append(a.scans, record)
	a.mu.Unlock()

	writeJSON(w, http.StatusCreated, map[string]any{
		"scan": record,
	})
}

func (a *API) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")

		origin := r.Header.Get("Origin")

		allowed := origin == "http://localhost:5173" ||
			origin == "http://127.0.0.1:5173"

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			if !allowed {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}

			w.Header().Set("Access-Control-Allow-Methods",
				"GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers",
				"Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func decodeJSON(
	w http.ResponseWriter,
	r *http.Request,
	destination any,
) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid JSON request: %w", err)
	}

	var extra any

	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request must contain only one JSON object")
	}

	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}

func newScanID() (string, error) {
	var bytes [8]byte

	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}

	return "scan_" + hex.EncodeToString(bytes[:]), nil
}
