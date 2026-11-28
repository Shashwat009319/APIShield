package httpapi

import (
	"context"
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

	"github.com/Shashwat009319/apishield/internal/database"
	"github.com/Shashwat009319/apishield/internal/openapi"
	"github.com/Shashwat009319/apishield/internal/scanner"
)

const maxSpecSize = 2 << 20 // 2 MiB

type scanRepository interface {
	SaveScan(context.Context, database.ScanRecord) error
	ListScans(context.Context) ([]database.ScanRecord, error)
}

type specRepository interface {
	SaveAPISpec(context.Context, string, *openapi.ParsedSpec) error
	ListAPISpecs(context.Context) ([]database.APISpecRecord, error)
	GetAPISpec(context.Context, string) (*openapi.ParsedSpec, error)
}

type API struct {
	scanner *scanner.Scanner
	repo    scanRepository
	specs   specRepository
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
	return newServer(addr, nil)
}

func NewWithDatabase(addr string, db *database.Database) *http.Server {
	return newServer(addr, db)
}

func newServer(addr string, db *database.Database) *http.Server {
	api := &API{
		scanner: scanner.New(),
		scans:   make([]ScanRecord, 0),
	}

	if db != nil {
		api.repo = db
		api.specs = db
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", api.health)
	mux.HandleFunc("GET /api/v1/dashboard/summary", api.dashboardSummary)
	mux.HandleFunc("GET /api/v1/scans", api.listScans)
	mux.HandleFunc("POST /api/v1/scans", api.createScan)

	mux.HandleFunc("POST /api/v1/specs", api.uploadSpec)
	mux.HandleFunc("GET /api/v1/specs", api.listSpecs)
	mux.HandleFunc("GET /api/v1/specs/{id}", api.getSpec)

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
		Version: "0.3.0",
	})
}

func (a *API) getScans(ctx context.Context) ([]ScanRecord, error) {
	if a.repo != nil {
		stored, err := a.repo.ListScans(ctx)
		if err != nil {
			return nil, err
		}

		scans := make([]ScanRecord, 0, len(stored))
		for _, item := range stored {
			scans = append(scans, ScanRecord{
				ID:          item.ID,
				TargetURL:   item.TargetURL,
				Status:      item.Status,
				StartedAt:   item.StartedAt,
				CompletedAt: item.CompletedAt,
				Result:      item.Result,
			})
		}
		return scans, nil
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	scans := make([]ScanRecord, len(a.scans))
	copy(scans, a.scans)
	return scans, nil
}

func (a *API) dashboardSummary(w http.ResponseWriter, r *http.Request) {
	scans, err := a.getScans(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load dashboard data")
		return
	}

	summary := DashboardSummary{
		Status:         "ok",
		ScansCompleted: len(scans),
		URLsAssessed:   len(scans),
	}

	if len(scans) == 0 {
		writeJSON(w, http.StatusOK, summary)
		return
	}

	summary.HasAssessment = true
	score := 100

	for i := range scans {
		if summary.LastScan == nil ||
			scans[i].CompletedAt.After(*summary.LastScan) {
			last := scans[i].CompletedAt
			summary.LastScan = &last
		}

		for _, finding := range scans[i].Result.Findings {
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
	scans, err := a.getScans(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load scans")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

func (a *API) createScan(w http.ResponseWriter, r *http.Request) {
	var request CreateScanRequest

	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !request.AuthorizationConfirmed {
		writeError(w, http.StatusBadRequest, "explicit authorization confirmation is required")
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

	id, err := newID("scan")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate scan ID")
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

	if a.repo != nil {
		err := a.repo.SaveScan(r.Context(), database.ScanRecord{
			ID:          record.ID,
			TargetURL:   record.TargetURL,
			Status:      record.Status,
			StartedAt:   record.StartedAt,
			CompletedAt: record.CompletedAt,
			Result:      record.Result,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "scan completed but could not be saved")
			return
		}
	} else {
		a.mu.Lock()
		a.scans = append(a.scans, record)
		a.mu.Unlock()
	}

	writeJSON(w, http.StatusCreated, map[string]any{"scan": record})
}

// uploadSpec accepts a multipart form containing a file field named "file".
func (a *API) uploadSpec(w http.ResponseWriter, r *http.Request) {
	if a.specs == nil {
		writeError(w, http.StatusServiceUnavailable, "API inventory requires database storage")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSpecSize+256*1024)

	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart upload or file too large")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "upload a specification using the file field")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxSpecSize+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read uploaded specification")
		return
	}
	if len(data) == 0 {
		writeError(w, http.StatusBadRequest, "uploaded specification is empty")
		return
	}
	if len(data) > maxSpecSize {
		writeError(w, http.StatusRequestEntityTooLarge, "specification exceeds the 2 MiB limit")
		return
	}

	parsed, err := openapi.Parse(data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id, err := newID("spec")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate specification ID")
		return
	}

	if err := a.specs.SaveAPISpec(r.Context(), id, parsed); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save API specification")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":   id,
		"spec": parsed,
	})
}

func (a *API) listSpecs(w http.ResponseWriter, r *http.Request) {
	if a.specs == nil {
		writeError(w, http.StatusServiceUnavailable, "API inventory requires database storage")
		return
	}

	specs, err := a.specs.ListAPISpecs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load API inventory")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"specs": specs})
}

func (a *API) getSpec(w http.ResponseWriter, r *http.Request) {
	if a.specs == nil {
		writeError(w, http.StatusServiceUnavailable, "API inventory requires database storage")
		return
	}

	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "specification ID is required")
		return
	}

	spec, err := a.specs.GetAPISpec(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "API specification not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":   id,
		"spec": spec,
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

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
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
	writeJSON(w, status, map[string]string{"error": message})
}

func newID(prefix string) (string, error) {
	var bytes [8]byte

	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}

	return prefix + "_" + hex.EncodeToString(bytes[:]), nil
}
