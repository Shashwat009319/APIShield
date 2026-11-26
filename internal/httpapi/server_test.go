package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	server := New("127.0.0.1:8080")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var response HealthResponse

	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}

	if response.Status != "ok" {
		t.Errorf("expected ok, got %s", response.Status)
	}

	if response.Service != "apishield" {
		t.Errorf("unexpected service: %s", response.Service)
	}
}

func TestDashboardSummaryEmpty(t *testing.T) {
	server := New(":0")

	req := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/dashboard/summary",
		nil,
	)

	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var summary DashboardSummary

	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}

	if summary.HasAssessment {
		t.Error("expected no assessment in an empty dashboard")
	}

	if summary.ScansCompleted != 0 {
		t.Errorf("expected zero scans, got %d", summary.ScansCompleted)
	}
}

func TestScanRequiresAuthorization(t *testing.T) {
	server := New(":0")

	body := `{
		"target_url": "http://127.0.0.1:9000",
		"authorization_confirmed": false
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/scans",
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestRemoteTargetRejected(t *testing.T) {
	server := New(":0")

	body := `{
		"target_url": "https://example.com",
		"authorization_confirmed": true
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/scans",
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCreateLocalScan(t *testing.T) {
	target := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("local test response"))
		}),
	)
	defer target.Close()

	server := New(":0")

	body := `{
		"target_url": "` + target.URL + `",
		"authorization_confirmed": true
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/scans",
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s",
			rec.Code, rec.Body.String())
	}

	var response struct {
		Scan ScanRecord `json:"scan"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}

	if response.Scan.ID == "" {
		t.Error("expected a generated scan ID")
	}

	if response.Scan.Status != "completed" {
		t.Errorf("expected completed status, got %s",
			response.Scan.Status)
	}

	if len(response.Scan.Result.Findings) == 0 {
		t.Error("expected missing-header findings from the test server")
	}

	if response.Scan.Result.HTTPStatus != http.StatusOK {
		t.Errorf("expected status 200, got %d",
			response.Scan.Result.HTTPStatus)
	}
}
