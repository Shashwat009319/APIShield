package database

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"time"

	"github.com/Shashwat009319/apishield/internal/openapi"
	"github.com/Shashwat009319/apishield/internal/scanner"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Database struct {
	Pool *pgxpool.Pool
}

type ScanRecord struct {
	ID          string
	TargetURL   string
	Status      string
	StartedAt   time.Time
	CompletedAt time.Time
	Result      scanner.Result
}

type APISpecRecord struct {
	ID             string
	Title          string
	Version        string
	OpenAPIVersion string
	Description    string
	EndpointCount  int
	ImportedAt     time.Time
}

func Open(ctx context.Context, databaseURL string) (*Database, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}

	config.MaxConns = 10
	config.MinConns = 2
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}

	db := &Database{Pool: pool}

	if err := db.Migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return db, nil
}

func (db *Database) Close() {
	db.Pool.Close()
}

func (db *Database) Migrate(ctx context.Context) error {
	files, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("find migrations: %w", err)
	}

	sort.Strings(files)

	for _, filename := range files {
		query, err := migrationFiles.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", filename, err)
		}

		if _, err := db.Pool.Exec(ctx, string(query)); err != nil {
			return fmt.Errorf("run migration %s: %w", filename, err)
		}

		log.Printf("Database migration checked: %s", filename)
	}

	return nil
}

// SaveScan stores the scan and all its findings atomically.
func (db *Database) SaveScan(ctx context.Context, scan ScanRecord) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin scan transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	resultJSON, err := json.Marshal(scan.Result)
	if err != nil {
		return fmt.Errorf("encode scan result: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO scans
			(id, target_url, status, started_at, completed_at, http_status, result)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`,
		scan.ID,
		scan.TargetURL,
		scan.Status,
		scan.StartedAt,
		scan.CompletedAt,
		scan.Result.HTTPStatus,
		resultJSON,
	)
	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}

	for _, finding := range scan.Result.Findings {
		_, err = tx.Exec(ctx, `
			INSERT INTO findings
				(scan_id, rule_id, title, severity, category,
				 description, evidence, remediation, endpoint)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`,
			scan.ID,
			finding.RuleID,
			finding.Title,
			finding.Severity,
			finding.Category,
			finding.Description,
			finding.Evidence,
			finding.Remediation,
			finding.Endpoint,
		)
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", finding.RuleID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit scan transaction: %w", err)
	}

	return nil
}

// ListScans retrieves persisted scans, newest first.
func (db *Database) ListScans(ctx context.Context) ([]ScanRecord, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, target_url, status, started_at, completed_at, result
		FROM scans
		ORDER BY completed_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("query scans: %w", err)
	}
	defer rows.Close()

	scans := make([]ScanRecord, 0)

	for rows.Next() {
		var scan ScanRecord
		var resultJSON []byte

		err := rows.Scan(
			&scan.ID,
			&scan.TargetURL,
			&scan.Status,
			&scan.StartedAt,
			&scan.CompletedAt,
			&resultJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("read scan: %w", err)
		}

		if err := json.Unmarshal(resultJSON, &scan.Result); err != nil {
			return nil, fmt.Errorf("decode scan result: %w", err)
		}

		scans = append(scans, scan)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scans: %w", err)
	}

	return scans, nil
}

// SaveAPISpec stores an OpenAPI document and its endpoints atomically.
func (db *Database) SaveAPISpec(
	ctx context.Context,
	id string,
	spec *openapi.ParsedSpec,
) error {
	if spec == nil {
		return fmt.Errorf("OpenAPI specification is nil")
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin API specification transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO api_specs
			(id, title, version, openapi_version, description, endpoint_count)
		VALUES ($1, $2, $3, $4, $5, $6)
	`,
		id,
		spec.Title,
		spec.Version,
		spec.OpenAPIVersion,
		spec.Description,
		spec.EndpointCount,
	)
	if err != nil {
		return fmt.Errorf("insert API specification: %w", err)
	}

	for _, endpoint := range spec.Endpoints {
		parametersJSON, err := json.Marshal(endpoint.Parameters)
		if err != nil {
			return fmt.Errorf("encode endpoint parameters: %w", err)
		}

		schemesJSON, err := json.Marshal(endpoint.SecuritySchemes)
		if err != nil {
			return fmt.Errorf("encode security schemes: %w", err)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO api_endpoints
				(spec_id, path, method, operation_id, summary,
				 parameters, has_request_body, security_declared, security_schemes)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`,
			id,
			endpoint.Path,
			endpoint.Method,
			endpoint.OperationID,
			endpoint.Summary,
			parametersJSON,
			endpoint.HasRequestBody,
			endpoint.SecurityDeclared,
			schemesJSON,
		)
		if err != nil {
			return fmt.Errorf("insert endpoint %s %s: %w",
				endpoint.Method, endpoint.Path, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit API specification: %w", err)
	}

	return nil
}

// ListAPISpecs retrieves imported specifications, newest first.
func (db *Database) ListAPISpecs(ctx context.Context) ([]APISpecRecord, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, title, version, openapi_version,
		       description, endpoint_count, imported_at
		FROM api_specs
		ORDER BY imported_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("query API specifications: %w", err)
	}
	defer rows.Close()

	specs := make([]APISpecRecord, 0)

	for rows.Next() {
		var spec APISpecRecord

		if err := rows.Scan(
			&spec.ID,
			&spec.Title,
			&spec.Version,
			&spec.OpenAPIVersion,
			&spec.Description,
			&spec.EndpointCount,
			&spec.ImportedAt,
		); err != nil {
			return nil, fmt.Errorf("read API specification: %w", err)
		}

		specs = append(specs, spec)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate API specifications: %w", err)
	}

	return specs, nil
}

// GetAPISpec retrieves a specification and its stored endpoints.
func (db *Database) GetAPISpec(
	ctx context.Context,
	id string,
) (*openapi.ParsedSpec, error) {
	var spec openapi.ParsedSpec

	err := db.Pool.QueryRow(ctx, `
		SELECT title, version, openapi_version, description, endpoint_count
		FROM api_specs
		WHERE id = $1
	`, id).Scan(
		&spec.Title,
		&spec.Version,
		&spec.OpenAPIVersion,
		&spec.Description,
		&spec.EndpointCount,
	)
	if err != nil {
		return nil, err
	}

	rows, err := db.Pool.Query(ctx, `
		SELECT path, method, operation_id, summary, parameters,
		       has_request_body, security_declared, security_schemes
		FROM api_endpoints
		WHERE spec_id = $1
		ORDER BY path, method
	`, id)
	if err != nil {
		return nil, fmt.Errorf("query API endpoints: %w", err)
	}
	defer rows.Close()

	spec.Endpoints = make([]openapi.Endpoint, 0)

	for rows.Next() {
		var endpoint openapi.Endpoint
		var parametersJSON []byte
		var schemesJSON []byte

		if err := rows.Scan(
			&endpoint.Path,
			&endpoint.Method,
			&endpoint.OperationID,
			&endpoint.Summary,
			&parametersJSON,
			&endpoint.HasRequestBody,
			&endpoint.SecurityDeclared,
			&schemesJSON,
		); err != nil {
			return nil, fmt.Errorf("read API endpoint: %w", err)
		}

		if err := json.Unmarshal(parametersJSON, &endpoint.Parameters); err != nil {
			return nil, fmt.Errorf("decode endpoint parameters: %w", err)
		}

		if err := json.Unmarshal(schemesJSON, &endpoint.SecuritySchemes); err != nil {
			return nil, fmt.Errorf("decode security schemes: %w", err)
		}

		spec.Endpoints = append(spec.Endpoints, endpoint)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate API endpoints: %w", err)
	}

	return &spec, nil
}
