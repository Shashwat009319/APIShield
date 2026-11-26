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
