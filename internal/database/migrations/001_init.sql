CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    target_url   TEXT NOT NULL,
    status       TEXT NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    http_status  INTEGER NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id      TEXT NOT NULL,
    title        TEXT NOT NULL,
    severity     TEXT NOT NULL,
    category     TEXT NOT NULL,
    description  TEXT NOT NULL,
    evidence     TEXT NOT NULL,
    remediation  TEXT NOT NULL,
    endpoint     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_completed_at
    ON scans (completed_at DESC);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id
    ON findings (scan_id);

CREATE INDEX IF NOT EXISTS idx_findings_severity
    ON findings (severity);