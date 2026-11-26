
CREATE TABLE IF NOT EXISTS api_specs (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    version TEXT NOT NULL,
    openapi_version TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    endpoint_count INTEGER NOT NULL DEFAULT 0,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_endpoints (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    spec_id TEXT NOT NULL REFERENCES api_specs(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    method TEXT NOT NULL,
    operation_id TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    parameters JSONB NOT NULL DEFAULT '[]'::jsonb,
    has_request_body BOOLEAN NOT NULL DEFAULT FALSE,
    security_declared BOOLEAN NOT NULL DEFAULT FALSE,
    security_schemes JSONB NOT NULL DEFAULT '[]'::jsonb,
    UNIQUE (spec_id, path, method)
);

CREATE INDEX IF NOT EXISTS idx_api_endpoints_spec_id
ON api_endpoints(spec_id);

CREATE INDEX IF NOT EXISTS idx_api_endpoints_method
ON api_endpoints(method);

CREATE INDEX IF NOT EXISTS idx_api_endpoints_security
ON api_endpoints(security_declared);
