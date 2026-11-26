
import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import type { LucideIcon } from "lucide-react";

import {
  Activity,
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  Bug,
  CheckCircle2,
  ChevronDown,
  FileText,
  LayoutDashboard,
  Layers,
  Network,
  Plus,
  Radar,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  Terminal,
} from "lucide-react";

import "./App.css";

const API_BASE = "http://127.0.0.1:8080";

type NavigationItem = {
  label: string;
  icon: LucideIcon;
};

type Finding = {
  rule_id: string;
  title: string;
  severity: string;
  category: string;
  description: string;
  evidence: string;
  remediation: string;
  endpoint: string;
};

type ScanRecord = {
  id: string;
  target_url: string;
  status: string;
  started_at: string;
  completed_at: string;
  result: {
    target_url: string;
    http_status: number;
    checked_at: string;
    findings: Finding[];
  };
};

type DashboardSummary = {
  status: string;
  has_assessment: boolean;
  scans_completed: number;
  urls_assessed: number;
  open_findings: number;
  critical_findings: number;
  security_posture: number;
  last_scan?: string;
};

type DisplayFinding = Finding & {
  scanId?: string;
  scanDate?: string;
};

const groups: { heading: string; items: NavigationItem[] }[] = [
  {
    heading: "WORKSPACE",
    items: [
      { label: "Overview", icon: LayoutDashboard },
      { label: "Scan Center", icon: Radar },
      { label: "API Inventory", icon: Network },
      { label: "Findings", icon: Bug },
    ],
  },
  {
    heading: "INTELLIGENCE",
    items: [
      { label: "Analytics", icon: Activity },
      { label: "Reports", icon: FileText },
      { label: "Integrations", icon: Layers },
    ],
  },
  {
    heading: "CONFIGURATION",
    items: [{ label: "Settings", icon: Settings }],
  },
];

async function requestJSON<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, options);
  const data: unknown = await response.json().catch(() => null);

  if (!response.ok) {
    let message = `Request failed: HTTP ${response.status}`;

    if (
      data &&
      typeof data === "object" &&
      "error" in data &&
      typeof data.error === "string"
    ) {
      message = data.error;
    }

    throw new Error(message);
  }

  return data as T;
}

function formatDate(value?: string): string {
  if (!value) return "No assessments yet";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return "Unknown";

  return date.toLocaleString();
}

function App() {
  const [activePage, setActivePage] = useState("Overview");
  const [targetURL, setTargetURL] = useState(
    "http://127.0.0.1:8080/health"
  );
  const [authorized, setAuthorized] = useState(false);

  const [summary, setSummary] = useState<DashboardSummary>({
    status: "loading",
    has_assessment: false,
    scans_completed: 0,
    urls_assessed: 0,
    open_findings: 0,
    critical_findings: 0,
    security_posture: 0,
  });

  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const loadDashboard = useCallback(async () => {
    setLoading(true);

    try {
      const [dashboardData, scanData] = await Promise.all([
        requestJSON<DashboardSummary>("/api/v1/dashboard/summary"),
        requestJSON<{ scans: ScanRecord[] }>("/api/v1/scans"),
      ]);

      setSummary(dashboardData);
      setScans(scanData.scans ?? []);
      setConnected(true);
      setError("");
    } catch (err) {
      setConnected(false);
      setError(
        err instanceof Error
          ? err.message
          : "Unable to connect to APIShield backend."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  const findings = useMemo<DisplayFinding[]>(
    () =>
      scans.flatMap((scan) =>
        (scan.result?.findings ?? []).map((finding) => ({
          ...finding,
          scanId: scan.id,
          scanDate: scan.completed_at,
        }))
      ),
    [scans]
  );

  const metrics = [
    {
      label: "COMPLETED SCANS",
      value: summary.scans_completed.toString(),
      note: "TOTAL ASSESSMENTS",
      tone: "positive",
      icon: Network,
    },
    {
      label: "OPEN FINDINGS",
      value: summary.open_findings.toString(),
      note: "ALL SEVERITIES",
      tone: "negative",
      icon: AlertTriangle,
    },
    {
      label: "CRITICAL FINDINGS",
      value: summary.critical_findings.toString(),
      note: "HIGH PRIORITY",
      tone: "negative",
      icon: Bug,
    },
    {
      label: "SECURITY POSTURE",
      value: summary.has_assessment
        ? String(summary.security_posture)
        : "—",
      note: summary.has_assessment ? "OUT OF 100" : "AWAITING SCAN",
      tone: "neutral",
      icon: ShieldCheck,
    },
  ];

  async function handleScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setNotice("");
    setError("");

    if (!authorized) {
      setError(
        "Confirm that you are authorized to assess this target."
      );
      return;
    }

    setSubmitting(true);

    try {
      const response = await requestJSON<{ scan: ScanRecord }>(
        "/api/v1/scans",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            target_url: targetURL.trim(),
            authorization_confirmed: true,
          }),
        }
      );

      setNotice(
        `Assessment completed successfully: ${response.scan.id}`
      );

      setAuthorized(false);
      await loadDashboard();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Assessment could not be completed."
      );
    } finally {
      setSubmitting(false);
    }
  }

  const latestScan = scans[scans.length - 1];

  return (
    <div className="bureau-shell">
      <aside className="bureau-sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={23} />
          </div>
          <div className="brand-word">
            <strong>API<span>SHIELD</span></strong>
            <small>SECURITY BUREAU</small>
          </div>
        </div>

        <div className="sidebar-workspace">
          <div className="workspace-monogram">P</div>
          <div className="workspace-name">
            <small>CURRENT WORKSPACE</small>
            <strong>Personal Sandbox</strong>
          </div>
          <ChevronDown size={14} />
        </div>

        <nav className="navigation">
          {groups.map((group) => (
            <section
              className="navigation-group"
              key={group.heading}
            >
              <div className="navigation-heading">
                {group.heading}
              </div>

              {group.items.map((item) => {
                const Icon = item.icon;

                return (
                  <button
                    key={item.label}
                    className={`navigation-link ${
                      activePage === item.label ? "selected" : ""
                    }`}
                    onClick={() => {
                      setActivePage(item.label);
                      setError("");
                      setNotice("");
                    }}
                  >
                    <Icon size={17} />
                    <span>{item.label}</span>

                    {item.label === "Findings" && findings.length > 0 && (
                      <span className="finding-count">
                        {findings.length}
                      </span>
                    )}
                  </button>
                );
              })}
            </section>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-status">
            <div className="status-heading">
              <span className="online-dot" />
              {connected
                ? "BACKEND CONNECTED"
                : "BACKEND DISCONNECTED"}
            </div>

            <div className="status-description">
              API service
              <strong>
                {connected ? "OPERATIONAL" : "UNAVAILABLE"}
              </strong>
            </div>
          </div>

          <div className="user-profile">
            <div className="user-avatar">SY</div>
            <div>
              <strong>Shashwat Yadav</strong>
              <small>Workspace administrator</small>
            </div>
          </div>
        </div>
      </aside>

      <main className="bureau-main">
        <header className="bureau-topbar">
          <div className="breadcrumb">
            <span>API SHIELD</span>
            <span>/</span>
            <strong>{activePage.toUpperCase()}</strong>
          </div>

          <div className="topbar-actions">
            <div className="search-box">
              <Search size={15} />
              <span>Live workspace</span>
            </div>

            <button
              className="topbar-icon"
              aria-label="Refresh dashboard"
              onClick={() => void loadDashboard()}
              disabled={loading}
            >
              <RefreshCw size={17} />
            </button>

            <div className="topbar-divider" />
            <div className="topbar-user">SY</div>
          </div>
        </header>

        <div className="bureau-content">
          {activePage === "Overview" && (
            <>
              <section className="intro-row">
                <div>
                  <div className="eyebrow">
                    <span className="eyebrow-bar" />
                    SECURITY INTELLIGENCE / LIVE DATA
                  </div>

                  <h1>
                    Security, without
                    <br />
                    the blind spots<span>.</span>
                  </h1>

                  <p>
                    Your API security posture, assessments and findings
                    from the live Go backend.
                  </p>
                </div>

                <div className="intro-actions">
                  <span className="report-date">
                    {connected
                      ? "LIVE BACKEND"
                      : "CONNECTION UNAVAILABLE"}
                  </span>

                  <button
                    className="run-button"
                    onClick={() => {
                      setActivePage("Scan Center");
                      setError("");
                    }}
                  >
                    <Plus size={17} />
                    New assessment
                  </button>
                </div>
              </section>

              <section className="brief">
                <div className="brief-copy">
                  <div className="brief-reference">
                    <span>API SECURITY OVERVIEW</span>
                    <span>BUILD 0.2.0</span>
                  </div>

                  <h2>
                    Measure exposure.
                    <br />
                    Improve security.
                  </h2>

                  <p>
                    APIShield evaluates HTTP response security,
                    identifies configuration weaknesses and records
                    evidence for remediation.
                  </p>

                  <button
                    className="brief-link"
                    onClick={() => setActivePage("Scan Center")}
                  >
                    Open scan center
                    <ArrowUpRight size={16} />
                  </button>
                </div>

                <div className="brief-map">
                  <div className="map-topline">
                    <span>01 / SCANNER STATUS</span>
                    <span>
                      <i />
                      {connected ? "CONNECTED" : "DISCONNECTED"}
                    </span>
                  </div>

                  <div className="topology">
                    <div className="topology-ring ring-a" />
                    <div className="topology-ring ring-b" />
                    <div className="topology-ring ring-c" />

                    <div className="topology-line line-a" />
                    <div className="topology-line line-b" />
                    <div className="topology-line line-c" />
                    <div className="topology-line line-d" />

                    <div className="topology-core">
                      <ShieldCheck size={27} />
                      <span>API CORE</span>
                    </div>

                    <div className="topology-node node-a">HTTP</div>
                    <div className="topology-node node-b">HEADERS</div>
                    <div className="topology-node node-c">CORS</div>
                    <div className="topology-node node-d">COOKIES</div>
                  </div>

                  <div className="map-bottomline">
                    <span>PASSIVE SECURITY ASSESSMENT</span>
                    <span>V0.2.0</span>
                  </div>
                </div>
              </section>

              <div className="section-label">
                <span>01</span>
                LIVE ENVIRONMENT SNAPSHOT
                <i />
                <small>{loading ? "REFRESHING" : "BACKEND DATA"}</small>
              </div>

              <section className="metrics">
                {metrics.map((metric) => {
                  const Icon = metric.icon;

                  return (
                    <article
                      className="metric"
                      key={metric.label}
                    >
                      <div className="metric-heading">
                        <span>{metric.label}</span>
                        <Icon size={17} />
                      </div>

                      <div className="metric-number">
                        {metric.value}
                      </div>

                      <div className={`metric-note ${metric.tone}`}>
                        <span className="metric-marker" />
                        {metric.note}
                      </div>
                    </article>
                  );
                })}
              </section>

              <section className="data-panel findings-panel">
                <div className="panel-header findings-title">
                  <div>
                    <span className="eyebrow">
                      02 / LATEST ASSESSMENTS
                    </span>
                    <h3>Recent scan activity</h3>
                  </div>

                  <button
                    className="filter-button"
                    onClick={() => setActivePage("Scan Center")}
                  >
                    OPEN SCAN CENTER
                    <ArrowRight size={14} />
                  </button>
                </div>

                {loading ? (
                  <div className="empty-state">
                    Loading scan history...
                  </div>
                ) : scans.length === 0 ? (
                  <div className="empty-state">
                    <Radar size={26} />
                    <strong>No assessments yet</strong>
                    <span>
                      Start your first authorized local security assessment.
                    </span>
                    <button
                      className="secondary-action"
                      onClick={() => setActivePage("Scan Center")}
                    >
                      Create first scan
                    </button>
                  </div>
                ) : (
                  <ScanTable
                    scans={scans.slice().reverse().slice(0, 5)}
                  />
                )}
              </section>

              <section className="data-panel findings-panel">
                <div className="panel-header findings-title">
                  <div>
                    <span className="eyebrow">
                      03 / SECURITY INTELLIGENCE
                    </span>
                    <h3>Latest findings</h3>
                  </div>

                  <button
                    className="filter-button"
                    onClick={() => setActivePage("Findings")}
                  >
                    VIEW ALL
                    <ArrowRight size={14} />
                  </button>
                </div>

                {findings.length === 0 ? (
                  <div className="empty-state compact">
                    Findings will appear here after an assessment.
                  </div>
                ) : (
                  <FindingTable findings={findings.slice(0, 5)} />
                )}
              </section>
            </>
          )}

          {activePage === "Scan Center" && (
            <>
              <section className="intro-row">
                <div>
                  <div className="eyebrow">
                    <span className="eyebrow-bar" />
                    SECURITY OPERATIONS / SCAN CENTER
                  </div>

                  <h1>
                    Assess your
                    <br />
                    attack surface<span>.</span>
                  </h1>

                  <p>
                    Run a passive HTTP security assessment against an
                    authorized local target.
                  </p>
                </div>
              </section>

              <section className="data-panel scan-form-panel">
                <div className="panel-header">
                  <div>
                    <span className="eyebrow">NEW ASSESSMENT</span>
                    <h3>Target configuration</h3>
                    <p>
                      Current scanner supports localhost targets only.
                    </p>
                  </div>
                  <Radar size={24} />
                </div>

                <form className="scan-form" onSubmit={handleScan}>
                  <label htmlFor="target-url">TARGET URL</label>

                  <input
                    id="target-url"
                    className="target-input"
                    type="url"
                    required
                    value={targetURL}
                    onChange={(event) =>
                      setTargetURL(event.target.value)
                    }
                    placeholder="http://127.0.0.1:8080/health"
                  />

                  <label className="authorization-check">
                    <input
                      type="checkbox"
                      checked={authorized}
                      onChange={(event) =>
                        setAuthorized(event.target.checked)
                      }
                    />
                    <span>
                      I own this target or have explicit permission
                      to assess it.
                    </span>
                  </label>

                  <div className="scan-actions">
                    <button
                      className="run-button"
                      type="submit"
                      disabled={submitting || !authorized || !connected}
                    >
                      {submitting ? (
                        <RefreshCw size={16} className="spin-icon" />
                      ) : (
                        <Plus size={16} />
                      )}

                      {submitting ? "Assessing..." : "Start assessment"}
                    </button>

                    <span>
                      PASSIVE HTTP CHECKS / LOCAL TARGETS ONLY
                    </span>
                  </div>
                </form>
              </section>

              <section className="data-panel findings-panel">
                <div className="panel-header findings-title">
                  <div>
                    <span className="eyebrow">SCAN HISTORY</span>
                    <h3>Previous assessments</h3>
                  </div>

                  <button
                    className="filter-button"
                    onClick={() => void loadDashboard()}
                  >
                    <RefreshCw size={13} />
                    REFRESH
                  </button>
                </div>

                {scans.length === 0 ? (
                  <div className="empty-state compact">
                    No scan history yet.
                  </div>
                ) : (
                  <ScanTable scans={scans.slice().reverse()} />
                )}
              </section>
            </>
          )}

          {activePage === "Findings" && (
            <>
              <section className="intro-row">
                <div>
                  <div className="eyebrow">
                    SECURITY INTELLIGENCE / FINDINGS
                  </div>

                  <h1>
                    Vulnerability
                    <br />
                    register<span>.</span>
                  </h1>

                  <p>
                    Evidence and remediation from actual scan results.
                  </p>
                </div>
              </section>

              <section className="data-panel findings-panel">
                <div className="panel-header findings-title">
                  <div>
                    <span className="eyebrow">ALL ASSESSMENTS</span>
                    <h3>{findings.length} recorded findings</h3>
                  </div>
                </div>

                {findings.length === 0 ? (
                  <div className="empty-state compact">
                    No findings recorded. Run an assessment first.
                  </div>
                ) : (
                  <FindingTable findings={findings} detailed />
                )}
              </section>
            </>
          )}

          {activePage === "API Inventory" && (
            <>
              <section className="intro-row">
                <div>
                  <div className="eyebrow">
                    ASSET MANAGEMENT / INVENTORY
                  </div>

                  <h1>
                    Assessed targets<span>.</span>
                  </h1>

                  <p>
                    Inventory of URLs assessed by APIShield.
                  </p>
                </div>
              </section>

              <section className="data-panel findings-panel">
                <div className="panel-header findings-title">
                  <h3>{scans.length} assessed targets</h3>
                </div>

                {scans.length === 0 ? (
                  <div className="empty-state compact">
                    Your inventory is empty.
                  </div>
                ) : (
                  <ScanTable scans={scans.slice().reverse()} />
                )}
              </section>
            </>
          )}

          {activePage === "Analytics" && (
            <>
              <section className="intro-row">
                <div>
                  <div className="eyebrow">
                    INTELLIGENCE / ANALYTICS
                  </div>

                  <h1>
                    Assessment analytics<span>.</span>
                  </h1>

                  <p>
                    Current statistics calculated from recorded assessments.
                  </p>
                </div>
              </section>

              <section className="metrics">
                {metrics.map((metric) => {
                  const Icon = metric.icon;

                  return (
                    <article
                      className="metric"
                      key={metric.label}
                    >
                      <div className="metric-heading">
                        <span>{metric.label}</span>
                        <Icon size={17} />
                      </div>

                      <div className="metric-number">
                        {metric.value}
                      </div>

                      <div className={`metric-note ${metric.tone}`}>
                        {metric.note}
                      </div>
                    </article>
                  );
                })}
              </section>

              <div className="data-panel analytics-note">
                <h3>Analytics source</h3>
                <p>
                  These values come from the Go backend process.
                  Historical trend analysis will follow after persistent
                  database storage is implemented.
                </p>
              </div>
            </>
          )}

          {![
            "Overview",
            "Scan Center",
            "Findings",
            "API Inventory",
            "Analytics",
          ].includes(activePage) && (
            <section className="module-page">
              <span className="eyebrow">API SHIELD / MODULE</span>

              <h1>{activePage}</h1>

              <p>
                This module is planned for a later development milestone.
              </p>

              <button
                className="outline-button"
                onClick={() => setActivePage("Overview")}
              >
                <ArrowRight size={15} />
                Return to overview
              </button>
            </section>
          )}

          {latestScan && (
            <div className="last-scan-note">
              <CheckCircle2 size={14} />
              Last completed scan: {formatDate(latestScan.completed_at)}
            </div>
          )}

          {error && (
            <div className="feedback-message error-message" role="alert">
              <AlertTriangle size={16} />
              <span>{error}</span>
              <button onClick={() => setError("")}>×</button>
            </div>
          )}

          {notice && (
            <div className="feedback-message success-message" role="status">
              <CheckCircle2 size={16} />
              <span>{notice}</span>
              <button onClick={() => setNotice("")}>×</button>
            </div>
          )}

          <footer className="bureau-footer">
            <span>API SHIELD / SECURITY INTELLIGENCE PLATFORM</span>
            <span>
              <Terminal size={12} />
              BUILD 0.2.0 / {connected ? "BACKEND ONLINE" : "OFFLINE"}
            </span>
          </footer>
        </div>
      </main>
    </div>
  );
}

function ScanTable({ scans }: { scans: ScanRecord[] }) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>SCAN ID</th>
            <th>TARGET</th>
            <th>HTTP STATUS</th>
            <th>FINDINGS</th>
            <th>COMPLETED</th>
          </tr>
        </thead>

        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td className="reference">{scan.id}</td>
              <td className="endpoint">{scan.target_url}</td>
              <td>{scan.result?.http_status ?? "—"}</td>
              <td>{scan.result?.findings?.length ?? 0}</td>
              <td className="age">
                {formatDate(scan.completed_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FindingTable({
  findings,
  detailed = false,
}: {
  findings: DisplayFinding[];
  detailed?: boolean;
}) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>RULE</th>
            <th>VULNERABILITY</th>
            <th>SEVERITY</th>
            <th>ENDPOINT</th>
            {detailed && <th>REMEDIATION</th>}
          </tr>
        </thead>

        <tbody>
          {findings.map((finding, index) => (
            <tr key={`${finding.rule_id}-${finding.scanId ?? index}`}>
              <td className="reference">{finding.rule_id}</td>

              <td>
                <strong className="issue-title">
                  {finding.title}
                </strong>

                <small className="issue-type">
                  {finding.category}
                </small>

                {detailed && (
                  <small className="finding-evidence">
                    Evidence: {finding.evidence}
                  </small>
                )}
              </td>

              <td>
                <span
                  className={`severity severity-${finding.severity.toLowerCase()}`}
                >
                  {finding.severity}
                </span>
              </td>

              <td className="endpoint">{finding.endpoint}</td>

              {detailed && (
                <td className="remediation">
                  {finding.remediation}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default App;
