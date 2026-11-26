
import { useState } from "react";
import type { LucideIcon } from "lucide-react";

import {
  Activity,
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  Bell,
  Bug,
  ChevronDown,
  Clock3,
  FileText,
  LayoutDashboard,
  Layers,
  Network,
  Plus,
  Radar,
  Search,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
} from "lucide-react";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type NavigationItem = {
  label: string;
  icon: LucideIcon;
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

const trend = [
  { day: "20 NOV", requests: 410, threats: 28 },
  { day: "21 NOV", requests: 490, threats: 34 },
  { day: "22 NOV", requests: 390, threats: 25 },
  { day: "23 NOV", requests: 580, threats: 43 },
  { day: "24 NOV", requests: 530, threats: 31 },
  { day: "25 NOV", requests: 710, threats: 54 },
  { day: "26 NOV", requests: 650, threats: 41 },
];

const findings = [
  {
    id: "AS-014",
    title: "Insufficient rate limiting",
    endpoint: "POST /v1/auth/login",
    type: "AUTHENTICATION",
    severity: "Critical",
    age: "12m ago",
  },
  {
    id: "AS-013",
    title: "Missing security headers",
    endpoint: "GET /v1/users/profile",
    type: "CONFIGURATION",
    severity: "High",
    age: "38m ago",
  },
  {
    id: "AS-012",
    title: "Permissive CORS policy",
    endpoint: "GET /v1/public/data",
    type: "CORS",
    severity: "Medium",
    age: "1h ago",
  },
  {
    id: "AS-011",
    title: "Cookie missing SameSite",
    endpoint: "POST /v1/session",
    type: "SESSION",
    severity: "Low",
    age: "3h ago",
  },
];

function Metric({
  label,
  value,
  unit,
  note,
  accent,
  icon: Icon,
}: {
  label: string;
  value: string;
  unit?: string;
  note: string;
  accent: string;
  icon: LucideIcon;
}) {
  return (
    <article className="metric">
      <div className="metric-heading">
        <span>{label}</span>
        <Icon size={17} strokeWidth={1.6} />
      </div>

      <div className="metric-number">
        {value}<small>{unit}</small>
      </div>

      <div className={`metric-note ${accent}`}>
        <span className="metric-marker" />
        {note}
      </div>
    </article>
  );
}

function App() {
  const [activePage, setActivePage] = useState("Overview");
  const [notice, setNotice] = useState("");

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
            <section className="navigation-group" key={group.heading}>
              <div className="navigation-heading">{group.heading}</div>

              {group.items.map((item) => {
                const Icon = item.icon;
                const active = activePage === item.label;

                return (
                  <button
                    key={item.label}
                    className={`navigation-link ${
                      active ? "selected" : ""
                    }`}
                    onClick={() => {
                      setActivePage(item.label);
                      setNotice("");
                    }}
                  >
                    <Icon size={17} strokeWidth={1.7} />
                    <span>{item.label}</span>

                    {item.label === "Findings" && (
                      <span className="finding-count">14</span>
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
              LOCAL ENVIRONMENT
            </div>

            <div className="status-description">
              Scanner engine
              <strong>IN DEVELOPMENT</strong>
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
              <span>Search workspace</span>
              <kbd>⌘ K</kbd>
            </div>

            <button
              className="topbar-icon"
              aria-label="Notifications"
              onClick={() =>
                setNotice(
                  "Notifications will be connected in a later milestone."
                )
              }
            >
              <Bell size={18} />
            </button>

            <div className="topbar-divider" />
            <div className="topbar-user">SY</div>
          </div>
        </header>

        <div className="bureau-content">
          {activePage !== "Overview" ? (
            <section className="module-page">
              <span className="eyebrow">API SHIELD / MODULE</span>

              <h1>{activePage}</h1>

              <p>
                This module is part of the APIShield architecture.
                We'll implement its functionality and connect it to the
                Go backend in upcoming milestones.
              </p>

              <button
                className="outline-button"
                onClick={() => setActivePage("Overview")}
              >
                <ArrowRight size={15} />
                Return to overview
              </button>
            </section>
          ) : (
            <>
              <section className="intro-row">
                <div>
                  <div className="eyebrow">
                    <span className="eyebrow-bar" />
                    SECURITY INTELLIGENCE / 01
                  </div>

                  <h1>
                    Security, without
                    <br />
                    the blind spots<span>.</span>
                  </h1>

                  <p>
                    Understand your API surface. Prioritise exposure.
                    Make informed security decisions.
                  </p>
                </div>

                <div className="intro-actions">
                  <span className="report-date">
                    THURSDAY / 26 NOV 2026
                  </span>

                  <button
                    className="run-button"
                    onClick={() =>
                      setNotice(
                        "The scan engine is not connected yet. Scan creation will be enabled after its backend implementation."
                      )
                    }
                  >
                    <Plus size={17} />
                    Run assessment
                  </button>
                </div>
              </section>

              <section className="brief">
                <div className="brief-copy">
                  <div className="brief-reference">
                    <span>FIELD REPORT 001</span>
                    <span>DEVELOPMENT PREVIEW</span>
                  </div>

                  <h2>
                    Know what
                    <br />
                    you're exposing.
                  </h2>

                  <p>
                    One place to inspect API endpoints, understand
                    security weaknesses and track remediation across
                    your environment.
                  </p>

                  <button
                    className="brief-link"
                    onClick={() => setActivePage("Findings")}
                  >
                    Review security findings
                    <ArrowUpRight size={16} />
                  </button>
                </div>

                <div className="brief-map">
                  <div className="map-topline">
                    <span>01 / SURFACE TOPOLOGY</span>
                    <span><i /> CONCEPTUAL MAP</span>
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

                    <div className="topology-node node-a">AUTH</div>
                    <div className="topology-node node-b">DATA</div>
                    <div className="topology-node node-c">EDGE</div>
                    <div className="topology-node node-d">USER</div>
                  </div>

                  <div className="map-bottomline">
                    <span>SCHEMATIC / NOT LIVE DISCOVERY</span>
                    <span>REF. 001-A</span>
                  </div>
                </div>
              </section>

              <div className="section-label">
                <span>01</span>
                ENVIRONMENT SNAPSHOT
                <i />
                <small>ILLUSTRATIVE DATA — NOT LIVE RESULTS</small>
              </div>

              <section className="metrics">
                <Metric
                  label="DISCOVERED ENDPOINTS"
                  value="128"
                  note="+12 THIS WEEK"
                  accent="positive"
                  icon={Network}
                />

                <Metric
                  label="OPEN FINDINGS"
                  value="14"
                  note="02 CRITICAL"
                  accent="negative"
                  icon={AlertTriangle}
                />

                <Metric
                  label="SECURITY POSTURE"
                  value="86"
                  unit="/100"
                  note="+8.4% THIS WEEK"
                  accent="positive"
                  icon={ShieldCheck}
                />

                <Metric
                  label="LAST ASSESSMENT"
                  value="04"
                  unit="HRS"
                  note="SAMPLE ASSESSMENT"
                  accent="neutral"
                  icon={Clock3}
                />
              </section>

              <div className="lower-grid">
                <section className="data-panel trend-panel">
                  <div className="panel-header">
                    <div>
                      <span className="eyebrow">02 / OBSERVABILITY</span>
                      <h3>Traffic & threat activity</h3>
                      <p>Seven-day illustrative telemetry</p>
                    </div>

                    <button
                      className="filter-button"
                      onClick={() =>
                        setNotice(
                          "The current chart uses a fixed seven-day sample."
                        )
                      }
                    >
                      <SlidersHorizontal size={14} />
                      7 DAYS
                    </button>
                  </div>

                  <div className="chart-key">
                    <span>
                      <i className="key-requests" />
                      Requests
                    </span>
                    <span>
                      <i className="key-threats" />
                      Threat signals
                    </span>
                  </div>

                  <div className="trend-chart">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={trend}>
                        <defs>
                          <linearGradient
                            id="requestFill"
                            x1="0"
                            y1="0"
                            x2="0"
                            y2="1"
                          >
                            <stop
                              offset="0%"
                              stopColor="#9a7cc5"
                              stopOpacity={0.24}
                            />
                            <stop
                              offset="100%"
                              stopColor="#9a7cc5"
                              stopOpacity={0}
                            />
                          </linearGradient>
                        </defs>

                        <CartesianGrid
                          stroke="#e6e0d9"
                          vertical={false}
                        />

                        <XAxis
                          dataKey="day"
                          axisLine={false}
                          tickLine={false}
                          tick={{ fill: "#817a85", fontSize: 9 }}
                          tickMargin={12}
                        />

                        <YAxis
                          axisLine={false}
                          tickLine={false}
                          tick={{ fill: "#817a85", fontSize: 10 }}
                          width={31}
                        />

                        <Tooltip
                          contentStyle={{
                            background: "#25212d",
                            color: "#fff",
                            border: "1px solid #52435e",
                            borderRadius: 4,
                            fontSize: 11,
                          }}
                        />

                        <Area
                          type="monotone"
                          dataKey="requests"
                          name="Requests"
                          stroke="#9a7cc5"
                          strokeWidth={2.3}
                          fill="url(#requestFill)"
                        />

                        <Area
                          type="monotone"
                          dataKey="threats"
                          name="Threat signals"
                          stroke="#dc83a2"
                          strokeWidth={1.7}
                          strokeDasharray="5 4"
                          fill="none"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>

                  <div className="panel-foot">
                    <span>
                      <Activity size={13} />
                      TELEMETRY PREVIEW
                    </span>
                    <span>LOCAL SAMPLE SERIES</span>
                  </div>
                </section>

                <section className="data-panel posture-panel">
                  <div className="panel-header">
                    <div>
                      <span className="eyebrow">03 / RISK REGISTER</span>
                      <h3>Priority breakdown</h3>
                      <p>Current sample finding distribution</p>
                    </div>
                  </div>

                  <div className="risk-summary">
                    <div>
                      <strong>14</strong>
                      <span>TOTAL FINDINGS</span>
                    </div>

                    <div className="risk-mark">
                      <AlertTriangle size={22} />
                    </div>
                  </div>

                  <div className="risk-row">
                    <span>
                      <i className="risk-critical" />
                      Critical
                    </span>
                    <div className="risk-track">
                      <i style={{ width: "40%" }} />
                    </div>
                    <strong>02</strong>
                  </div>

                  <div className="risk-row">
                    <span>
                      <i className="risk-high" />
                      High
                    </span>
                    <div className="risk-track">
                      <i style={{ width: "80%" }} />
                    </div>
                    <strong>04</strong>
                  </div>

                  <div className="risk-row">
                    <span>
                      <i className="risk-medium" />
                      Medium
                    </span>
                    <div className="risk-track">
                      <i style={{ width: "100%" }} />
                    </div>
                    <strong>05</strong>
                  </div>

                  <div className="risk-row">
                    <span>
                      <i className="risk-low" />
                      Low
                    </span>
                    <div className="risk-track">
                      <i style={{ width: "60%" }} />
                    </div>
                    <strong>03</strong>
                  </div>

                  <button
                    className="register-link"
                    onClick={() => setActivePage("Findings")}
                  >
                    OPEN FINDINGS REGISTER
                    <ArrowRight size={14} />
                  </button>
                </section>
              </div>

              <section className="data-panel findings-panel">
                <div className="panel-header findings-title">
                  <div>
                    <span className="eyebrow">
                      04 / SECURITY REGISTER
                    </span>
                    <h3>Recently identified issues</h3>
                  </div>

                  <button
                    className="filter-button"
                    onClick={() => setActivePage("Findings")}
                  >
                    ALL FINDINGS
                    <ArrowUpRight size={14} />
                  </button>
                </div>

                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>REFERENCE</th>
                        <th>ISSUE</th>
                        <th>AFFECTED ENDPOINT</th>
                        <th>SEVERITY</th>
                        <th>DETECTED</th>
                      </tr>
                    </thead>

                    <tbody>
                      {findings.map((item) => (
                        <tr key={item.id}>
                          <td className="reference">{item.id}</td>

                          <td>
                            <strong className="issue-title">
                              {item.title}
                            </strong>
                            <small className="issue-type">
                              {item.type}
                            </small>
                          </td>

                          <td className="endpoint">
                            {item.endpoint}
                          </td>

                          <td>
                            <span
                              className={`severity severity-${item.severity.toLowerCase()}`}
                            >
                              {item.severity}
                            </span>
                          </td>

                          <td className="age">{item.age}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              <footer className="bureau-footer">
                <span>
                  API SHIELD / SECURITY INTELLIGENCE PLATFORM
                </span>
                <span>
                  <Terminal size={12} />
                  BUILD 0.1.0 / DEVELOPMENT
                </span>
              </footer>
            </>
          )}

          {notice && (
            <div className="notice">
              <span>{notice}</span>
              <button onClick={() => setNotice("")}>
                ×
              </button>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
