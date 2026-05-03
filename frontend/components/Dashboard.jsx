import { useEffect, useState } from "react";

import {
  getAdminAnalytics,
  getAdminLogs,
  getAdminStats,
  getAuthToken,
  loginUser,
  setAuthToken,
  updateIncidentStatus,
} from "../services/api";
import LogsTable from "./LogsTable";
import StatsCard from "./StatsCard";

const initialStats = {
  total_requests: 0,
  labels: {
    SAFE: 0,
    SUSPICIOUS: 0,
    MALICIOUS: 0,
  },
  average_risk_score: 0,
};

const initialAnalytics = {
  trends: [],
  distribution: {
    total: 0,
    distribution: {
      SAFE: { count: 0, percentage: 0 },
      SUSPICIOUS: { count: 0, percentage: 0 },
      MALICIOUS: { count: 0, percentage: 0 },
    },
  },
  attack_types: [],
  histogram: [],
};

const initialFilters = {
  search: "",
  label: "",
  incident_status: "",
  attack_type: "",
  min_risk: "",
  max_risk: "",
};

function TinyBarChart({ title, items, colorClass = "bg-ember" }) {
  const maxValue = Math.max(...items.map((item) => item.count || item.total || 0), 1);

  return (
    <div className="rounded-[28px] border border-slate-200 bg-white p-5">
      <p className="text-sm uppercase tracking-[0.24em] text-slate-500">{title}</p>
      <div className="mt-5 space-y-4">
        {items.map((item) => {
          const label = item.label || item.type || item.range || item.date;
          const value = item.count ?? item.total ?? 0;
          const width = `${Math.max((value / maxValue) * 100, value > 0 ? 8 : 0)}%`;

          return (
            <div key={label} className="space-y-2">
              <div className="flex items-center justify-between text-sm text-slate-600">
                <span className="truncate">{label}</span>
                <span>{value}</span>
              </div>
              <div className="h-3 rounded-full bg-slate-100">
                <div className={`h-3 rounded-full ${colorClass}`} style={{ width }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState(initialStats);
  const [analytics, setAnalytics] = useState(initialAnalytics);
  const [logsData, setLogsData] = useState({
    items: [],
    page: 1,
    page_size: 10,
    total: 0,
    total_pages: 0,
  });
  const [activeView, setActiveView] = useState("all");
  const [filters, setFilters] = useState(initialFilters);
  const [draftFilters, setDraftFilters] = useState(initialFilters);
  const [loading, setLoading] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);
  const [savingIncidentId, setSavingIncidentId] = useState(null);
  const [error, setError] = useState("");
  const [token, setToken] = useState("");
  const [credentials, setCredentials] = useState({
    username: "",
    password: "",
  });

  useEffect(() => {
    const storedToken = getAuthToken();
    if (storedToken) {
      setToken(storedToken);
    }
  }, []);

  useEffect(() => {
    if (!token) {
      return;
    }

    void loadDashboard({ page: 1, activeTab: activeView, nextFilters: filters });
  }, [token]);

  const buildLogFilters = (activeTab, nextFilters) => {
    const applied = { ...nextFilters };
    if (activeTab === "high-risk") {
      applied.label = "MALICIOUS";
    }
    return applied;
  };

  const loadDashboard = async ({
    page = logsData.page,
    activeTab = activeView,
    nextFilters = filters,
  } = {}) => {
    setLoading(true);
    setError("");

    try {
      const logFilters = buildLogFilters(activeTab, nextFilters);
      const [statsPayload, analyticsPayload, logsPayload] = await Promise.all([
        getAdminStats(),
        getAdminAnalytics(),
        getAdminLogs(page, logsData.page_size, logFilters),
      ]);

      setStats(statsPayload);
      setAnalytics(analyticsPayload);
      setLogsData(logsPayload);
    } catch (err) {
      setError(err.message || "Unable to load SOC dashboard.");
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (event) => {
    event.preventDefault();
    setAuthLoading(true);
    setError("");

    try {
      const payload = await loginUser(credentials.username, credentials.password);
      setToken(payload.access_token);
    } catch (err) {
      setError(err.message || "Login failed.");
    } finally {
      setAuthLoading(false);
    }
  };

  const handleTokenSave = async () => {
    setAuthToken(token);
    await loadDashboard({ page: 1 });
  };

  const handleLogout = () => {
    setAuthToken("");
    setToken("");
    setStats(initialStats);
    setAnalytics(initialAnalytics);
    setLogsData({ items: [], page: 1, page_size: 10, total: 0, total_pages: 0 });
  };

  const handlePageChange = async (nextPage) => {
    if (nextPage < 1 || nextPage > Math.max(logsData.total_pages, 1)) {
      return;
    }
    await loadDashboard({ page: nextPage });
  };

  const applyFilters = async () => {
    setFilters(draftFilters);
    await loadDashboard({ page: 1, nextFilters: draftFilters });
  };

  const resetFilters = async () => {
    setDraftFilters(initialFilters);
    setFilters(initialFilters);
    await loadDashboard({ page: 1, nextFilters: initialFilters });
  };

  const handleIncidentSave = async (logId, incidentStatus, incidentNotes) => {
    setSavingIncidentId(logId);
    setError("");

    try {
      await updateIncidentStatus(logId, incidentStatus, incidentNotes);
      await loadDashboard();
    } catch (err) {
      setError(err.message || "Unable to update incident status.");
    } finally {
      setSavingIncidentId(null);
    }
  };

  const switchView = async (nextView) => {
    setActiveView(nextView);
    await loadDashboard({ page: 1, activeTab: nextView });
  };

  const maliciousShare = stats.total_requests
    ? `${Math.round((stats.labels.MALICIOUS / stats.total_requests) * 100)}%`
    : "0%";

  const trendItems = analytics.trends.map((trend) => ({
    label: trend.date,
    total: trend.total,
  }));

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(29,41,61,0.18),_transparent_30%),radial-gradient(circle_at_top_right,_rgba(204,90,47,0.18),_transparent_28%),linear-gradient(180deg,_#f5efe6_0%,_#ede4d5_55%,_#e7dccd_100%)] px-6 py-10 text-slateink">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-8">
        <section className="grid gap-6 rounded-[32px] border border-white/60 bg-white/75 p-8 shadow-card backdrop-blur lg:grid-cols-[1.15fr_0.85fr]">
          <div className="space-y-5">
            <span className="inline-flex rounded-full bg-slateink px-4 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-sand">
              SOC Dashboard
            </span>
            <div className="space-y-3">
              <h1 className="max-w-3xl text-4xl font-semibold leading-tight md:text-5xl">
                Monitor attack traffic, triage incidents, and track LLM abuse patterns like a real security operations console.
              </h1>
              <p className="max-w-2xl text-base leading-7 text-slate-600">
                This console combines JWT-secured admin access, attack analytics, log filtering, and incident review workflow into one operational surface.
              </p>
            </div>
          </div>

          <div className="rounded-[28px] bg-slateink p-6 text-sand">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-sm uppercase tracking-[0.24em] text-sand/70">Authentication</p>
                <h2 className="mt-2 text-2xl font-semibold">JWT Access</h2>
              </div>
              {token ? (
                <button
                  type="button"
                  onClick={handleLogout}
                  className="rounded-full border border-white/20 px-4 py-2 text-sm font-semibold text-sand transition hover:bg-white/10"
                >
                  Clear Token
                </button>
              ) : null}
            </div>

            <form className="mt-6 space-y-4" onSubmit={handleLogin}>
              <input
                type="text"
                placeholder="Admin username"
                value={credentials.username}
                onChange={(event) =>
                  setCredentials((current) => ({ ...current, username: event.target.value }))
                }
                className="w-full rounded-2xl border border-white/10 bg-white/10 px-4 py-3 text-sm text-sand outline-none placeholder:text-sand/45 focus:border-white/30"
              />
              <input
                type="password"
                placeholder="Password"
                value={credentials.password}
                onChange={(event) =>
                  setCredentials((current) => ({ ...current, password: event.target.value }))
                }
                className="w-full rounded-2xl border border-white/10 bg-white/10 px-4 py-3 text-sm text-sand outline-none placeholder:text-sand/45 focus:border-white/30"
              />
              <button
                type="submit"
                disabled={authLoading}
                className="w-full rounded-full bg-ember px-4 py-3 text-sm font-semibold text-white transition hover:bg-[#b84f28] disabled:cursor-not-allowed disabled:opacity-60"
              >
                {authLoading ? "Signing In..." : "Login and Store JWT"}
              </button>
            </form>

            <div className="mt-5">
              <label className="mb-2 block text-sm font-medium text-sand/80" htmlFor="jwt-token">
                Or paste an existing JWT token
              </label>
              <textarea
                id="jwt-token"
                className="min-h-28 w-full rounded-2xl border border-white/10 bg-white/10 px-4 py-3 text-sm text-sand outline-none placeholder:text-sand/45 focus:border-white/30"
                placeholder="Paste bearer token here..."
                value={token}
                onChange={(event) => setToken(event.target.value)}
              />
              <button
                type="button"
                onClick={handleTokenSave}
                disabled={!token.trim() || loading}
                className="mt-4 w-full rounded-full border border-white/15 px-4 py-3 text-sm font-semibold text-sand transition hover:bg-white/10 disabled:cursor-not-allowed disabled:opacity-60"
              >
                Save Token and Load Dashboard
              </button>
            </div>
          </div>
        </section>

        {error ? (
          <p className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </p>
        ) : null}

        <section className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
          <StatsCard
            title="Total Requests"
            value={stats.total_requests}
            accent="slate"
            description="All analyzed prompts observed by the gateway."
          />
          <StatsCard
            title="Safe Requests"
            value={stats.labels.SAFE}
            accent="sage"
            description="Traffic that cleared detection without escalation."
          />
          <StatsCard
            title="Malicious Share"
            value={maliciousShare}
            accent="crimson"
            description={`${stats.labels.MALICIOUS} requests were classified as malicious.`}
          />
          <StatsCard
            title="Average Risk"
            value={stats.average_risk_score}
            accent="ember"
            description="Mean risk score across the full request history."
          />
        </section>

        <section className="grid gap-6 rounded-[32px] border border-white/60 bg-white/80 p-6 shadow-card backdrop-blur xl:grid-cols-[0.85fr_1.15fr]">
          <div className="rounded-[28px] bg-slateink p-6 text-sand">
            <p className="text-sm uppercase tracking-[0.24em] text-sand/65">Attack Distribution</p>
            <div className="mt-6 space-y-5">
              {[
                { label: "SAFE", value: stats.labels.SAFE, color: "bg-green-400" },
                { label: "SUSPICIOUS", value: stats.labels.SUSPICIOUS, color: "bg-yellow-400" },
                { label: "MALICIOUS", value: stats.labels.MALICIOUS, color: "bg-red-400" },
              ].map((item) => {
                const share = analytics.distribution.total
                  ? Math.max((item.value / analytics.distribution.total) * 100, item.value > 0 ? 6 : 0)
                  : 0;

                return (
                  <div key={item.label} className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span>{item.label}</span>
                      <span>{item.value}</span>
                    </div>
                    <div className="h-3 rounded-full bg-white/10">
                      <div className={`h-3 rounded-full ${item.color}`} style={{ width: `${share}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="rounded-[28px] bg-sand p-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-sm uppercase tracking-[0.24em] text-slate-500">Investigation Views</p>
                <h2 className="mt-2 text-2xl font-semibold text-slateink">Threat Hunting Controls</h2>
              </div>
              <button
                type="button"
                onClick={() => loadDashboard({ page: 1 })}
                disabled={loading}
                className="rounded-full bg-slateink px-4 py-2 text-sm font-semibold text-sand transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {loading ? "Refreshing..." : "Refresh"}
              </button>
            </div>

            <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              <input
                type="text"
                placeholder="Search prompt or reason"
                value={draftFilters.search}
                onChange={(event) =>
                  setDraftFilters((current) => ({ ...current, search: event.target.value }))
                }
                className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700 outline-none focus:border-slateink"
              />
              <select
                value={draftFilters.label}
                onChange={(event) =>
                  setDraftFilters((current) => ({ ...current, label: event.target.value }))
                }
                className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700 outline-none focus:border-slateink"
              >
                <option value="">All labels</option>
                <option value="SAFE">SAFE</option>
                <option value="SUSPICIOUS">SUSPICIOUS</option>
                <option value="MALICIOUS">MALICIOUS</option>
              </select>
              <select
                value={draftFilters.incident_status}
                onChange={(event) =>
                  setDraftFilters((current) => ({ ...current, incident_status: event.target.value }))
                }
                className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700 outline-none focus:border-slateink"
              >
                <option value="">All incidents</option>
                <option value="NEW">NEW</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="ESCALATED">ESCALATED</option>
                <option value="RESOLVED">RESOLVED</option>
                <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
              </select>
              <select
                value={draftFilters.attack_type}
                onChange={(event) =>
                  setDraftFilters((current) => ({ ...current, attack_type: event.target.value }))
                }
                className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700 outline-none focus:border-slateink"
              >
                <option value="">All attack types</option>
                <option value="prompt_injection">prompt_injection</option>
                <option value="jailbreak">jailbreak</option>
                <option value="data_leak">data_leak</option>
                <option value="unknown">unknown</option>
              </select>
              <input
                type="number"
                min="0"
                max="100"
                placeholder="Min risk"
                value={draftFilters.min_risk}
                onChange={(event) =>
                  setDraftFilters((current) => ({ ...current, min_risk: event.target.value }))
                }
                className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700 outline-none focus:border-slateink"
              />
              <input
                type="number"
                min="0"
                max="100"
                placeholder="Max risk"
                value={draftFilters.max_risk}
                onChange={(event) =>
                  setDraftFilters((current) => ({ ...current, max_risk: event.target.value }))
                }
                className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700 outline-none focus:border-slateink"
              />
            </div>

            <div className="mt-5 flex flex-wrap gap-3">
              <button
                type="button"
                onClick={() => switchView("all")}
                className={`rounded-full px-4 py-2 text-sm font-semibold transition ${
                  activeView === "all"
                    ? "bg-slateink text-sand"
                    : "border border-slate-300 text-slate-700 hover:border-slateink"
                }`}
              >
                All Logs
              </button>
              <button
                type="button"
                onClick={() => switchView("high-risk")}
                className={`rounded-full px-4 py-2 text-sm font-semibold transition ${
                  activeView === "high-risk"
                    ? "bg-ember text-white"
                    : "border border-slate-300 text-slate-700 hover:border-ember"
                }`}
              >
                Malicious Only
              </button>
              <button
                type="button"
                onClick={applyFilters}
                className="rounded-full bg-ember px-4 py-2 text-sm font-semibold text-white transition hover:bg-[#b84f28]"
              >
                Apply Filters
              </button>
              <button
                type="button"
                onClick={resetFilters}
                className="rounded-full border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 transition hover:border-slateink"
              >
                Reset
              </button>
            </div>
          </div>
        </section>

        <section className="grid gap-6 xl:grid-cols-2">
          <TinyBarChart title="Request Volume by Day" items={trendItems} colorClass="bg-ember" />
          <TinyBarChart title="Top Attack Types" items={analytics.attack_types} colorClass="bg-slateink" />
          <TinyBarChart title="Risk Histogram" items={analytics.histogram} colorClass="bg-yellow-400" />
          <TinyBarChart
            title="Label Distribution"
            items={Object.entries(analytics.distribution.distribution).map(([label, value]) => ({
              label,
              count: value.count,
            }))}
            colorClass="bg-green-400"
          />
        </section>

        <LogsTable
          title={activeView === "all" ? "Audit Logs" : "High Risk Logs"}
          description={
            activeView === "all"
              ? "Paginated event history across every analyzed prompt captured by the gateway."
              : "Filtered review of only MALICIOUS prompts for rapid escalation and incident response."
          }
          logs={logsData.items}
          page={logsData.page}
          pageSize={logsData.page_size}
          totalPages={logsData.total_pages}
          total={logsData.total}
          loading={loading}
          savingIncidentId={savingIncidentId}
          onPageChange={handlePageChange}
          onIncidentSave={handleIncidentSave}
        />
      </div>
    </main>
  );
}
