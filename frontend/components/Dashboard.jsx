import { useEffect, useState } from "react";

import {
  getAdminLogs,
  getAdminStats,
  getAuthToken,
  getHighRiskLogs,
  loginUser,
  setAuthToken,
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

export default function Dashboard() {
  const [stats, setStats] = useState(initialStats);
  const [logsData, setLogsData] = useState({
    items: [],
    page: 1,
    page_size: 10,
    total: 0,
    total_pages: 0,
  });
  const [highRiskData, setHighRiskData] = useState({
    items: [],
    page: 1,
    page_size: 5,
    total: 0,
    total_pages: 0,
  });
  const [activeView, setActiveView] = useState("all");
  const [loading, setLoading] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);
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

    void loadDashboard({
      logsPage: logsData.page,
      highRiskPage: highRiskData.page,
    });
  }, [token]);

  const loadDashboard = async ({
    logsPage = logsData.page,
    highRiskPage = highRiskData.page,
  } = {}) => {
    setLoading(true);
    setError("");

    try {
      const [statsPayload, logsPayload, highRiskPayload] = await Promise.all([
        getAdminStats(),
        getAdminLogs(logsPage, logsData.page_size),
        getHighRiskLogs(highRiskPage, highRiskData.page_size),
      ]);

      setStats(statsPayload);
      setLogsData(logsPayload);
      setHighRiskData(highRiskPayload);
    } catch (err) {
      setError(err.message || "Unable to load admin dashboard.");
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
    await loadDashboard();
  };

  const handleLogout = () => {
    setAuthToken("");
    setToken("");
    setStats(initialStats);
    setLogsData({ items: [], page: 1, page_size: 10, total: 0, total_pages: 0 });
    setHighRiskData({ items: [], page: 1, page_size: 5, total: 0, total_pages: 0 });
  };

  const handleLogsPageChange = async (nextPage) => {
    if (nextPage < 1 || nextPage > Math.max(logsData.total_pages, 1)) {
      return;
    }
    await loadDashboard({ logsPage: nextPage, highRiskPage: highRiskData.page });
  };

  const handleHighRiskPageChange = async (nextPage) => {
    if (nextPage < 1 || nextPage > Math.max(highRiskData.total_pages, 1)) {
      return;
    }
    await loadDashboard({ logsPage: logsData.page, highRiskPage: nextPage });
  };

  const maliciousShare = stats.total_requests
    ? `${Math.round((stats.labels.MALICIOUS / stats.total_requests) * 100)}%`
    : "0%";

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(29,41,61,0.18),_transparent_30%),radial-gradient(circle_at_top_right,_rgba(204,90,47,0.18),_transparent_28%),linear-gradient(180deg,_#f5efe6_0%,_#ede4d5_55%,_#e7dccd_100%)] px-6 py-10 text-slateink">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-8">
        <section className="grid gap-6 rounded-[32px] border border-white/60 bg-white/75 p-8 shadow-card backdrop-blur lg:grid-cols-[1.2fr_0.8fr]">
          <div className="space-y-5">
            <span className="inline-flex rounded-full bg-slateink px-4 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-sand">
              Admin Dashboard
            </span>
            <div className="space-y-3">
              <h1 className="max-w-3xl text-4xl font-semibold leading-tight md:text-5xl">
                Review gateway traffic, investigate malicious activity, and audit model safety at a glance.
              </h1>
              <p className="max-w-2xl text-base leading-7 text-slate-600">
                This dashboard connects to protected admin APIs and gives security operators visibility
                into request volume, attack distribution, average risk levels, and detailed analysis logs.
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

        <section className="grid gap-6 rounded-[32px] border border-white/60 bg-white/80 p-6 shadow-card backdrop-blur lg:grid-cols-[0.9fr_1.1fr]">
          <div className="rounded-[28px] bg-slateink p-6 text-sand">
            <p className="text-sm uppercase tracking-[0.24em] text-sand/65">Attack Distribution</p>
            <div className="mt-6 space-y-5">
              {[
                { label: "SAFE", value: stats.labels.SAFE, color: "bg-green-400" },
                { label: "SUSPICIOUS", value: stats.labels.SUSPICIOUS, color: "bg-yellow-400" },
                { label: "MALICIOUS", value: stats.labels.MALICIOUS, color: "bg-red-400" },
              ].map((item) => {
                const share = stats.total_requests
                  ? Math.max((item.value / stats.total_requests) * 100, item.value > 0 ? 6 : 0)
                  : 0;

                return (
                  <div key={item.label} className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span>{item.label}</span>
                      <span>{item.value}</span>
                    </div>
                    <div className="h-3 rounded-full bg-white/10">
                      <div
                        className={`h-3 rounded-full ${item.color}`}
                        style={{ width: `${share}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="space-y-4 rounded-[28px] bg-sand p-6">
            <p className="text-sm uppercase tracking-[0.24em] text-slate-500">Views</p>
            <div className="flex flex-wrap gap-3">
              <button
                type="button"
                onClick={() => setActiveView("all")}
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
                onClick={() => setActiveView("high-risk")}
                className={`rounded-full px-4 py-2 text-sm font-semibold transition ${
                  activeView === "high-risk"
                    ? "bg-ember text-white"
                    : "border border-slate-300 text-slate-700 hover:border-ember"
                }`}
              >
                Malicious Only
              </button>
            </div>
            <p className="text-sm leading-6 text-slate-600">
              Use the malicious-only view to triage the highest-risk prompts quickly, or switch back
              to the complete log stream for broader operational analysis.
            </p>
          </div>
        </section>

        {activeView === "all" ? (
          <LogsTable
            title="Audit Logs"
            description="Paginated event history across every analyzed prompt captured by the gateway."
            logs={logsData.items}
            page={logsData.page}
            pageSize={logsData.page_size}
            totalPages={logsData.total_pages}
            total={logsData.total}
            loading={loading}
            onPageChange={handleLogsPageChange}
          />
        ) : (
          <LogsTable
            title="High Risk Logs"
            description="Focused review of only MALICIOUS classifications for incident response and escalation."
            logs={highRiskData.items}
            page={highRiskData.page}
            pageSize={highRiskData.page_size}
            totalPages={highRiskData.total_pages}
            total={highRiskData.total}
            loading={loading}
            onPageChange={handleHighRiskPageChange}
          />
        )}
      </div>
    </main>
  );
}
