const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";
const TOKEN_STORAGE_KEY = "llm_gateway_jwt";

function getStoredToken() {
  if (typeof window === "undefined") {
    return "";
  }
  return window.localStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

export function setAuthToken(token) {
  if (typeof window === "undefined") {
    return;
  }

  if (token) {
    window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
    return;
  }

  window.localStorage.removeItem(TOKEN_STORAGE_KEY);
}

export function getAuthToken() {
  return getStoredToken();
}

async function apiRequest(path, options = {}) {
  const token = getStoredToken();
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });

  if (!response.ok) {
    let detail = "Request failed.";
    try {
      const payload = await response.json();
      detail = payload.detail || detail;
    } catch (error) {
      detail = "Unexpected response from backend.";
    }
    throw new Error(detail);
  }

  return response.json();
}

export async function analyzePrompt(input) {
  return apiRequest("/analyze", {
    method: "POST",
    body: JSON.stringify({ input }),
  });
}

export async function loginUser(username, password) {
  const payload = await apiRequest("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  setAuthToken(payload.access_token);
  return payload;
}

export async function getAdminStats() {
  return apiRequest("/admin/stats", { method: "GET" });
}

export async function getAdminLogs(page = 1, pageSize = 10) {
  return apiRequest(`/admin/logs?page=${page}&page_size=${pageSize}`, { method: "GET" });
}

export async function getHighRiskLogs(page = 1, pageSize = 10) {
  return apiRequest(`/admin/high-risk?page=${page}&page_size=${pageSize}`, { method: "GET" });
}
