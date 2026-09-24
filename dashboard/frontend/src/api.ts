export type Entry = {
  site_name: string;
  username_hint: string;
  updated_at: string;
  login_url: string;
};

export type ApiKeyRow = {
  name: string;
  service_hint: string;
  updated_at: string;
};

export type Bootstrap = {
  username: string;
  csrf_token: string;
  entries: Entry[] | null;
  api_keys: ApiKeyRow[] | null;
  entries_error: string | null;
  api_keys_error: string | null;
};

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

let csrf = "";

export function setCsrf(token: string) {
  csrf = token;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body) headers.set("Content-Type", "application/json");
  if (init.method && init.method !== "GET") headers.set("X-CSRF-Token", csrf);
  const response = await fetch(path, { ...init, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof data.error === "string" ? data.error : "Request failed";
    throw new ApiError(response.status, message);
  }
  return data as T;
}

export async function loadBootstrap(refresh = false): Promise<Bootstrap> {
  const path = refresh ? "/api/bootstrap?refresh=1" : "/api/bootstrap";
  const body = await request<Bootstrap>(path);
  setCsrf(body.csrf_token);
  return body;
}

export function addEntry(payload: Record<string, string>) {
  return request<Entry>("/api/entries", { method: "POST", body: JSON.stringify(payload) });
}

export function updateEntry(site: string, payload: Record<string, string>) {
  return request<Entry>(`/api/entries/${encodeURIComponent(site)}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function deleteEntry(site: string) {
  return request<{ ok: boolean }>(`/api/entries/${encodeURIComponent(site)}`, { method: "DELETE" });
}

export function getEntry(site: string) {
  return request<{ site_name: string; username: string; login_url: string; notes: string }>(
    `/api/entries/${encodeURIComponent(site)}`,
  );
}

export function revealEntry(site: string, field: "password" | "notes") {
  return request<Record<string, string>>(`/api/entries/${encodeURIComponent(site)}/reveal`, {
    method: "POST",
    body: JSON.stringify({ fields: [field] }),
  });
}

export function addApiKey(payload: Record<string, string>) {
  return request<ApiKeyRow>("/api/api-keys", { method: "POST", body: JSON.stringify(payload) });
}

export function updateApiKey(name: string, payload: Record<string, string>) {
  return request<ApiKeyRow>(`/api/api-keys/${encodeURIComponent(name)}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function deleteApiKey(name: string) {
  return request<{ ok: boolean }>(`/api/api-keys/${encodeURIComponent(name)}`, { method: "DELETE" });
}

export function getApiKey(name: string) {
  return request<{ name: string; service: string; notes: string }>(`/api/api-keys/${encodeURIComponent(name)}`);
}

export function revealApiKey(name: string, field: "api_key" | "notes") {
  return request<Record<string, string>>(`/api/api-keys/${encodeURIComponent(name)}/reveal`, {
    method: "POST",
    body: JSON.stringify({ fields: [field] }),
  });
}

export function logout() {
  return request<{ ok: boolean }>("/api/logout", { method: "POST", body: JSON.stringify({}) });
}
