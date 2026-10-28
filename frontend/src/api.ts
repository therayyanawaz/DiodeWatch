import type {
  Chain, ChainVerify, Diode, EvidenceAlert, MlMetrics, Source,
} from "./types";

async function getJson<T>(url: string): Promise<T> {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${url} → HTTP ${r.status}`);
  return r.json() as Promise<T>;
}

async function post(url: string): Promise<void> {
  try {
    await fetch(url, { method: "POST" });
  } catch (e) {
    console.error(`${url} failed`, e);
  }
}

export const api = {
  get: getJson,
  sources: () => getJson<Source[]>("/api/sources"),
  evidence: (id: string) => getJson<EvidenceAlert>(`/api/evidence/${id}`),
  diode: () => getJson<Diode>("/api/diode"),
  mlMetrics: () => getJson<MlMetrics>("/api/ml_metrics"),
  chain: () => getJson<Chain>("/api/chain"),
  /* Re-hashing the whole session is deliberately not on a poll: the board asks
     for it when an operator presses RE-VERIFY, and /api/chain stays cheap. */
  chainVerify: () => getJson<ChainVerify>("/api/chain/verify"),
  health: () => getJson<{ ok: boolean }>("/api/health"),
  start: (params: { source: string; window_s: number; tick_ms: number }) =>
    fetch("/api/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(params),
    }).then((r) => r.json()),
  pause: () => post("/api/session/pause"),
  resume: () => post("/api/session/resume"),
  reset: () => post("/api/session/reset"),
};
