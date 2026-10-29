import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import type {
  Chain, ChainVerify, Diode, LiveMessage, MlMetrics, Snapshot, Source,
} from "./types";

/* Everything the board prints is polled or pushed: five endpoints on one 5 s
   cadence, the same websocket the wall streams over, plus the one call a poll
   cannot make — /api/chain/verify, which re-hashes the whole session on
   demand. */
const REFRESH_MS = 5000;

export type StatusState = {
  connected: boolean;
  snap: Snapshot | null;
  diode: Diode | null;
  chain: Chain | null;
  ml: MlMetrics | null;
  sources: Source[] | null;
  verify: ChainVerify | null;
  verifying: boolean;
  apiOk: boolean;
  updated: Date | null;
};

const INITIAL: StatusState = {
  connected: false, snap: null, diode: null, chain: null, ml: null,
  sources: null, verify: null, verifying: false, apiOk: false, updated: null,
};

export function useStatus() {
  const [st, setSt] = useState<StatusState>(INITIAL);
  const refreshing = useRef(false);

  const patch = useCallback((p: Partial<StatusState>) => {
    setSt((prev) => ({ ...prev, ...p, updated: new Date() }));
  }, []);

  const verify = useCallback(() => {
    patch({ verifying: true });
    api.chainVerify()
      .then((v) => patch({ verify: v, verifying: false }))
      // A re-verify that never answered is a state the row has to name; it is
      // not evidence that the chain broke.
      .catch(() => patch({ verify: { failed: true }, verifying: false }));
  }, [patch]);

  const refresh = useCallback(() => {
    if (refreshing.current) return;
    refreshing.current = true;
    const pull = <T,>(url: string, key: keyof StatusState) =>
      api.get<T>(url)
        .then((v) => patch({ [key]: v } as Partial<StatusState>))
        // a failed poll is state, not an exception: the row reads OFFLINE
        .catch(() => patch({ [key]: null } as Partial<StatusState>));
    void Promise.allSettled([
      api.get<{ ok: boolean }>("/api/health")
        .then((h) => patch({ apiOk: h.ok === true }))
        .catch(() => patch({ apiOk: false })),
      pull<Diode>("/api/diode", "diode"),
      pull<Chain>("/api/chain", "chain"),
      pull<MlMetrics>("/api/ml_metrics", "ml"),
      pull<Source[]>("/api/sources", "sources"),
    ]).then(() => { refreshing.current = false; });
  }, [patch]);

  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, REFRESH_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  /* The session rows read the live wall over the same socket the dashboard
     uses, so the board cannot report a session the wall is not running. */
  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer = 0;
    let gone = false;

    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws/live`);
      ws.onopen = () => setSt((p) => ({ ...p, connected: true }));
      ws.onclose = () => {
        setSt((p) => ({ ...p, connected: false }));
        if (!gone) timer = window.setTimeout(connect, 1200);
      };
      ws.onerror = () => ws?.close();
      ws.onmessage = (ev) => {
        let m: LiveMessage;
        try {
          m = JSON.parse(ev.data) as LiveMessage;
        } catch {
          return;
        }
        setSt((p) => {
          if (m.type === "snapshot") return { ...p, snap: m.data, updated: new Date() };
          if (!p.snap) return p;
          if (m.type === "windows") {
            return {
              ...p,
              snap: { ...p.snap, state: m.state, metrics: m.metrics, progress: m.progress },
              updated: new Date(),
            };
          }
          if (m.type === "state") {
            return { ...p, snap: { ...p.snap, state: m.state }, updated: new Date() };
          }
          return p;
        });
      };
    };

    connect();
    return () => {
      gone = true;
      window.clearTimeout(timer);
      ws?.close();
    };
  }, []);

  return { st, refresh, verify };
}
