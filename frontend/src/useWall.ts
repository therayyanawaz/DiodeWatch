import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import type {
  Alert, ClassStat, Custody, LiveMessage, Metrics, Params, Snapshot,
} from "./types";

type Wall = {
  connected: boolean;
  sessionState: string;
  error: string | null;
  progress: number | null;
  metrics: Metrics;
  alerts: Alert[];
  classStats: Record<string, ClassStat>;
  /* capture-second -> alert count, owned by the server and replaced wholesale
     on every push, so the timeline cannot drift into a partial history. */
  timeline: Record<string, number>;
  classNames: Record<string, string>;
  threatLevels: Record<string, string>;
  custody: Custody | null;
  params: Params;
};

const INITIAL: Wall = {
  connected: false,
  sessionState: "idle",
  error: null,
  progress: null,
  metrics: {},
  alerts: [],
  classStats: {},
  timeline: {},
  classNames: {},
  threatLevels: {},
  custody: null,
  params: { source: "demo", window_s: 10, tick_ms: 1000 },
};

/* The store hands alerts oldest-first; the feed shows newest-first. */
const newestFirst = (list: Alert[]) => [...list].reverse();

function mergeFresh(prev: Alert[], incoming: Alert[]): Alert[] {
  if (!incoming.length) return prev;
  const seen = new Set(prev.map((a) => a.alert_id));
  const fresh = newestFirst(incoming).filter((a) => !seen.has(a.alert_id));
  return fresh.length ? [...fresh, ...prev] : prev;
}

export function useWall() {
  const [wall, setWall] = useState<Wall>(INITIAL);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer = 0;
    let gone = false;

    const fromSnapshot = (d: Snapshot): Wall => ({
      ...INITIAL,
      connected: true,
      sessionState: d.state || "idle",
      error: d.error ?? null,
      progress: d.progress ?? null,
      metrics: d.metrics || {},
      alerts: newestFirst(d.alerts || []),
      classStats: d.class_stats || {},
      timeline: d.timeline || {},
      classNames: d.class_names || {},
      threatLevels: d.threat_levels || {},
      custody: d.evidence ?? null,
      params: { ...INITIAL.params, ...d.params },
    });

    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws/live`);
      ws.onopen = () => setWall((w) => ({ ...w, connected: true }));
      ws.onclose = () => {
        setWall((w) => ({ ...w, connected: false }));
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
        if (m.type === "snapshot") {
          setWall(fromSnapshot(m.data));
        } else if (m.type === "windows") {
          setWall((w) => ({
            ...w,
            sessionState: m.state || w.sessionState,
            progress: m.progress ?? w.progress,
            metrics: m.metrics || w.metrics,
            alerts: mergeFresh(w.alerts, m.new_alerts || []),
            classStats: m.class_stats || w.classStats,
            timeline: m.timeline || w.timeline,
            custody: m.evidence ?? w.custody,
          }));
        } else if (m.type === "state") {
          setWall((w) => {
            if (m.state !== "idle" && m.state !== "loading") {
              return { ...w, sessionState: m.state };
            }
            /* A fresh session wipes the wall: leftover cards would otherwise
               read as evidence from a capture that never ran. The naming
               tables and the chosen window survive, because only the snapshot
               carries the words and the per-window pushes never re-send them. */
            return {
              ...INITIAL,
              connected: w.connected,
              classNames: w.classNames,
              threatLevels: w.threatLevels,
              params: w.params,
            };
          });
        } else if (m.type === "error") {
          setWall((w) => ({ ...w, error: m.message || "server error" }));
        }
      };
    };

    connect();
    return () => {
      gone = true;
      window.clearTimeout(timer);
      ws?.close();
    };
  }, []);

  const launch = useCallback(async (p: Params) => {
    try {
      await api.start(p);
    } catch (e) {
      setWall((w) => ({ ...w, error: String(e) }));
    }
  }, []);

  const togglePause = useCallback((paused: boolean) => {
    void (paused ? api.resume() : api.pause());
  }, []);

  const reset = useCallback(() => {
    void api.reset();
  }, []);

  const classLabel = useMemo(() => {
    const names = wall.classNames;
    // src/alerts/schema.py CLASS_NAMES owns the words; this is display_class()'s
    // own fallback for a class nobody named, not a fourth spelling of it.
    return (tc: string | null | undefined) =>
      names[tc || ""] || (tc || "").toUpperCase().replace(/_/g, " ");
  }, [wall.classNames]);

  const levelWord = useMemo(() => {
    const levels = wall.threatLevels;
    return (sev: string | null | undefined) =>
      levels[sev || ""] || (sev || "CALM").toUpperCase();
  }, [wall.threatLevels]);

  return { wall, launch, togglePause, reset, classLabel, levelWord };
}
