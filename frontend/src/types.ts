/* Wire types for server.py's payloads. Field-for-field, so a rename on the
   server fails `npm run typecheck` instead of printing `undefined`. */

export type Metrics = {
  replay_fps?: number;
  alerts_per_sec?: number;
  sustained_fps?: number;
  p50_eval_ms?: number;
  p95_eval_ms?: number;
  p95_per_flow_ms?: number;
  windows?: number;
  flows?: number;
  alerts?: number;
  alerts_raw?: number;
  alerts_suppressed?: number;
  entities?: number;
  max_severity?: string | null;
};

export type EvidenceItem = {
  condition: string;
  operator: string;
  observed: string | number | null;
  threshold: string | number | null;
  description: string | null;
  unit: string | null;
};

export type Alert = {
  alert_id: string;
  timestamp: string;
  flow_id: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  proto: string | null;
  threat_class: string;
  severity: string | null;
  confidence: number;
  evidence: EvidenceItem[];
  window_start: string | null;
  window_end: string | null;
  window_seconds: number | null;
  key: string | null;
  detector: string | null;
  attack_technique: string | null;
  attack_tactic: string | null;
  "att&ck_techniques": string[];
  label: string | null;
  triage: Record<string, unknown> | null;
};

export type EvidenceAlert = Alert & { triage_line: string | null };

export type ClassStat = {
  count: number;
  severity: string | null;
  attack: string | null;
};

/* What the evidence store hands the wall: the two ways a feed row can fail to
   be a chain link, both named rather than hidden. */
export type Custody = {
  persisted: boolean;
  rejected: number;
  error: string | null;
};

export type Params = { source: string; window_s: number; tick_ms: number };

export type Snapshot = {
  state: string;
  error: string | null;
  params: Params;
  source: { label: string; story: string };
  progress: number | null;
  metrics: Metrics;
  alerts: Alert[];
  timeline: Record<string, number>;
  class_stats: Record<string, ClassStat>;
  class_names: Record<string, string>;
  threat_levels: Record<string, string>;
  evidence: Custody | null;
  ml_available: boolean;
  ml_total: number;
};

export type WindowPush = {
  type: "windows";
  state: string;
  metrics: Metrics;
  progress: number | null;
  new_alerts: Alert[];
  timeline: Record<string, number>;
  class_stats: Record<string, ClassStat>;
  evidence: Custody | null;
};
export type LiveMessage =
  | { type: "snapshot"; data: Snapshot }
  | WindowPush
  | { type: "state"; state: string; message?: string }
  | { type: "error"; message: string };

/* /api/diode: the file's own fields are allegations the attesting host wrote;
   `proof` is the server's verdict over them and the only thing a client may
   turn into a claim on screen. */
export type DiodeProof = {
  proof?: string;
  verdict?: string;
  reasons?: string[];
  scope?: string;
  [k: string]: unknown;
};

export type Diode = {
  available: boolean;
  path?: string;
  proof?: DiodeProof;
  monitor_available?: boolean;
  mode?: string;
  backend?: string;
  backend_reason?: string;
  protected_uid?: number;
  protected_user?: string;
  last_error?: string | null;
  enforcement_verified?: boolean;
  dropped_packets?: number | null;
  outbound_connections?: number;
  outbound_bytes?: number;
  bytes_accounting?: string;
  compliant?: boolean;
  violations_total?: number;
  seq?: number;
  timestamp?: string;
};

export type Source = {
  key: string;
  label: string;
  story: string;
  kind: string;
  note?: string;
};

/* /api/ml_metrics: the committed held-out artifacts, channel-keyed by
   load_ml_metrics() and present only where a pin exists, so every field is
   optional and a missing channel is a state the board renders, not an error. */
export type PerClassRow = {
  precision?: number | null;
  recall?: number | null;
  f1?: number | null;
  support?: number | null;
  /* null = the tuning slice never reached the precision gate, so this class is
     rank-only and can never alert. Its 0.000 hold-out row would read as a
     measured failure, which is the wrong claim. */
  threshold?: number | null;
};

export type MlMetrics = {
  window?: {
    per_class?: Record<string, PerClassRow>;
    benign_false_positives_per_day?: Record<string, number>;
  };
  supervised?: { per_class?: Record<string, PerClassRow> };
  beacon?: {
    roc_auc_macro?: number | null;
    precision?: number | null;
    recall?: number | null;
    threshold?: number | null;
    positives?: number | null;
  };
  dga?: {
    f1?: number | null;
    precision?: number | null;
    recall?: number | null;
    families?: number | string | null;
    umbrella_fpr_at_threshold?: number | null;
  };
  tls?: {
    watchlist_size?: number | null;
    novelty_available?: boolean;
    baseline_flag_rate_on_real_eval?: number | null;
    synthetic_plant_eval?: {
      precision?: number | null;
      recall?: number | null;
      f1?: number | null;
      tp?: number;
      fn?: number;
      watchlist_only?: { tp?: number };
      novelty_only?: { tp?: number };
    };
  };
  [k: string]: unknown;
};

/* /api/chain describes what the session appended; /api/chain/verify is the
   only thing that re-hashes it. Kept as two types because the board must not
   turn the first into the second's claim. */
export type Chain = {
  available: boolean;
  degraded: boolean;
  error: string | null;
  db?: string;
  links: number;
  head: { chain_hash?: string } | null;
  rejected: number;
  anchored?: boolean;
  ledger_error?: string | null;
};

export type ChainVerify = {
  ok?: boolean;
  links?: number;
  alerts?: number;
  anchored?: boolean;
  error?: string | null;
  db?: string;
  degraded?: boolean;
  /* Set client-side when the request itself never answered, so the row can say
     "re-verify failed" instead of borrowing the previous verdict. */
  failed?: boolean;
};
