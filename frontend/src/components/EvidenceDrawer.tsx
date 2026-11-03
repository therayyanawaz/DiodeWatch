import { useEffect, useState } from "react";
import { api } from "../api";
import type { EvidenceAlert } from "../types";
import Help from "./Help";

type Props = {
  alertId: string | null;
  classLabel: (tc: string | null | undefined) => string;
  onClose: () => void;
};

/* Window-aggregate alerts (flow_id "entity/*") span many flows, so no single
   port or proto exists: the panel names the entity and says so rather than
   printing a fake "?:? → ?:? (?)". Per-flow ML alerts keep the 5-tuple. */
function subject(a: EvidenceAlert) {
  const agg = (a.flow_id || "").endsWith("/*");
  const entity = a.src_ip || a.dst_ip || a.key || "?";
  if (agg) {
    return {
      title: "ENTITY — WINDOW AGGREGATE",
      text: `${entity} — window aggregate (one entity, many flows; no single port)`,
    };
  }
  if (a.src_ip || a.dst_ip) {
    return {
      title: "FLOW 5-TUPLE",
      text: `${a.src_ip || "?"}:${a.src_port ?? "?"} → ${a.dst_ip || "?"}:`
        + `${a.dst_port ?? "?"} (${a.proto || "?"})`,
    };
  }
  return {
    title: "ENTITY — DETECTOR KEY",
    text: `${entity} — pair this detector keyed on (no per-flow tuple recorded)`,
  };
}

export default function EvidenceDrawer({ alertId, classLabel, onClose }: Props) {
  const [body, setBody] = useState<EvidenceAlert | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!alertId) return;
    setBody(null);
    setError(null);
    api.evidence(alertId).then(setBody).catch((e) => setError(String(e)));
  }, [alertId]);

  useEffect(() => {
    const key = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, [onClose]);

  const open = alertId !== null;
  const s = body && subject(body);

  return (
    <>
      <div
        className={`drawer-overlay${open ? " open" : ""}`}
        aria-hidden="true"
        onClick={onClose}
      />
      <aside
        className={`drawer${open ? " open" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label="Alert evidence"
      >
        <div className="drawer-head">
          <div>
            <div className="drawer-kicker">
              EVIDENCE{body ? ` · ${body.detector || "detector"}` : ""}{" "}
              <Help about="Evidence">Observed-vs-threshold proof for the selected
                alert, with ATT&CK tags and one-click STIX and report
                export.</Help>
            </div>
            <h3>{body ? classLabel(body.threat_class) : "—"}</h3>
          </div>
          <button className="iconbtn" onClick={onClose} aria-label="Close evidence drawer">
            <svg aria-hidden="true"><use href="#i-x" /></svg>
          </button>
        </div>
        <div className="drawer-body">
          {!alertId && <p className="muted">select an alert…</p>}
          {alertId && !body && !error && <p className="muted">loading…</p>}
          {error && <p className="muted">Evidence unavailable: {error}</p>}
          {body && s && (
            <>
              <div className="ev-block ev-tags">
                <span className="ev-tag ev-tag--red">
                  {(body.severity || "medium").toUpperCase()}
                </span>
                <span className="ev-tag ev-tag--cyan">
                  CONF {Math.round((body.confidence || 0) * 100)}%
                </span>
                {body.attack_technique && <span className="ev-tag">{body.attack_technique}</span>}
                {body.attack_tactic && (
                  <span className="ev-tag ev-tag--green">{body.attack_tactic}</span>
                )}
                {body.window_seconds && (
                  <span className="ev-tag ev-tag--cyan">{body.window_seconds}s WINDOW</span>
                )}
              </div>

              <div className="ev-block">
                <p className="ev-block-title">{s.title}</p>
                <div className="ev-tuple">
                  {s.text}
                  <br />
                  <span className="muted">
                    entity {body.key || "—"} · flow {body.flow_id || "—"}
                  </span>
                  <br />
                  <span className="muted">
                    {body.timestamp}
                    {body.window_start && ` · window ${body.window_start} → ${body.window_end || "—"}`}
                  </span>
                </div>
              </div>

              <div className="ev-block">
                <p className="ev-block-title">EVIDENCE — OBSERVED VS THRESHOLD</p>
                <table className="ev-table">
                  <thead>
                    <tr>
                      <th>CONDITION</th><th>OBSERVED</th><th></th><th>THRESHOLD</th><th>NOTES</th>
                    </tr>
                  </thead>
                  <tbody>
                    {body.evidence.length === 0 && (
                      <tr><td colSpan={5} className="muted">no evidence items</td></tr>
                    )}
                    {body.evidence.map((e, i) => (
                      <tr key={i}>
                        <td>{e.condition}</td>
                        <td className="ev-obs">{String(e.observed ?? "—")}</td>
                        <td className="ev-op">{e.operator}</td>
                        <td>
                          {String(e.threshold ?? "—")}
                          {e.unit && <span className="ev-desc"> {e.unit}</span>}
                        </td>
                        <td className="ev-desc">{e.description || ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {body.triage_line && (
                <div className="ev-block">
                  <p className="ev-block-title">
                    TRIAGE — ADVISORY (NEVER MUTATES THE DETECTION)
                  </p>
                  <div className="ev-tuple">{body.triage_line}</div>
                </div>
              )}

              <div className="ev-block">
                <p className="ev-block-title">SOC EXPORT</p>
                <div className="ev-actions">
                  <a className="btn-dark" href={`/report/${body.alert_id}`}
                     target="_blank" rel="noopener">INCIDENT REPORT</a>
                  <a className="btn-outline" href={`/api/export/stix/${body.alert_id}`}
                     target="_blank" rel="noopener">STIX 2.1 BUNDLE</a>
                </div>
              </div>
            </>
          )}
        </div>
      </aside>
    </>
  );
}
