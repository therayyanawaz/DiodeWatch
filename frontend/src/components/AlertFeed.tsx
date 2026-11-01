import { useMemo, useState } from "react";
import { fmt, fmtTime } from "../format";
import type { Alert, ClassStat, Custody } from "../types";
import Help from "./Help";

/* Cards on screen. The wire carries the last FEED_CAP (400) alerts and the
   session holds thousands, so the feed keeps the newest head of a newest-first
   array and lets the oldest fall off the tail. */
const DOM_CAP = 80;

const SEVERITIES = ["all", "critical", "high", "medium", "low"] as const;

function custodyNote(e: Custody | null): { text: string; title: string } {
  if (!e) return { text: "", title: "" };
  if (!e.persisted) return { text: "feed not chained", title: e.error || "" };
  if (e.rejected) {
    return { text: `${fmt(e.rejected)} dropped by schema`, title: "" };
  }
  return { text: "", title: "" };
}

function Card({ a, classLabel, onSelect }: {
  a: Alert;
  classLabel: (tc: string) => string;
  onSelect: (id: string) => void;
}) {
  const sev = (a.severity || "medium").toLowerCase();
  const conf = Math.max(0, Math.min(100, Math.round((a.confidence || 0) * 100)));
  return (
    <article
      className={`alert-card sev--${sev}`}
      data-sev={sev}
      data-cls={a.threat_class}
      onClick={() => onSelect(a.alert_id)}
    >
      <div className="ac-bar" />
      <div className="ac-body">
        <div className="ac-row1">
          <span className="ac-class">{classLabel(a.threat_class)}</span>
          <span className="ac-sev">{sev.toUpperCase()}</span>
          <span className="ac-time">{fmtTime(a.timestamp)}</span>
        </div>
        <div className="ac-row2">
          <span className="ac-key" title={a.key || ""}>{a.key || "—"}</span>
          <span className="ac-det">{a.detector || ""}</span>
        </div>
        <div className="ac-row3">
          <div className="ac-conf"><i style={{ width: `${conf}%` }} /></div>
          <span className="ac-conf-label">conf {(a.confidence ?? 0).toFixed(2)}</span>
          {a.attack_technique && <span className="ac-attack">{a.attack_technique}</span>}
        </div>
      </div>
    </article>
  );
}

type Props = {
  alerts: Alert[];
  classStats: Record<string, ClassStat>;
  custody: Custody | null;
  sessionState: string;
  sessionTotal: number;
  classLabel: (tc: string) => string;
  onSelect: (id: string) => void;
};

export default function AlertFeed({
  alerts, classStats, custody, sessionState, sessionTotal, classLabel, onSelect,
}: Props) {
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [clsFilter, setClsFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [showChips, setShowChips] = useState(false);

  const onScreen = useMemo(() => alerts.slice(0, DOM_CAP), [alerts]);
  const needle = search.trim().toLowerCase();
  const filtered = useMemo(() => onScreen.filter((a) => {
    const sev = (a.severity || "medium").toLowerCase();
    const text = `${a.key || ""} ${classLabel(a.threat_class)} ${a.detector || ""}`
      .toLowerCase();
    return (sevFilter === "all" || sev === sevFilter)
      && (clsFilter === "all" || a.threat_class === clsFilter)
      && (!needle || text.includes(needle));
  }), [onScreen, sevFilter, clsFilter, needle, classLabel]);

  const cust = custodyNote(custody);
  const active = sevFilter !== "all" || clsFilter !== "all" || needle !== "";
  // The wire carries at most the newest cards and the DOM holds 80 of those;
  // metrics know the session total, so a trimmed feed says "last N of M"
  // instead of under-reporting it.
  const label = onScreen.length < sessionTotal
    ? `last ${fmt(onScreen.length)} of ${fmt(sessionTotal)} alerts`
    : `${fmt(onScreen.length)} alerts`;
  const meta = sessionState === "running"
    ? `streaming · ${fmt(filtered.length)}${active ? `/${fmt(onScreen.length)}` : ""} shown`
    : `${label}${active ? ` · ${fmt(filtered.length)} shown` : ""}`;

  return (
    <section className="card feedcard" id="activity">
      <div className="card-head">
        <b>Live Alert Feed</b>
        {cust.text && <span className="custody" title={cust.title}>{cust.text}</span>}
        {" "}<Help about="Live Alert Feed">Every closed window lands here the instant its
          detector fires — click a row to open its evidence.</Help>
        <span className="muted">{sessionState === "idle" ? "awaiting launch" : meta}</span>
        <div className="feed-tools">
          <label className="searchbox">
            <svg className="sm" aria-hidden="true"><use href="#i-search" /></svg>
            <input
              placeholder="Search alerts"
              autoComplete="off"
              aria-label="Search alerts"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </label>
          <button className="filterbtn" onClick={() => setShowChips((v) => !v)}>
            <svg className="sm" aria-hidden="true"><use href="#i-sliders" /></svg> Filter
          </button>
        </div>
      </div>

      {showChips && (
        <div className="chips">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              className={`chip${sevFilter === s ? " is-on" : ""}`}
              onClick={() => setSevFilter(s)}
            >
              {s[0].toUpperCase() + s.slice(1)}
            </button>
          ))}
          <span className="chips-sep" />
          <span className="cls-chips">
            {Object.keys(classStats).map((tc) => (
              <button
                key={tc}
                className={`chip${clsFilter === tc ? " is-on" : ""}`}
                onClick={() => setClsFilter(clsFilter === tc ? "all" : tc)}
              >
                {classLabel(tc).toUpperCase()}
              </button>
            ))}
          </span>
        </div>
      )}

      <div className="feed" role="feed" aria-label="Live alert feed">
        {onScreen.length === 0 && (
          <div className="feed-empty">
            <div className="feed-empty-glyph">
              <svg className="tri" aria-hidden="true"><use href="#i-tri" /></svg>
            </div>
            <p>
              Link is live. Launch a replay and every closed window
              <br />
              lands here the instant its detector fires.
            </p>
          </div>
        )}
        {onScreen.length > 0 && filtered.length === 0 && (
          <p className="muted">
            no alert on screen matches this filter (
            {fmt(onScreen.length)} hidden)
          </p>
        )}
        {filtered.map((a) => (
          <Card key={a.alert_id} a={a} classLabel={classLabel} onSelect={onSelect} />
        ))}
      </div>
    </section>
  );
}
