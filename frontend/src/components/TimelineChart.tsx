import { useEffect, useRef, useState } from "react";
import { cssVar } from "../format";
import { useThemeSignal } from "../useTheme";
import Help from "./Help";

/* Ported from the shipped wall's drawTimeline(): zero-fill every second across
   the range so a burst reads as a spike against a quiet baseline, bucket
   anything longer than an hour, and pad the time domain so an edge burst never
   glues to the border. */
function entriesOf(raw: Array<[number, number]>): Array<[number, number]> {
  if (raw.length < 2) return raw;
  const span = raw[raw.length - 1][0] - raw[0][0];
  if (span > 1 && span <= 3600) {
    const known = new Map(raw);
    const out: Array<[number, number]> = [];
    for (let t = raw[0][0]; t <= raw[raw.length - 1][0]; t++) {
      out.push([t, known.get(t) || 0]);
    }
    return out;
  }
  if (span > 3600) {
    const B = Math.ceil(span / 600);      // ~600 points maximum
    const buckets = new Map<number, number>();
    for (const [t, n] of raw) {
      const b = raw[0][0] + Math.floor((t - raw[0][0]) / B) * B;
      buckets.set(b, (buckets.get(b) || 0) + n);
    }
    return [...buckets.entries()].sort((a, b) => a[0] - b[0]);
  }
  return raw;
}

export default function TimelineChart({ timeline }: {
  timeline: Record<string, number>;
}) {
  const cv = useRef<HTMLCanvasElement | null>(null);
  const theme = useThemeSignal();
  const [viewport, setViewport] = useState(0);

  useEffect(() => {
    const onResize = () => setViewport((v) => v + 1);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    const el = cv.current;
    if (!el) return;
    const dpr = window.devicePixelRatio || 1;
    const W = el.clientWidth || Number(el.getAttribute("width"));
    const H = el.clientHeight || Number(el.getAttribute("height"));
    el.width = Math.round(W * dpr);
    el.height = Math.round(H * dpr);
    const ctx = el.getContext("2d");
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw(ctx, W, H, timeline);
  }, [timeline, theme, viewport]);

  return (
    <section className="card chartcard">
      <div className="card-head">
        <div>
          <b>Alert Timeline</b>
          {" "}<Help about="Alert Timeline">Alerts per capture-second across the replay,
            zero-filled so bursts read as spikes against quiet seconds.</Help>
          <p className="muted small">alerts per capture-second</p>
        </div>
        <div className="legend">
          <i className="lg lg--orange" />Alerts<i className="lg lg--gray" />Peak
        </div>
      </div>
      <canvas ref={cv} width={900} height={230} />
    </section>
  );
}

function draw(
  ctx: CanvasRenderingContext2D, W: number, H: number,
  timeline: Record<string, number>,
) {
  const grid = cssVar("--chart-grid"), sub = cssVar("--chart-sub");
  const accent = cssVar("--chart-accent"), soft = cssVar("--chart-accent-soft");
  const peak = cssVar("--chart-peak");
  ctx.clearRect(0, 0, W, H);
  const pad = { l: 46, r: 14, t: 14, b: 24 };

  const raw = Object.entries(timeline)
    .map(([s, n]) => [Number(s), n] as [number, number])
    .sort((a, b) => a[0] - b[0]);
  if (!raw.length) {
    ctx.fillStyle = sub;
    ctx.font = "500 11px ui-monospace,Consolas,monospace";
    ctx.textAlign = "center";
    ctx.fillText("the timeline fills as alerts fire", W / 2, H / 2);
    return;
  }

  const entries = entriesOf(raw);
  const max = Math.max(1, ...entries.map((e) => e[1]));
  const t0 = entries[0][0];
  const t1 = Math.max(entries[entries.length - 1][0], t0 + 1);
  const padT = Math.max(1, (t1 - t0) * 0.04);
  const d0 = t0 - padT, d1 = t1 + padT;
  const x = (t: number) => pad.l + ((t - d0) / (d1 - d0)) * (W - pad.l - pad.r);
  const y = (n: number) => pad.t + (1 - n / max) * (H - pad.t - pad.b);

  const steps = max <= 4 ? max : 4;
  ctx.strokeStyle = grid; ctx.lineWidth = 1;
  ctx.fillStyle = sub;
  ctx.font = "500 9px ui-monospace,Consolas,monospace";
  ctx.textAlign = "right";
  for (let g = 0; g <= steps; g++) {
    const frac = g / steps;
    const val = max * (1 - frac);
    const gy = pad.t + frac * (H - pad.t - pad.b);
    ctx.beginPath(); ctx.moveTo(pad.l, gy); ctx.lineTo(W - pad.r, gy); ctx.stroke();
    ctx.fillText(String(Math.round(val * 10) / 10), pad.l - 7, gy + 3);
  }

  const plotW = W - pad.l - pad.r;
  const slot = plotW / entries.length;
  const bw = Math.max(2, Math.min(28, slot * 0.62));
  ctx.beginPath();
  entries.forEach(([t, n], i) => {
    const px = x(t), py = y(n);
    if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
  });
  ctx.strokeStyle = soft; ctx.lineWidth = 1.2;
  ctx.stroke();
  ctx.fillStyle = accent;
  for (const [t, n] of entries) {
    if (n <= 0) continue;
    const bx = x(t) - bw / 2, by = y(n), base = H - pad.b;
    ctx.fillRect(bx, by, bw, Math.max(2, base - by));
  }
  for (const [t, n] of entries) {
    if (n <= 0) continue;
    ctx.beginPath(); ctx.arc(x(t), y(n), 2.6, 0, Math.PI * 2);
    ctx.fillStyle = peak; ctx.fill();
  }

  ctx.fillStyle = sub; ctx.textAlign = "center";
  const tickN = Math.min(4, entries.length);
  for (let i = 0; i < tickN; i++) {
    const e = entries[Math.round((i / Math.max(1, tickN - 1)) * (entries.length - 1))];
    ctx.fillText(`+${Math.round(e[0] - t0)}s`, x(e[0]), H - 8);
  }
}
