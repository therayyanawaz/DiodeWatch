import { useEffect, useRef } from "react";
import { cssVar, fmt } from "../format";
import { useThemeSignal } from "../useTheme";
import type { ClassStat } from "../types";

/* The rule layer's own classes, so a session that produced nothing yet still
   draws a three-axis frame instead of a blank box. */
const RADAR_BASE = ["ddos", "scan", "exfil"];

const count = (stats: Record<string, ClassStat>, k: string) => stats[k]?.count || 0;

/* Same axis rule as the shipped wall: every class that fired, then any base
   class nobody has reported yet, capped at 8, and never fewer than 3. */
export function radarAxes(stats: Record<string, ClassStat>): string[] {
  const live = Object.keys(stats).filter((k) => count(stats, k) > 0);
  const rest = RADAR_BASE.filter((k) => !(k in stats));
  const axes = [...live, ...rest].slice(0, 8);
  if (axes.length < 3) {
    for (const k of ["beacon", "dga", "bot"]) {
      if (!axes.includes(k)) axes.push(k);
      if (axes.length >= 3) break;
    }
  }
  return axes;
}

type Fit = { ctx: CanvasRenderingContext2D; w: number; h: number };

export default function Radar({ classStats, classLabel }: {
  classStats: Record<string, ClassStat>;
  classLabel: (tc: string) => string;
}) {
  const cv = useRef<HTMLCanvasElement | null>(null);
  const fit = useRef<Fit | null>(null);
  const cur = useRef<Record<string, number>>({});
  /* The draw loop is one long-lived interval that reads the latest props out of
     a ref, so easing never restarts when a window lands mid-glide. */
  const data = useRef({ stats: classStats, label: classLabel });
  data.current = { stats: classStats, label: classLabel };
  const theme = useThemeSignal();

  useEffect(() => {
    const redraw = () => {
      const el = cv.current;
      if (!el) return;
      if (!fit.current) {
        const dpr = window.devicePixelRatio || 1;
        const w = el.clientWidth || Number(el.getAttribute("width"));
        const h = el.clientHeight || Number(el.getAttribute("height"));
        el.width = Math.round(w * dpr);
        el.height = Math.round(h * dpr);
        const ctx = el.getContext("2d");
        if (!ctx) return;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        fit.current = { ctx, w, h };
      }
      draw(fit.current, cur, data.current.stats, data.current.label);
    };
    const resize = () => { fit.current = null; };
    window.addEventListener("resize", resize);
    const id = window.setInterval(redraw, 50);
    return () => {
      window.clearInterval(id);
      window.removeEventListener("resize", resize);
    };
  }, [theme]);

  return (
    <>
      <canvas id="radar" ref={cv} width={340} height={190} />
      <RadarLegend classStats={classStats} classLabel={classLabel} />
    </>
  );
}

function draw(
  f: Fit, cur: { current: Record<string, number> },
  stats: Record<string, ClassStat>, classLabel: (tc: string) => string,
) {
  const { ctx, w: W, h: H } = f;
  const grid = cssVar("--chart-grid"), sub = cssVar("--chart-sub");
  const accent = cssVar("--chart-accent"), soft = cssVar("--chart-accent-soft");
  const peak = cssVar("--chart-peak");
  ctx.clearRect(0, 0, W, H);

  const axes = radarAxes(stats);
  if (axes.length < 3) {
    ctx.fillStyle = sub;
    ctx.font = "500 11px ui-monospace,Consolas,monospace";
    ctx.textAlign = "center";
    ctx.fillText("awaiting signal", W / 2, H / 2);
    return;
  }

  const max = Math.max(1, ...axes.map((k) => count(stats, k)));
  const target: Record<string, number> = {};
  for (const k of axes) target[k] = count(stats, k) / max;

  // ease toward the target, same 0.14 rate as the shipped wall
  for (const k of Object.keys(target)) {
    const to = target[k], from = cur.current[k] ?? 0;
    const d = to - from;
    cur.current[k] = Math.abs(d) > 0.004 ? from + d * 0.14 : to;
  }
  for (const k of Object.keys(cur.current)) {
    if (!(k in target)) delete cur.current[k];
  }

  const cx = W / 2, cy = H / 2 + 4, R = Math.min(W, H) / 2 - 38;
  const ang = (i: number) => (Math.PI * 2 * i) / axes.length - Math.PI / 2;
  ctx.strokeStyle = grid; ctx.lineWidth = 1;
  for (let ring = 1; ring <= 4; ring++) {
    ctx.beginPath();
    for (let i = 0; i <= axes.length; i++) {
      const a = ang(i % axes.length), r = (R * ring) / 4;
      const x = cx + r * Math.cos(a), y = cy + r * Math.sin(a);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.stroke();
  }

  ctx.font = "600 9px ui-monospace,Consolas,monospace";
  axes.forEach((k, i) => {
    const a = ang(i);
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + R * Math.cos(a), cy + R * Math.sin(a));
    ctx.stroke();
    const lx = cx + (R + 16) * Math.cos(a), ly = cy + (R + 16) * Math.sin(a);
    ctx.textAlign = Math.abs(Math.cos(a)) < 0.3 ? "center"
      : (Math.cos(a) > 0 ? "left" : "right");
    ctx.fillStyle = sub;
    ctx.fillText(classLabel(k).toUpperCase(), lx, ly - 2);
    ctx.fillStyle = sub;
    ctx.fillText(String(count(stats, k)), lx, ly + 10);
  });

  const pts = axes.map((k, i) => {
    const a = ang(i), r = R * Math.max(0.02, cur.current[k] || 0);
    return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
  });
  ctx.beginPath();
  pts.forEach(([x, y], i) => (i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y)));
  ctx.closePath();
  ctx.fillStyle = soft;
  ctx.strokeStyle = accent; ctx.lineWidth = 1.6;
  ctx.fill(); ctx.stroke();

  pts.forEach(([x, y], i) => {
    const k = axes[i], atMax = count(stats, k) >= max && max > 1;
    ctx.beginPath(); ctx.arc(x, y, 2.6, 0, Math.PI * 2);
    ctx.fillStyle = atMax ? peak : accent;
    ctx.fill();
  });
}

/* The legend is the DOM half of the same aggregate the canvas draws, so the
   two can never disagree about which classes are on the wall. */
function RadarLegend({ classStats, classLabel }: {
  classStats: Record<string, ClassStat>;
  classLabel: (tc: string) => string;
}) {
  const axes = radarAxes(classStats);
  const max = Math.max(1, ...axes.map((k) => count(classStats, k)));
  return (
    <div className="radar-legend">
      {axes.map((k) => {
        const c = count(classStats, k);
        return (
          <span key={k}>{c >= max && max > 1 ? "◆" : "◇"} {classLabel(k)} <b>{fmt(c)}</b></span>
        );
      })}
    </div>
  );
}
