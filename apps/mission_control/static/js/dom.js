/* DiodeWatch · formatting primitives.
   Pure helpers, no imports, no app state. The wall's client is built from
   these (`frontend/src/format.ts` re-exports them) rather than holding a
   second copy, so the naive-UTC rule below has one owner. */
/* An absent measurement reads 0, never "NaN": a wall that has not run yet
   has genuinely processed zero flows. Values that must not be mistaken for a
   real zero render " -" at the call site, the way the diode panel does. */
export const fmt = (n, d = 0) => Number(n ?? 0).toLocaleString("en-US", {
  minimumFractionDigits: d, maximumFractionDigits: d
});
export const cssVar = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
/* Alert capture time, HH:MM:SS (24 h) in UTC, the evidence clock, not the
   wall clock (the header shows the viewer's own time and says LOCAL).
   Two producers, two spellings: the rule layer writes naive UTC
   ("2023-11-14T22:14:50") and the ML sidecar writes "+00:00". JS reads a
   zone-less date-time as LOCAL, so `new Date(s)` alone would show one card's
   UTC face and its neighbour's same instant converted to local, 5h30m apart
   on an IST host. Pin the missing zone, then always read UTC. */
export const fmtTime = (ts) => {
  const s = String(ts || "");
  const zoneless = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s) &&
    !/(?:z|[+-]\d{2}:?\d{2})$/i.test(s);
  const d = new Date(zoneless ? `${s}Z` : s);
  if (s && !Number.isNaN(d.getTime()))
    return [d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds()]
      .map((n) => String(n).padStart(2, "0")).join(":");
  const m = /T(\d{2}:\d{2}:\d{2})/.exec(s);   // non-ISO fallback: raw slice
  return m ? m[1] : s.slice(11, 19) || " -";
};
/* wall-clock time in the viewer's own timezone, HH:MM:SS (24 h) */
export const fmtLocal = (d = new Date()) =>
  [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map((n) => String(n).padStart(2, "0")).join(":");
