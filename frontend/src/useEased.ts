import { useEffect, useRef, useState } from "react";

/* One owner for the animated numbers, exactly like the shipped wall's single
   state.kpi: the stat tiles, the capacity card and the hero all read the same
   eased object, so "Sustained Capacity" can never print a different flow rate
   from the benchmark bar beside it.

   The wall eases instead of snapping — a number that jumps 0 → 11,556 in one
   frame reads as a glitch — and it runs on setInterval rather than
   requestAnimationFrame, because a rAF loop stops in a hidden or occluded
   webview and the figures would freeze mid-glide. Same 50 ms tick, same 0.16
   rate, same deadband. */
const TICK_MS = 50;
const RATE = 0.16;

export type Kpi = {
  replay: number;
  alertRate: number;
  p95: number;
  p50: number;
  cap: number;
  flows: number;
  alerts: number;
  suppressed: number;
};

export function useEased<T extends Record<string, number>>(target: T): T {
  const want = useRef(target);
  want.current = target;
  const cur = useRef<Record<string, number>>({});
  const [shown, setShown] = useState<Record<string, number>>({});

  useEffect(() => {
    const id = window.setInterval(() => {
      const next = { ...cur.current };
      let moved = false;
      for (const key of Object.keys(want.current)) {
        const to = want.current[key];
        const from = next[key] ?? 0;
        const diff = to - from;
        if (Math.abs(diff) > Math.max(0.02, Math.abs(to) * 0.001)) {
          next[key] = from + diff * RATE;
          moved = true;
        } else if (from !== to) {
          next[key] = to;
          moved = true;
        }
      }
      if (moved) {
        cur.current = next;
        setShown(next);
      }
    }, TICK_MS);
    return () => window.clearInterval(id);
  }, []);

  return shown as T;
}
