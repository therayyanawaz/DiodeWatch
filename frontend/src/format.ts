/* One clock, not two. `dom.js` is the wall's own formatter module and this file
   only re-exports it, so the naive-UTC-vs-+00:00 rule that took a bug to write
   cannot be broken in one copy while the other stays correct, and the canvas
   panels read the same theme variables the charts read. CI runs
   `node scripts/checks/check_timefmt.mjs` on a non-UTC host against this same
   implementation, so the page and the check can never disagree. */
export { fmt, fmtTime, fmtLocal, cssVar } from "../../apps/mission_control/static/js/dom.js";
