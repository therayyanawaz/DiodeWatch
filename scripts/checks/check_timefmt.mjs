/* Exit check: the wall renders one clock, not two.
 *
 * The alert feed's only formatter is dom.js `fmtTime`. The rule layer writes
 * naive UTC ("2025-06-15T15:07:00") and the ML sidecar writes "+00:00", and
 * JavaScript reads a zone-less date-time as LOCAL, so a formatter that just
 * calls `new Date(s)` shows one card's UTC face and its neighbour's same
 * instant converted to local time. On a +5:30 host that is 5h30m apart, and
 * it only shows up on a machine that is not UTC, which is why the Python
 * suite (and a UTC CI runner) cannot see it.
 *
 * Run from the repo root: node scripts/checks/check_timefmt.mjs
 *
 * Both walls import this module, the React client re-exports these same three
 * helpers instead of holding a copy (frontend/src/format.ts), and
 * tests/ui/test_mission_control.py fails CI if either surface re-declares one -
 * so what passes here is the clock the analyst actually sees on either page.
 */
import { fmtTime, fmtLocal } from "../../apps/mission_control/static/js/dom.js";

const HOST_OFFSET = -new Date().getTimezoneOffset() / 60;

// The same instant, spelled the way each producer spells it.
const NAIVE = "2025-06-15T15:07:00";
const OFFSET = "2025-06-15T15:07:00+00:00";
const OTHER_ZONE = "2025-06-15T20:37:00+05:30";   // same instant, IST spelling
const UTC_FACE = "15:07:00";

const cases = [
  ["naive UTC (rule layer)", fmtTime(NAIVE), UTC_FACE],
  ["explicit +00:00 (ML sidecar)", fmtTime(OFFSET), UTC_FACE],
  ["offset in another zone", fmtTime(OTHER_ZONE), UTC_FACE],
  ["space separator", fmtTime("2025-06-15 15:07:00"), UTC_FACE],
  ["non-ISO fallback still slices", fmtTime("nope T11:22:33 here"), "11:22:33"],
  ["empty stays a dash", fmtTime(""), " -"],
];

let failed = 0;
for (const [name, got, want] of cases) {
  if (got !== want) {
    failed++;
    console.error(`FAIL  ${name}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
  } else {
    console.log(`ok    ${name} -> ${got}`);
  }
}

// The invariant the Python suite cannot check: two spellings of one instant
// must not disagree, whatever the host thinks its zone is.
const spread = Math.abs(new Date(OFFSET) - new Date(NAIVE)) / 3.6e6;
console.log(`host offset: UTC${HOST_OFFSET >= 0 ? "+" : ""}${HOST_OFFSET}` +
  ` · naive-vs-offset divergence the old body produced: ${spread}h`);
if (HOST_OFFSET !== 0 && fmtTime(NAIVE) !== fmtTime(OFFSET)) {
  failed++;
  console.error("FAIL  the same instant renders differently on this host");
}

// fmtLocal is the operator's wall clock (the header, labelled LOCAL) and must
// stay local: the fix belongs to the capture clock, not to the viewer's.
if (fmtLocal(new Date(OFFSET)) === UTC_FACE && HOST_OFFSET !== 0) {
  failed++;
  console.error("FAIL  fmtLocal stopped showing the viewer's own time");
}

console.log(failed ? `TIME CLOCK CHECK FAILED (${failed})` : "TIME CLOCK CHECK CLEAN");
process.exit(failed ? 1 : 0);
