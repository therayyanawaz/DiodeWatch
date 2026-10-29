import { useEffect, useState } from "react";
import { fmtLocal } from "../format";

/* The header clock, on both page entries: the viewer's own time, labelled
   LOCAL, while every alert timestamp on screen is the evidence clock in UTC.
   It comes through format.ts, so no page keeps a second formatter that could
   read a zone-less timestamp as local. */
export default function Clock() {
  const [now, setNow] = useState(fmtLocal());

  useEffect(() => {
    const id = window.setInterval(() => setNow(fmtLocal()), 1000);
    return () => window.clearInterval(id);
  }, []);

  return (
    <span className="sys-clock" title="Local clock">
      <span>{now}</span><span> LOCAL</span>
    </span>
  );
}
