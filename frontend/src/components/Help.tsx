import type { ReactNode } from "react";

/* The tooltip beside a panel title. `about` builds the accessible name
   ("About Threat Level") so a screen reader announces the button by what it
   explains, and the tip carries the caveat that number needs — what it does
   NOT measure. `edge` is the variant the stylesheet anchors to the right. */
export default function Help({ about, edge = false, children }: {
  about: string;
  edge?: boolean;
  children: ReactNode;
}) {
  return (
    <button
      className={`help${edge ? " help--edge" : ""}`}
      type="button"
      aria-label={`About ${about}`}
    >
      <svg aria-hidden="true"><use href="#i-help" /></svg>
      <span className="help-tip" role="tooltip">{children}</span>
    </button>
  );
}
