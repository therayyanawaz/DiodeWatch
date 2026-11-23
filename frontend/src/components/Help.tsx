import { useId } from "react";
import type { ReactNode } from "react";

/* The tooltip beside a panel title. `about` builds the accessible name
   ("About Threat Level") so a screen reader announces the button by what it
   explains, and the tip carries the caveat that number needs, what it does
   NOT measure. `edge` is the variant the stylesheet anchors to the right.

   The tip is wired as the button's description, not as an unnamed tooltip: a
   `role="tooltip"` node takes no name from its contents, so without the
   `aria-describedby` pairing a screen reader reaches the button and never
   hears the caveat, which is the part that says what the number does NOT
   measure. */
export default function Help({ about, edge = false, children }: {
  about: string;
  edge?: boolean;
  children: ReactNode;
}) {
  const tipId = useId();
  return (
    <button
      className={`help${edge ? " help--edge" : ""}`}
      type="button"
      aria-label={`About ${about}`}
      aria-describedby={tipId}
    >
      <svg aria-hidden="true"><use href="#i-help" /></svg>
      <span className="help-tip" role="tooltip" id={tipId}>{children}</span>
    </button>
  );
}
