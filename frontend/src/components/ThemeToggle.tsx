import { useEffect, useState } from "react";

/* One localStorage key ("sih-theme"), so a host keeps one theme across the wall
   and its status board, and the pre-paint script in each page entry reads the
   same value before the first frame. The button keeps id="themeToggle" because
   the shared stylesheet swaps the sun and moon glyphs by that id rather than by
   a class. */
export default function ThemeToggle() {
  const [dark, setDark] = useState(() => {
    try {
      return localStorage.getItem("sih-theme") === "dark";
    } catch {
      return false;
    }
  });

  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "";
    try {
      localStorage.setItem("sih-theme", dark ? "dark" : "light");
    } catch {
      /* private mode: the choice just does not persist */
    }
  }, [dark]);

  return (
    <button
      className="iconbtn"
      id="themeToggle"
      title="Toggle light / dark theme"
      aria-label="Toggle light / dark theme"
      onClick={() => setDark((v) => !v)}
    >
      <svg className="ic-sun" aria-hidden="true"><use href="#i-sun" /></svg>
      <svg className="ic-moon" aria-hidden="true"><use href="#i-moon" /></svg>
    </button>
  );
}
