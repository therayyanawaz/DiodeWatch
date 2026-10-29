import { useEffect, useState } from "react";

/* Both canvas clients need to know when the host flips the theme: the shipped
   wall calls drawRadar()/drawTimeline() from its toggle handler, and a React
   panel that re-rendered instead would still read stale CSS variables. Watching
   the attribute keeps the observer next to the paint, so Topbar does not have to
   know which panels draw. */
export function useThemeSignal(): "dark" | "light" {
  const read = () =>
    (document.documentElement.dataset.theme === "dark" ? "dark" : "light");
  const [theme, setTheme] = useState<"dark" | "light">(read);

  useEffect(() => {
    const mo = new MutationObserver(() => setTheme(read()));
    mo.observe(document.documentElement, {
      attributes: true, attributeFilter: ["data-theme"],
    });
    return () => mo.disconnect();
  }, []);

  return theme;
}
