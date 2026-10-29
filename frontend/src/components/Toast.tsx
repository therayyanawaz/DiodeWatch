import { useEffect, useState } from "react";

/* One toast element, mounted once per page and faded on a timer: the `#toast`
   id and the `.err` state are what the shared stylesheet already styles, and
   `role="status"` with `aria-live="polite"` announces it to a screen reader
   without stealing focus from the feed. */
export default function Toast({ message, isError }: { message: string; isError: boolean }) {
  const [shown, setShown] = useState(false);

  useEffect(() => {
    if (!message) return;
    setShown(true);
    const id = window.setTimeout(() => setShown(false), 4200);
    return () => window.clearTimeout(id);
  }, [message]);

  return (
    <div id="toast" className={isError ? "err" : undefined}
         role="status" aria-live="polite"
         style={{ opacity: shown ? 1 : 0 }}>
      {message}
    </div>
  );
}
