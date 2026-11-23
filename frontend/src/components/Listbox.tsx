import { useEffect, useId, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import type { Source } from "../types";

/* The two floating listboxes the shipped wall builds on top of native <select>s.
   React holds the state directly, so there is no visually-hidden select left to
   keep in sync, but the markup, classes, ARIA roles and keyboard contract are
   the wall's, because the shared stylesheet and a screen reader both key off
   them. */

const SRC_ICONS: Record<string, string> = {
  demo: "i-pulse", ddos: "i-bolt", beacon: "i-radio", dga: "i-dna",
  exfil: "i-send", scan: "i-radar", tls: "i-lock", dns: "i-dna",
  brute: "i-bolt", web: "i-bolt",
};

export function srcIcon(key: string): string {
  const k = key || "";
  for (const part of k.replace(/^pack:/, "").split(/[_/\-]/)) {
    for (const name of Object.keys(SRC_ICONS)) {
      if (part.startsWith(name)) return SRC_ICONS[name];
    }
  }
  return "i-radar";
}

type Opt = { value: string; text: string; icon?: string };

function useListbox(options: Opt[], value: string, onPick: (v: string) => void) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const root = useRef<HTMLDivElement | null>(null);
  const btn = useRef<HTMLButtonElement | null>(null);
  const rows = useRef<HTMLElement[]>([]);

  const index = () => {
    const i = options.findIndex((o) => o.value === value);
    return i < 0 ? 0 : i;
  };

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("click", onDoc);
    return () => document.removeEventListener("click", onDoc);
  }, [open]);

  const toggle = () => {
    setOpen((v) => {
      if (!v) setActive(index());
      return !v;
    });
  };

  const moveTo = (dir: number) => {
    if (!options.length) return;
    const next = Math.min(options.length - 1, Math.max(0, active + dir));
    setActive(next);
    rows.current[next]?.scrollIntoView({ block: "nearest" });
  };

  const choose = (i: number) => {
    onPick(options[i].value);
    setOpen(false);
    btn.current?.focus();
  };

  const onKeyDown = (e: ReactKeyboardEvent) => {
    if (e.key === "Escape") {
      if (open) { setOpen(false); btn.current?.focus(); }
      return;
    }
    if (!open) {
      if (["Enter", " ", "ArrowDown", "ArrowUp"].includes(e.key)) {
        e.preventDefault();
        setActive(index());
        setOpen(true);
      }
      return;
    }
    if (e.key === "ArrowDown") { e.preventDefault(); moveTo(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); moveTo(-1); }
    else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); choose(active); }
    else if (e.key === "Tab") { setOpen(false); }
  };

  return { open, active, root, btn, rows, toggle, onKeyDown, choose };
}

function Chevron() {
  return <svg className="chev" aria-hidden="true"><use href="#i-chev" /></svg>;
}

/** The option rows, identical contract in both listboxes. */
function Options({ lb, options, value, menuClass, ariaLabel, iconled }: {
  lb: ReturnType<typeof useListbox>;
  options: Opt[];
  value: string;
  menuClass: string;
  ariaLabel: string;
  iconled: boolean;
}) {
  // Arrow keys move `lb.active`; without activedescendant the focus ring moves
  // and a screen reader says nothing, so the list appears frozen to anyone not
  // looking at it. useId keeps the pairing unique per listbox instance.
  const listId = useId();
  return (
    <div className={menuClass} role="listbox" aria-label={ariaLabel} hidden={!lb.open}
         aria-activedescendant={lb.active === null ? undefined : `${listId}-opt-${lb.active}`}>
      {options.map((o, i) => (
        <div
          key={o.value}
          id={`${listId}-opt-${i}`}
          ref={(el) => { lb.rows.current[i] = el as HTMLElement; }}
          className={`source-option${i === lb.active ? " is-active" : ""}`}
          role="option"
          aria-selected={o.value === value}
          onClick={() => lb.choose(i)}
        >
          {iconled && <svg aria-hidden="true"><use href={`#${o.icon}`} /></svg>}
          <span>{o.text}</span>
        </div>
      ))}
    </div>
  );
}

export function MiniSelect({ label, value, options, onChange }: {
  label: string;
  value: string;
  options: Opt[];
  onChange: (v: string) => void;
}) {
  const lb = useListbox(options, value, onChange);
  const current = options.find((o) => o.value === value);
  return (
    <div ref={lb.root} className={`customsel customsel--mini${lb.open ? " open" : ""}`}
         onKeyDown={lb.onKeyDown}>
      <button ref={lb.btn} type="button" className="customsel-btn"
              aria-haspopup="listbox" aria-expanded={lb.open} aria-label={label}
              onClick={lb.toggle}>
        <span className="customsel-value">{current ? current.text : " -"}</span>
        <Chevron />
      </button>
      <Options lb={lb} options={options} value={value} ariaLabel={label}
               menuClass="source-menu customsel-menu" iconled={false} />
    </div>
  );
}

/* The capture picker. Its leading icon is the wall's fixed pulse glyph, the
   row icons change with the source, the pill icon does not. */
export function SourcePicker({ sources, value, onChange }: {
  sources: Source[];
  value: string;
  onChange: (v: string) => void;
}) {
  const options: Opt[] = sources.length
    ? sources.map((s) => ({ value: s.key, text: s.label, icon: srcIcon(s.key) }))
    : [{ value: "demo", text: "Demo capture, mixed threats", icon: srcIcon("demo") }];
  const lb = useListbox(options, value, onChange);
  const current = options.find((o) => o.value === value);
  return (
    <div ref={lb.root} className={`pillselect${lb.open ? " open" : ""}`} title="Replay capture"
         onKeyDown={lb.onKeyDown}>
      <button ref={lb.btn} type="button" className="pillselect-btn"
              aria-haspopup="listbox" aria-expanded={lb.open}
              aria-label="Replay capture source" onClick={lb.toggle}>
        <svg className="sm" aria-hidden="true"><use href="#i-pulse" /></svg>
        <span>{current ? current.text : " -"}</span>
        <Chevron />
      </button>
      <Options lb={lb} options={options} value={value} ariaLabel="Replay capture source"
               menuClass="source-menu" iconled />
    </div>
  );
}
