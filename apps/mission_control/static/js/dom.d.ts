/* Types for the wall's own formatting primitives, which its client is built
   against. This file declares dom.js; it does not reimplement it. */
export declare const fmt: (n?: number | null, d?: number) => string;
export declare const cssVar: (name: string) => string;
export declare const fmtTime: (ts?: string | null) => string;
export declare const fmtLocal: (d?: Date) => string;
