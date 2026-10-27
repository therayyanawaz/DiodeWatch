import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The wall is a client of server.py only: every number it prints comes from a
// route that server already answers, so `npm run dev` proxies them instead of
// teaching the React app a second, invented API surface.
const API = process.env.DIODEWATCH_API ?? "http://127.0.0.1:8530";

export default defineConfig({
  // The wall is the home page, so the build is rooted at the directory the
  // server already mounts at `/`: chunk URLs come out as `/assets/…` and the
  // existing StaticFiles walk serves them without a mount invented for the
  // client. `emptyOutDir` is off because that same directory holds the
  // hand-written stylesheet and formatter module the bundle is built against;
  // `prebuild` prunes just the chunks, so a content hash that changes cannot
  // leave the last build's orphans in the committed tree.
  base: "/",
  plugins: [react()],
  build: {
    outDir: "../apps/mission_control/static",
    emptyOutDir: false,
    rollupOptions: {
      // Two pages, one bundle graph: the wall and its status board are the two
      // surfaces a judge reads, and emitting the second as a page (rather than
      // a hash route inside the SPA) keeps the existing StaticFiles mount and
      // two explicit routes as the only things serving them.
      input: {
        main: fileURLToPath(new URL("./index.html", import.meta.url)),
        status: fileURLToPath(new URL("./status.html", import.meta.url)),
      },
      output: {
        // Both pages import React, so without this Rollup folds the library into
        // a shared chunk and labels it after whichever app module happened to
        // join it. Naming the library chunk for the library keeps the largest
        // asset in `static/assets/` describing its own contents.
        manualChunks(id) {
          if (id.includes("node_modules")) return "react";
        },
      },
    },
  },
  server: {
    port: 5199,
    // The client imports the wall's own formatters from static/js/dom.js
    // rather than holding a second copy, and that file sits above the Vite
    // root — dev would refuse to serve it without this.
    fs: { allow: [".."] },
    proxy: {
      "/api": API,
      "/css": API,
      "/report": API,
      "/status": API,
      "/ws/live": { target: API.replace(/^http/, "ws"), ws: true },
    },
  },
});
