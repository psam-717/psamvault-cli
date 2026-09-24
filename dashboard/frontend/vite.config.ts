import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Built files land in dashboard/static/app, which Flask serves at /static/app/.
// The repo gitignores a top-level dist/, so this folder is named app on purpose.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "/static/app/",
  build: {
    outDir: "../static/app",
    emptyOutDir: true,
  },
});
