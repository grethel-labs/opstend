import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

// excaliplant reads its font from disk and rasterises PNG through resvg; both are
// Node-only. In the browser the font is served as a file and PNG export is not needed.
function excaliplantBrowser(): Plugin {
  const font = fileURLToPath(
    new URL("./node_modules/@grethel-labs/excaliplant/assets/fonts/Excalifont-Regular.woff2", import.meta.url),
  );
  return {
    name: "excaliplant-browser",
    enforce: "pre",
    resolveId(source, importer) {
      if (!importer?.includes("@grethel-labs/excaliplant")) return null;
      if (source.endsWith("/font.mjs") || source === "./font.mjs") return "\0excaliplant-font";
      if (source.endsWith("/png.mjs") || source === "./png.mjs") return "\0excaliplant-png";
      return null;
    },
    load(id) {
      if (id === "\0excaliplant-font") {
        return `import url from ${JSON.stringify(font + "?url")};
export const EXCALIFONT_TTF_PATH = "";
export function excalifontFaceCss() {
  return '@font-face{font-family:"Excalifont";src:url(' + url + ') format("woff2");font-display:swap;}';
}`;
      }
      if (id === "\0excaliplant-png") {
        return `export function svgToPng() { throw new Error("PNG export is not available in the browser"); }`;
      }
      return null;
    },
  };
}

export default defineConfig({
  plugins: [excaliplantBrowser(), react()],
  build: {
    outDir: "../src/opstend/api/static",
    emptyOutDir: true,
    target: "es2022",
    chunkSizeWarningLimit: 1500,
  },
  server: {
    proxy: { "/api": { target: "http://127.0.0.1:8080", changeOrigin: false } },
  },
});
