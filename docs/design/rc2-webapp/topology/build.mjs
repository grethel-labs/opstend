import { build } from "esbuild";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const directory = fileURLToPath(new URL("./", import.meta.url));
const require = createRequire(import.meta.url);
const library = dirname(require.resolve("@grethel-labs/excaliplant/package.json"));

await build({
  stdin: {
    contents: `
      import { render } from "@grethel-labs/excaliplant";
      import { bindHooks } from "@grethel-labs/excaliplant/hooks";
      window.opstendExcaliplant = { render, bindHooks };`,
    resolveDir: directory,
  },
  bundle: true,
  platform: "browser",
  format: "iife",
  minify: true,
  legalComments: "inline",
  target: "es2022",
  outfile: join(directory, "excaliplant.bundle.js"),
  plugins: [{
    name: "svg-preview",
    setup(plugin) {
      plugin.onResolve({ filter: /\/(font|png)\.mjs$/ }, (args) => {
        const target = resolve(args.resolveDir, args.path);
        if (target === join(library, "src/render/font.mjs")) return { path: "font", namespace: "svg-preview" };
        if (target === join(library, "src/render/png.mjs")) return { path: "png", namespace: "svg-preview" };
      });
      plugin.onLoad({ filter: /.*/, namespace: "svg-preview" }, ({ path }) => ({
        contents: path === "font"
          ? 'export const EXCALIFONT_TTF_PATH = ""; export const excalifontFaceCss = () => "";'
          : 'export function svgToPng() { throw new Error("The live map renders SVG."); }',
      }));
    },
  }],
});
