// Render docs/diagrams/*.puml to light and dark SVG with excaliplant.
import { readdir, readFile, writeFile } from "node:fs/promises";
import { render } from "@grethel-labs/excaliplant";

const dir = new URL("../../docs/diagrams/", import.meta.url);
for (const file of (await readdir(dir)).filter((f) => f.endsWith(".puml"))) {
  const source = await readFile(new URL(file, dir), "utf8");
  for (const [theme, suffix] of [["grethel-labs-light", "light"], ["grethel-labs-dark", "dark"]]) {
    const result = await render(source, { theme, aspectRatio: 16 / 9 });
    await writeFile(new URL(file.replace(".puml", `-${suffix}.svg`), dir), await result.toSvg({ padding: 16 }));
  }
  console.log(`rendered ${file}`);
}
