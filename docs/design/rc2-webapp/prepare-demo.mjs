import { copyFile, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";

const root = new URL("./", import.meta.url);
const brand = new URL("../../../webapp/public/brand/", root);
const destination = await mkdtemp("/var/tmp/opstend-rc2-demo.");
const scriptsAndStyles = [
  "locale.js", "inventory.js", "network-rules.js", "zorec-policy.js", "object-ui.js", "monitoring-data.js", "views.js", "monitoring.js", "ports.js", "network-rules-ui.js", "events.js", "guest.js", "services.js", "topology.js", "api-demo.js", "manage.js",
  "zorec-mascot.js", "zorec-status.js", "zorec-activity.js", "deploy.js", "styles.css", "topology.css", "manage.css", "deploy.css", "zorec-mascot.css", "zorec-activity.css", "monitoring.css",
  "zorec-diagram.js", "zorec-fields.js", "zorec-console.js", "zorec-model.js", "zorec-context-tools.js", "zorec-diagram.css", "zorec-fields.css", "zorec-console.css",
  "zorec-model-comparison.js", "zorec-model-comparison.css", "self-update-state.js", "self-update.js", "self-update.css",
  "host-management-state.js", "host-management.js", "host-management.css",
  "host-maintenance-state.js", "host-maintenance-ui.js", "zorec-autonomy.js", "zorec-autonomy-ui.js",
  "publications.js", "publication-ui.js",
  "pve-inventory-data.js", "pve-inventory-ui.js", "pve-inventory-fixtures.json",
  "zorec-navigation.js", "zorec-knowledge.js", "zorec-inspections.js", "zorec-chats.js",
];
const brandFiles = ["opstend.svg", "opstend-dark.svg"];
const renderer = "topology/excaliplant.bundle.js";

const app = (await readFile(new URL("app.js", root), "utf8")).replaceAll("../../../webapp/public/brand", "brand");
await writeFile(join(destination, "app.js"), app);
for (const file of scriptsAndStyles) {
  await copyFile(new URL(file, root), join(destination, file));
}

await mkdir(join(destination, "brand"));
for (const file of brandFiles) {
  await copyFile(new URL(file, brand), join(destination, "brand", file));
}
await mkdir(join(destination, "topology"));
await copyFile(new URL(renderer, root), join(destination, renderer));

const html = (await readFile(new URL("index.html", root), "utf8")).replaceAll("../../../webapp/public/brand", "brand");
const hash = createHash("sha256").update(html);
hash.update(await readFile(new URL("serve-demo.py", root)));
const assets = new Set(["app.js", ...scriptsAndStyles, ...brandFiles.map((file) => `brand/${file}`), renderer]);
for (const asset of assets) hash.update(await readFile(join(destination, asset)));
const build = hash.digest("hex").slice(0, 12);
const index = html.replace("<html ", `<html data-demo-build="${build}" `)
  .replace(/(src|href)="([^"]+)"/g, (match, attribute, url) =>
    assets.has(url) ? `${attribute}="${url}?build=${build}"` : match);
await writeFile(join(destination, "index.html"), index);
await writeFile(join(destination, "demo-version.json"), JSON.stringify({ build }));
console.log(destination);
