// Screenshots of the demo for README and reviews. Start `uv run opstend demo` first.
import { mkdir } from "node:fs/promises";
import { chromium, devices } from "@playwright/test";

const base = process.env.OPSTEND_URL ?? "http://127.0.0.1:8080";
const out = new URL("../../docs/screenshots/", import.meta.url).pathname;
await mkdir(out, { recursive: true });
const browser = await chromium.launch();
const shots = [
  ["operations", "/", 1500],
  ["topology", "/network/topology?layers=physical,network", 6000],
  ["network", "/network", 1500],
  ["guest", "/guests/pve%3Ahome%3A101", 1200],
  ["updates", "/updates", 1200],
  ["new-service", "/services/new?repo=https%3A%2F%2Fgithub.com%2Fwerkstatt%2Fwetterstation", 2500],
  ["cluster", "/cluster", 1200],
];
for (const [scheme, suffix] of [["light", ""], ["dark", "-dark"]]) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: scheme, locale: "de-DE" });
  for (const [name, path, wait] of scheme === "dark" ? shots.slice(0, 2) : shots) {
    await page.goto(base + "/#" + path);
    await page.waitForTimeout(wait);
    await page.screenshot({ path: `${out}${name}${suffix}.png` });
  }
  await page.close();
}
const phone = await browser.newPage({ ...devices["Pixel 7"], locale: "de-DE" });
await phone.goto(base + "/");
await phone.waitForTimeout(1500);
await phone.screenshot({ path: `${out}phone.png` });
await browser.close();
console.log(`screenshots in ${out}`);
