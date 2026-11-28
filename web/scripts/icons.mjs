// Render the PWA icons from the brand SVG. Run once after changing the logo.
import { readFile } from "node:fs/promises";
import { chromium } from "@playwright/test";

const svg = await readFile(new URL("../public/brand/opstend-dark.svg", import.meta.url), "utf8");
const browser = await chromium.launch();
const page = await browser.newPage({ deviceScaleFactor: 1 });
for (const [name, size, pad] of [["icon-192", 192, 0], ["icon-512", 512, 0], ["maskable-512", 512, 0.16]]) {
  const inner = Math.round(size * (1 - pad * 2));
  await page.setViewportSize({ width: size, height: size });
  await page.setContent(`<body style="margin:0;background:#0f2a2c;display:grid;place-items:center;height:${size}px">
    <div style="width:${inner}px;height:${inner}px">${svg.replace("<svg ", `<svg width="${inner}" height="${inner}" `)}</div></body>`);
  await page.screenshot({ path: new URL(`../public/icons/${name}.png`, import.meta.url).pathname });
}
await browser.close();
