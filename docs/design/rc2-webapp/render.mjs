import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { chromium } from "../../../webapp/node_modules/playwright/index.mjs";

const prototype = new URL("index.html", import.meta.url);
const output = new URL("renderings/", import.meta.url);
const pveDemoUrl = process.env.OPSTEND_PVE_DEMO_URL;
const browser = await chromium.launch();

const captures = [
  ["rc2-betrieb", "", "Betriebsübersicht"],
  ["rc2-eskalation", "view=changes&job=sensorik", "Änderungen"],
  ["rc2-systemuebersicht", "view=overview", "Systemübersicht"],
  ["rc2-ueberwachung", "view=monitoring&monitorHost=host-b", "Überwachung"],
  ["rc2-ueberwachung-mobil", "view=monitoring&host=host-b&monitorHost=host-b", "Überwachung", "dark", { width: 390, height: 844 }],
  ["rc2-dienste", "view=services", "Dienste und Deployments"],
  ["rc2-gast", "view=service&host=nuc-a&serviceId=entwicklung", "Entwicklung"],
  ["rc2-gastanlage", "view=guest-create&host=nuc-a", "Gast aus Vorlage"],
  ["rc2-adapter-einstellungen", "view=service&host=host-b&serviceId=sensorik", "Sensorik"],
  ["rc2-adapter-aenderung", "view=service&host=host-b&serviceId=sensorik", "Sensorik"],
  ["rc2-adapter-wechsel", "view=service&host=host-b&serviceId=sensorik", "Sensorik"],
  ["rc2-inventar", "view=inventory", "Inventar"],
  ["rc2-netzwerk", "view=network", "Netzwerk"],
  ["rc2-netzdetail", "view=network-detail&networkId=services", "VLAN 20 · Dienste"],
  ["rc2-switchport", "view=network-port&host=nuc-a&portId=link-nuc-a", "Port P2"],
  ["rc2-netzregel", "view=network-rule&host=nuc-a&ruleId=storage-nfs", "NFS für Medien"],
  ["rc2-maschine", "view=host&host=nuc-a", "nuc-a"],
  ["rc2-hostwartung", "view=host-maintenance&host=nuc-a", "Hostwartung"],
  ["rc2-platzierung", "view=topology", "Topologie"],
  ["rc2-gesamttopologie", "view=topology&layer=all", "Topologie"],
  ["rc2-verkabelung", "view=topology&layer=physical", "Topologie"],
  ["rc2-netz-dunkel", "view=topology&layer=network", "Topologie", "dark"],
  ["rc2-vpn-zugang", "view=topology&layer=access", "Topologie"],
  ["rc2-aenderungen", "view=changes", "Änderungen"],
  ["rc2-protokoll", "view=events&host=host-b&eventKind=health", "Ereignisprotokoll"],
  ["rc2-freigabe", "view=changes&job=route", "Änderungen"],
  ["rc2-configuration", "view=settings", "Configuration"],
  ["rc2-hostverwaltung", "view=settings&settingsTab=hosts", "Configuration"],
  ["rc2-eigenupdate", "view=settings&settingsTab=updates&host=nuc-a", "Configuration"],
  ["rc2-zorec-shells", "view=settings&settingsTab=ai", "Configuration"],
  ["rc2-zorec-autonomie", "view=settings&settingsTab=ai", "Configuration"],
  ["rc2-zorec-gesten", "view=settings&settingsTab=ai", "Configuration"],
  ["rc2-einstellungen", "view=settings&settingsTab=policies&host=edge-01", "Configuration"],
  ["rc2-backup-dialog", "view=settings&settingsTab=backup", "Configuration"],
  ["rc2-zorec", "view=changes&host=host-b&job=sensorik", "Änderungen"],
  ["rc2-zorec-diagramm", "view=service&serviceId=sensorik&host=host-b", "Sensorik"],
  ["rc2-zorec-aktivitaet", "host=host-b", "Betrieb auf host-b"],
  ["rc2-zorec-aktivitaet-mobil", "view=changes&host=host-b&job=sensorik", "Änderungen", "dark", { width: 390, height: 844 }],
  ["rc2-mobil", "", "Betriebsübersicht", "light", { width: 390, height: 844 }],
];

async function ready(page, route, heading, errors) {
  await page.goto(`${prototype.href}${route ? `#${route}` : ""}`);
  await page.getByRole("heading", { level: 1, name: heading, exact: true }).waitFor();
  if (heading === "Topologie") await page.locator(".topology-graph svg").waitFor();
  await page.waitForFunction(() => Array.from(document.images).every((image) => image.complete && image.naturalWidth > 0));
  await page.evaluate(() => document.fonts.ready);
  assert.deepEqual(errors, []);
}

async function askZorec(dialog, prompt) {
  const question = dialog.getByRole("textbox", { name: "Frage an Zorec" });
  await question.fill(prompt);
  await question.press("Enter");
}

async function queueMaintenance(page) {
  const queue = page.getByRole("button", { name: "Wartung vormerken", exact: true });
  assert.ok(await queue.isDisabled());
  await page.getByRole("checkbox", { name: "Unterbrechung für die aufgeführten Gäste und Dienste bestätigen", exact: true }).check();
  await queue.click();
  await page.getByRole("button", { name: "Auftrag öffnen", exact: true }).waitFor();
}

const resources = (page) => page.getByRole("region", { name: "Auftragsdetails" })
  .getByRole("region", { name: "Betroffene Ressourcen" });

function assertRoute(page, expected) {
  const route = new URLSearchParams(new URL(page.url()).hash.slice(1));
  for (const [key, value] of Object.entries(expected)) assert.equal(route.get(key), value, key);
}

try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, colorScheme: "light" });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await ready(page, "", "Betriebsübersicht", errors);
  await page.getByText("3 erreichbar · 2 Belege offen", { exact: true }).waitFor();
  await page.getByText("40 / 112 GiB", { exact: true }).waitFor();
  await page.getByText(/3 von 5 Hosts mit aktuellen Messwerten · 152 GiB erfasste Gesamtkapazität/).waitFor();
  const decisions = page.getByRole("region", { name: "Anstehende Entscheidungen" });
  await decisions.getByRole("button", { name: "Freigabe prüfen" }).waitFor();
  await page.getByRole("button", { name: "Prüfung verfolgen" }).click();
  await page.getByText("Health-Nachprüfung läuft · seit 14:21:08").waitFor();
  assertRoute(page, { view: "changes", host: "host-b" });
  const destinations = [
    ["Sensorik", "Sensorik", { view: "service", host: "host-b", serviceId: "sensorik" }],
    ["host-b", "host-b", { view: "host", host: "host-b" }],
    ["VLAN 20 · Dienste", "VLAN 20 · Dienste", { view: "network-detail", host: "host-b", networkId: "services" }],
    ["Sensorik in Topologie", "Topologie", { view: "topology", host: "host-b", topologyFocus: "sensorik" }],
  ];
  for (const [label, heading, route] of destinations) {
    await resources(page).getByRole("button", { name: label, exact: true }).press("Enter");
    await page.getByRole("heading", { level: 1, name: heading, exact: true }).waitFor();
    assertRoute(page, route);
    if (route.view === "topology") {
      await page.locator("#topology-inspector").getByRole("heading", { name: "Sensorik", exact: true }).waitFor();
      await page.locator('svg [data-inventory-id="sensorik"][data-selected]').first().waitFor();
      const tabTargets = await page.locator('svg [data-inventory-id][tabindex="0"]').evaluateAll((targets) => targets.map((target) => target.dataset.inventoryId));
      assert.equal(new Set(tabTargets).size, tabTargets.length);
    }
    await page.goBack();
    await resources(page).getByRole("button", { name: "Sensorik", exact: true }).waitFor();
  }
  await resources(page).getByRole("button", { name: "Sensorik im Protokoll", exact: true }).click();
  await page.getByRole("heading", { level: 1, name: "Ereignisprotokoll", exact: true }).waitFor();
  assertRoute(page, { view: "events", host: "host-b", eventSubject: "service:sensorik" });
  await page.reload();
  assert.equal(await page.getByRole("combobox", { name: "Objekt", exact: true }).inputValue(), "service:sensorik");
  const alert = page.getByRole("listitem").filter({ has: page.getByRole("heading", { name: "Störung erkannt", exact: true }) });
  await alert.getByRole("button", { name: "Auftrag öffnen", exact: true }).click();
  await page.locator('[data-job-event-row][aria-current="true"]').getByText("Störung erkannt", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Betrieb", exact: true }).click();
  await page.getByRole("combobox", { name: "Geltungsbereich" }).selectOption("nuc-a");
  await page.getByText("Keine offenen Störungen.", { exact: true }).waitFor();
  await decisions.getByRole("button", { name: "Freigabe prüfen" }).click();
  await resources(page).getByRole("button", { name: "WireGuard · Tunnel", exact: true }).click();
  await page.locator("#topology-inspector").getByRole("heading", { name: "WireGuard · Tunnel", exact: true }).waitFor();
  assertRoute(page, { view: "topology", host: "edge-01", layer: "access", topologyFocus: "edge-tunnel" });
  await page.reload();
  await page.locator("#topology-inspector").getByRole("heading", { name: "WireGuard · Tunnel", exact: true }).waitFor();
  await page.locator('svg [data-inventory-id="edge-tunnel"][data-selected]').first().waitFor();
  await page.goBack();
  await page.getByRole("button", { name: "In der Demo freigeben" }).click();
  await page.getByText("Entscheidung im Browser gespeichert", { exact: true }).waitFor();
  await page.reload();
  await page.getByText("Entscheidung im Browser gespeichert", { exact: true }).waitFor();
  await resources(page).getByRole("button", { name: "WireGuard · Tunnel", exact: true }).waitFor();
  await page.getByRole("button", { name: "Betrieb", exact: true }).click();
  await decisions.getByText("Keine Entscheidung ausstehend.", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Systemübersicht", exact: true }).click();
  await page.getByRole("heading", { level: 1, name: "Systemübersicht" }).waitFor();
  await page.getByRole("button", { name: "Gesamttopologie öffnen" }).click();
  await page.locator(".topology-graph svg").waitFor();
  assert.equal(await page.locator(".topology-tabs input:checked").count(), 3);
  await ready(page, "view=topology&layer=network", "Topologie", errors);
  await page.getByRole("button", { name: "Dunkles Farbschema aktivieren" }).click();
  await page.locator('html[data-theme="dark"] .topology-graph svg').waitFor();
  await page.getByRole("button", { name: "Helles Farbschema aktivieren" }).click();
  await page.getByRole("combobox", { name: "Geltungsbereich" }).selectOption("edge-01");
  await page.getByRole("button", { name: "Configuration", exact: true }).click();
  await page.locator('button[data-settings-tab="policies"]').click();
  await page.getByText("Sonntag, 04:00–05:00", { exact: true }).waitFor();
  await page.reload();
  assert.equal(await page.locator("#scope").inputValue(), "edge-01");
  await page.getByRole("combobox", { name: "Geltungsbereich" }).selectOption("");
  const search = page.getByRole("textbox", { name: "Ressourcen suchen" });
  await search.fill("ensorik");
  await search.press("Enter");
  await page.getByText("1 von 20 Ressourcen", { exact: false }).waitFor();
  await page.getByRole("button", { name: "Sensorik", exact: true }).click();
  await page.getByRole("heading", { level: 1, name: "Sensorik", exact: true }).waitFor();
  assert.deepEqual(errors, []);
  await page.close();

  const publication = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  publication.on("pageerror", (error) => errors.push(error.message));
  await ready(publication, "view=overview&host=host-b", "Systemübersicht", errors);
  await publication.getByRole("button", { name: "HTTPS-Veröffentlichungen", exact: true }).click();
  const catalog = publication.getByRole("region", { name: "HTTPS-Veröffentlichungen", exact: true });
  await publication.locator("#network-publications:focus").waitFor();
  await catalog.getByRole("button", { name: "HTTPS-Freigabe für Medien", exact: true }).click();
  assertRoute(publication, { view: "access-detail", host: "host-b", publicationId: "medien-publication" });
  await publication.getByRole("button", { name: "Auftrag öffnen", exact: true }).click();
  await publication.getByRole("button", { name: "In der Demo freigeben", exact: true }).click();
  await publication.getByRole("button", { name: "Veröffentlichung simulieren", exact: true }).click();
  await publication.getByText("Externe HTTPS-Prüfung ausstehend", { exact: true }).waitFor();
  await publication.getByRole("button", { name: "Externen HTTPS-Abruf fehlgeschlagen simulieren", exact: true }).click();
  await publication.getByText("Externe HTTPS-Prüfung fehlgeschlagen", { exact: true }).first().waitFor();
  await publication.getByRole("button", { name: "Externen HTTPS-Abruf erfolgreich simulieren", exact: true }).click();
  await publication.getByRole("button", { name: "Zugangspfad öffnen", exact: true }).click();
  const proof = publication.getByRole("region", { name: "Externer HTTPS-Abruf", exact: true });
  await proof.getByText("Simulierter Abruf erfolgreich", { exact: true }).waitFor();
  await publication.screenshot({ path: fileURLToPath(new URL("rc2-https-veroeffentlichung.png", output)), fullPage: true, animations: "disabled" });
  await publication.getByRole("button", { name: "Veröffentlichung in Topologie", exact: true }).click();
  await publication.locator("#topology-inspector").getByRole("heading", { name: "HTTPS Medien · Simuliert erreichbar", exact: true }).waitFor();
  await publication.locator('svg [data-inventory-id="edge-tunnel"]').first().waitFor();
  await publication.goBack();
  await publication.getByRole("button", { name: "Auftrag öffnen", exact: true }).click();
  await publication.getByRole("button", { name: "Veröffentlichung zurücknehmen", exact: true }).click();
  await publication.getByText("Der Browser hat die Rücknahme simuliert und gespeichert.", { exact: true }).waitFor();
  assert.deepEqual(errors, []);
  await publication.close();

  const runtime = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  runtime.on("pageerror", (error) => errors.push(error.message));
  await ready(runtime, "view=service&host=nuc-a&serviceId=entwicklung", "Entwicklung", errors);
  await runtime.getByRole("button", { name: "Geordnet stoppen", exact: true }).click();
  await runtime.getByRole("button", { name: "In der Demo bestätigen", exact: true }).click();
  await runtime.getByRole("button", { name: "Antwortverlust simulieren", exact: true }).click();
  await runtime.getByRole("button", { name: "Auftrag abgleichen", exact: true }).waitFor();
  await runtime.screenshot({ path: fileURLToPath(new URL("rc2-gastauftrag.png", output)), fullPage: true, animations: "disabled" });
  await runtime.reload();
  await runtime.getByRole("button", { name: "Auftrag abgleichen", exact: true }).click();
  await runtime.getByRole("button", { name: "Ausführungserfolg simulieren", exact: true }).click();
  const readRuntime = () => runtime.evaluate(() => {
    const demo = window.opstendDemo;
    return demo.serviceRuntime(demo.getInventory().services.find(({ id }) => id === "entwicklung"));
  });
  await runtime.getByRole("button", { name: "Gastzustand bestätigen", exact: true }).waitFor();
  assert.equal(await readRuntime(), "running");
  await runtime.getByRole("button", { name: "Gastzustand bestätigen", exact: true }).click();
  await runtime.locator(".manage-outcome").getByText("Zielzustand bestätigt", { exact: true }).waitFor();
  assert.equal(await readRuntime(), "stopped");
  await runtime.getByRole("button", { name: "Laufzeitereignisse öffnen", exact: true }).click();
  assertRoute(runtime, { view: "events", host: "nuc-a", eventKind: "runtime", eventSubject: "service:entwicklung" });
  assert.deepEqual(errors, []);
  await runtime.close();

  const clock = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  clock.on("pageerror", (error) => errors.push(error.message));
  await ready(clock, "", "Betriebsübersicht", errors);
  await clock.getByRole("button", { name: "Zorec fragen", exact: true }).click();
  const clockChat = clock.getByRole("dialog", { name: "Zorec", exact: true });
  const clockOffer = clockChat.getByRole("button", { name: "Zeitsynchronisation prüfen", exact: true });
  await askZorec(clockChat, "haben die Services alle gesyncte Zeiten?");
  await clockOffer.waitFor();
  assert.equal(await clockChat.getByText(/Simulierte Zeitproben/).count(), 0);
  await clock.reload();
  await clock.getByRole("button", { name: "Zorec fragen", exact: true }).click();
  await clockOffer.waitFor();
  await askZorec(clockChat, "Ja, bitte prüfen");
  const clockSummary = clockChat.locator(".chat-answer").last();
  await clockSummary.getByText(/Simulierte Zeitproben/).waitFor();
  assert.match(await clockSummary.innerText(), /6 synchronisiert · 2 mit Abweichung · 2 ohne Messwert · 2 ohne registrierte Probe/);
  await clockChat.getByRole("button", { name: "Zorec schließen", exact: true }).click();
  await clock.getByRole("combobox", { name: "Geltungsbereich" }).selectOption("host-b");
  await clock.getByRole("button", { name: "Zorec fragen", exact: true }).click();
  await clockOffer.click();
  await clockChat.getByText(/Die Auswahl hat sich geändert/).waitFor();
  assert.equal(await clockChat.getByText(/Simulierte Zeitproben/).count(), 1);
  await clock.close();

  const mobile = await browser.newPage({ viewport: { width: 320, height: 760 }, isMobile: true, hasTouch: true, colorScheme: "dark" });
  mobile.on("pageerror", (error) => errors.push(error.message));
  await ready(mobile, "host=host-b", "Betrieb auf host-b", errors);
  await mobile.getByRole("button", { name: "Prüfung verfolgen" }).tap();
  await mobile.locator("#manage-job-title:focus").waitFor();
  await mobile.getByRole("button", { name: "Zur Auftragsliste", exact: true }).tap();
  await mobile.locator("#manage-jobs-title:focus").waitFor();
  await resources(mobile).getByRole("button", { name: "Sensorik im Protokoll", exact: true }).waitFor();
  assert.ok(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await resources(mobile).getByRole("button", { name: "Sensorik im Protokoll", exact: true }).tap();
  assertRoute(mobile, { view: "events", host: "host-b", eventSubject: "service:sensorik" });
  assert.deepEqual(errors, []);
  await ready(mobile, "view=service&serviceId=sensorik&host=host-b", "Sensorik", errors);
  await mobile.getByRole("button", { name: "Zorec fragen", exact: true }).tap();
  const mobileChat = mobile.getByRole("dialog", { name: "Zorec", exact: true });
  await askZorec(mobileChat, "Erstelle ein Sequenzdiagramm für Sensorik.");
  const viewDiagram = mobileChat.getByRole("button", { name: "Diagramm ansehen", exact: true });
  await viewDiagram.tap();
  const mobileDiagram = mobileChat.getByRole("region", { name: "Diagramm", exact: true });
  await mobileDiagram.locator("[data-zorec-diagram-viewport] svg").waitFor();
  const diagramBounds = await mobileDiagram.boundingBox();
  assert.ok(diagramBounds.x >= 0 && diagramBounds.x + diagramBounds.width <= 320);
  assert.equal(await mobileChat.getByRole("log").count(), 0);
  await mobileDiagram.getByRole("button", { name: "Diagramm schließen" }).tap();
  await mobileChat.locator("[data-diagram-turn]:focus").waitFor();
  await mobileChat.getByRole("textbox", { name: "Frage an Zorec" }).waitFor();
  await askZorec(mobileChat, "Gleichen unsere Dienste ihre Uhren ab?");
  await mobileChat.getByRole("button", { name: "Zeitsynchronisation prüfen", exact: true }).tap();
  const inspection = mobileChat.locator(".chat-answer").last();
  await inspection.getByText(/Simulierte Zeitproben/).waitFor();
  assert.match(await inspection.innerText(), /Sensorik \(host-b\) · Synchronisiert/);
  assert.doesNotMatch(await inspection.innerText(), /Entwicklung \(nuc-a\)/);
  assert.deepEqual(errors, []);
  await mobile.close();

  const maintenance = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  maintenance.on("pageerror", (error) => errors.push(error.message));
  await ready(maintenance, "view=host&host=nuc-a", "nuc-a", errors);
  await maintenance.getByRole("button", { name: "Wartung planen", exact: true }).click();
  await maintenance.getByText(/GPU mit HDMI und USB-Gerät/).waitFor();
  await queueMaintenance(maintenance);
  await maintenance.getByRole("button", { name: "Auftrag öffnen", exact: true }).click();
  await maintenance.getByRole("button", { name: "Wartung freigeben", exact: true }).click();
  await maintenance.getByRole("button", { name: "Neustart im Fenster simulieren", exact: true }).click();
  await maintenance.getByRole("button", { name: "Wiederanlauf simulieren", exact: true }).waitFor();
  await maintenance.reload();
  await maintenance.getByRole("button", { name: "Wiederanlauf simulieren", exact: true }).click();
  await maintenance.getByText("Die Health-Prüfung der gestarteten Dienste steht aus.", { exact: true }).first().waitFor();
  await maintenance.getByRole("button", { name: "Wartung im Protokoll", exact: true }).click();
  assert.equal(await maintenance.getByRole("combobox", { name: "Ereignistyp", exact: true }).inputValue(), "maintenance");
  await maintenance.close();

  const autonomy = await browser.newPage({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  autonomy.on("pageerror", (error) => errors.push(error.message));
  await ready(autonomy, "view=settings&settingsTab=ai", "Configuration", errors);
  const autonomous = autonomy.getByRole("switch", { name: "Vollautonomer Modus", exact: true });
  assert.ok(await autonomous.isDisabled());
  const edit = autonomy.getByRole("form", { name: "Admin Edit", exact: true });
  await edit.locator('[name="enabled"]').check();
  await edit.getByRole("combobox", { name: "Schreibumfang" }).selectOption("operate");
  await edit.locator('[name="automation"]').check();
  await edit.getByRole("button", { name: "Profil speichern", exact: true }).click();
  await autonomous.check();
  await ready(autonomy, "view=host-maintenance&host=edge-01", "Hostwartung", errors);
  await autonomy.getByText("Sonntag, 04:00–05:00", { exact: true }).waitFor();
  await queueMaintenance(autonomy);
  await autonomy.getByRole("button", { name: "Auftrag öffnen", exact: true }).tap();
  await autonomy.getByRole("button", { name: "Neustart im Fenster simulieren", exact: true }).waitFor();
  await ready(autonomy, "view=changes&host=host-b&job=sensorik", "Änderungen", errors);
  const failProbe = autonomy.getByRole("button", { name: "Prüfung fehlgeschlagen simulieren", exact: true });
  const decision = autonomy.getByRole("region", { name: "Zorecs Entscheidung", exact: true });
  await failProbe.tap();
  await decision.getByText("Health-Nachprüfung angestoßen", { exact: true }).waitFor();
  await decision.getByText("Registrierter Health-Pfad von Sensorik · simulierte Prüfung", { exact: true }).waitFor();
  await decision.evaluate((panel) => panel.scrollIntoView({ block: "center" }));
  await decision.screenshot({ path: fileURLToPath(new URL("rc2-zorec-entscheidung.png", output)), animations: "disabled" });
  await autonomy.reload();
  await decision.getByText("Das simulierte Ergebnis steht aus.", { exact: true }).waitFor();
  await failProbe.tap();
  await decision.getByText("Für diesen Vorfall wurde bereits eine weitere Health-Prüfung gestartet.", { exact: true }).waitFor();
  await autonomy.getByRole("button", { name: "Erneute Prüfung anstoßen", exact: true }).waitFor();
  const recovery = await autonomy.evaluate(() => window.opstendDemo.recoveryFor(window.opstendDemo.getInventory().services.find(({ id }) => id === "sensorik")));
  assert.deepEqual(recovery.events.map(({ action, actor }) => [action, actor || ""]), [["probe-fail", ""], ["retry", "zorec"], ["probe-fail", ""]]);
  await ready(autonomy, "view=settings&settingsTab=ai", "Configuration", errors);
  await autonomy.getByText("Angekündigtes Wartungsfenster", { exact: true }).waitFor();
  assert.ok(await autonomy.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await autonomous.uncheck();
  await autonomy.getByText("Wirksam · aus", { exact: true }).waitFor();
  assert.deepEqual(errors, []);
  await autonomy.close();

  if (pveDemoUrl) {
    const pve = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    pve.on("pageerror", (error) => errors.push(error.message));
    await pve.goto(new URL("#view=inventory", pveDemoUrl).href);
    await pve.getByRole("button", { name: "Proxmox-Inventar", exact: true }).click();
    const guests = pve.getByRole("region", { name: "Gäste", exact: true });
    await guests.getByRole("button", { name: "Medien", exact: true }).waitFor();
    await pve.screenshot({ path: fileURLToPath(new URL("rc2-pve-inventar.png", output)), fullPage: true, animations: "disabled" });
    await guests.getByRole("button", { name: "Medien", exact: true }).click();
    await pve.getByRole("region", { name: "Messwerte", exact: true }).getByText(/^0\s*%$/).first().waitFor();
    await pve.getByRole("region", { name: "Native PVE-Tasks", exact: true }).waitFor();
    await pve.screenshot({ path: fileURLToPath(new URL("rc2-pve-gastbelege.png", output)), fullPage: true, animations: "disabled" });
    const profile = pve.getByRole("combobox", { name: "Demo-Lesestand", exact: true });
    await profile.selectOption("restricted");
    await pve.getByText("Gast im Lesebereich nicht verfügbar.", { exact: true }).waitFor();
    assert.doesNotMatch(await pve.locator("#content").innerText(), /Medien|201/);
    await profile.selectOption("stale");
    await pve.getByText("Snapshot veraltet", { exact: true }).waitFor();
    assert.equal(await pve.getByRole("region", { name: "Messwerte", exact: true }).count(), 0);
    assert.deepEqual(errors, []);
    await pve.close();
  }

  for (const [name, route, heading, scheme = "light", viewport = { width: 1440, height: 1000 }] of captures) {
    const screenshot = await browser.newPage({ viewport, colorScheme: scheme });
    const failures = [];
    screenshot.on("pageerror", (error) => failures.push(error.message));
    await ready(screenshot, route, heading, failures);
    if (name === "rc2-zorec-autonomie") {
      const settings = screenshot.getByRole("region", { name: "Vollautonomer Modus", exact: true });
      await settings.screenshot({ path: fileURLToPath(new URL(`${name}.png`, output)), animations: "disabled" });
      await screenshot.close();
      continue;
    }
    if (name === "rc2-netzregel") {
      await screenshot.getByRole("combobox", { name: "Wirkung", exact: true }).selectOption("block");
      await screenshot.getByRole("button", { name: "Änderung prüfen", exact: true }).click();
      await screenshot.getByRole("heading", { name: "Regeländerung prüfen", exact: true }).waitFor();
      await screenshot.getByRole("region", { name: "Konfigurationswirkung" }).getByText("Erlauben", { exact: true }).waitFor();
      await screenshot.getByRole("region", { name: "Verbindungsbeleg" }).getByText("Verbindungsprüfung", { exact: true }).waitFor();
    }
    if (name === "rc2-eskalation") {
      await screenshot.getByRole("button", { name: "Prüfung fehlgeschlagen simulieren" }).click();
      await screenshot.getByRole("button", { name: "Betrieb", exact: true }).click();
      await screenshot.getByRole("heading", { name: "Sensorik erneut prüfen" }).waitFor();
    }
    if (name.startsWith("rc2-ueberwachung")) {
      await screenshot.getByRole("heading", { name: "host-b · CPU-Auslastung", exact: true }).waitFor();
      assert.equal(await screenshot.locator(".monitor-trace-cpu polyline").count(), 2);
    }
    if (name === "rc2-adapter-aenderung") {
      await screenshot.locator('input[name="intervalSeconds"]').fill("75");
      await screenshot.getByRole("button", { name: "Änderung prüfen", exact: true }).click();
      await screenshot.getByRole("heading", { name: "Änderung zum Speichern prüfen" }).waitFor();
      await screenshot.getByRole("cell", { name: "75", exact: true }).waitFor();
    }
    if (name === "rc2-adapter-wechsel") {
      await screenshot.getByRole("button", { name: "Adapter aktualisieren", exact: true }).click();
      await screenshot.getByRole("heading", { name: "Adapter-Update prüfen" }).waitFor();
      await screenshot.getByRole("cell", { name: "Neue Vorgabe", exact: true }).waitFor();
    }
    if (name === "rc2-zorec-gesten") {
      await screenshot.getByRole("combobox", { name: "Reaktion" }).selectOption("embarrassed");
      await screenshot.locator('[data-zorec-preview-mark] [data-mood="embarrassed"]').waitFor();
    }
    if (name === "rc2-hostverwaltung") {
      await screenshot.getByRole("button", { name: "Host hinzufügen", exact: true }).click();
      await screenshot.getByRole("button", { name: "Bestand mit Zorec prüfen", exact: true }).click();
      await screenshot.getByRole("group", { name: "Ressourcen für OpsTend freigeben" }).waitFor();
    }
    if (name === "rc2-eigenupdate") {
      await screenshot.getByRole("button", { name: "Nach Release suchen", exact: true }).click();
      await screenshot.getByRole("button", { name: "Patches sichern und abgleichen", exact: true }).click();
      await screenshot.getByRole("heading", { name: "Patch-Abgleich", exact: true }).waitFor();
    }
    if (name === "rc2-zorec" || name.startsWith("rc2-zorec-aktivitaet")) {
      await screenshot.getByRole("button", { name: "Zorec fragen" }).click();
      const contextSuggestions = screenshot.getByRole("group", { name: "Auf dieser Seite" });
      const isJob = route.startsWith("view=changes");
      const prompt = isJob ? contextSuggestions.getByRole("button", { name: "Nachprüfung erklären" })
        : screenshot.getByRole("button", { name: "Offene Vorgänge" });
      await prompt.click();
      await screenshot.getByRole("log").getByText(isJob ? "registrierten Health-Pfad" : "Zorec prüft den Wiederanlauf", { exact: false }).waitFor();
      if (name !== "rc2-zorec") {
        await screenshot.getByRole("button", { name: "Ablauf ansehen" }).click();
        await screenshot.getByRole("region", { name: "Aktivitätskonsole" }).getByText(isJob ? "Auftragsstand lesen" : "Offene Vorgänge abgleichen").waitFor();
      }
    }
    if (name === "rc2-zorec-diagramm") {
      const launcher = screenshot.getByRole("button", { name: "Zorec fragen", exact: true });
      await launcher.click();
      const dialog = screenshot.getByRole("dialog", { name: "Zorec", exact: true });
      const diagram = dialog.getByRole("region", { name: "Diagramm", exact: true });
      await askZorec(dialog, "Erstelle ein Sequenzdiagramm für Sensorik.");
      await diagram.getByText("Sequenz · Version 1", { exact: true }).waitFor();
      const chatBounds = await dialog.locator(".zorec-chat").boundingBox();
      assert.ok((await diagram.boundingBox()).x >= chatBounds.x + chatBounds.width - 1);
      assert.equal(await dialog.getByRole("log").locator("svg").count(), 0);
      await diagram.getByRole("combobox", { name: "Diagrammtyp" }).selectOption("component");
      await diagram.getByText("Komponenten · Version 1", { exact: true }).waitFor();
      await askZorec(dialog, "Ergänze das Diagramm um einen Health-Prüfschritt.");
      await diagram.getByText("Komponenten · Version 2", { exact: true }).waitFor();
      await dialog.getByRole("button", { name: "Aktivität", exact: true }).click();
      await dialog.getByRole("region", { name: "Aktivitätskonsole" }).waitFor();
      await dialog.getByRole("button", { name: "Diagramm", exact: true }).click();
      await diagram.getByText("Komponenten · Version 2", { exact: true }).waitFor();
      const question = dialog.getByRole("textbox", { name: "Frage an Zorec" });
      await question.fill("Mein Entwurf bleibt erhalten.");
      await screenshot.mouse.click(5, 5);
      await dialog.waitFor({ state: "hidden" });
      await screenshot.locator("[data-open-zorec]:focus").waitFor();
      await launcher.click();
      assert.equal(await question.inputValue(), "Mein Entwurf bleibt erhalten.");
      await dialog.getByRole("log").getByText("Ich habe das Diagramm auf Version 2 aktualisiert.", { exact: true }).waitFor();
      await question.fill("");
      await dialog.getByRole("button", { name: "Diagramm", exact: true }).click();
      await diagram.locator('svg [data-excaliplant-hook-id="check"]').first().waitFor();
    }
    assert.equal(await screenshot.locator("html").getAttribute("data-theme"), scheme);
    assert.ok(await screenshot.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${name} has horizontal overflow`);
    if (name === "rc2-mobil") {
      for (const selector of [".nav-list", ".ops-grid .table-wrap"]) {
        assert.ok(await screenshot.locator(selector).evaluate((element) => element.scrollWidth <= element.clientWidth), `${selector} has horizontal overflow`);
      }
    }
    await screenshot.screenshot({ path: fileURLToPath(new URL(`${name}.png`, output)), fullPage: true, animations: "disabled" });
    if (name === "rc2-zorec") {
      const chat = screenshot.getByRole("dialog", { name: "Zorec", exact: true });
      const question = chat.getByRole("textbox", { name: "Frage an Zorec" });
      await question.fill("Navigier mich zu der seite wo ich deine berechtigungen ändern kann?");
      await question.press("Enter");
      await chat.getByRole("log").getByText("Ich habe Zorec und KI geöffnet.", { exact: true }).waitFor();
      await chat.getByRole("button", { name: "Aktive Shell erklären", exact: true }).waitFor();
      await chat.getByRole("button", { name: "Offene Vorgänge", exact: true }).waitFor();
      assert.equal(new URLSearchParams(new URL(screenshot.url()).hash.slice(1)).get("settingsTab"), "ai");
    }
    await screenshot.close();
    console.log(name);
  }
} finally {
  await browser.close();
}
