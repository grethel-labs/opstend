(function () {
  "use strict";

  const data = window.opstendMonitoringData;
  const locale = window.opstendLocale;
  const language = () => locale?.ui() ?? "de";
  const t = (de, en, lang = language()) => lang === "en" ? en : de;
  const timeZone = "Europe/Berlin";
  const formatters = Object.fromEntries([['de', 'de-DE'], ['en', 'en-GB']].map(([id, localeId]) => [id, {
    time: new Intl.DateTimeFormat(localeId, { timeZone, hour: "2-digit", minute: "2-digit" }),
    date: new Intl.DateTimeFormat(localeId, { timeZone, day: "2-digit", month: "2-digit" }),
    number: new Intl.NumberFormat(localeId, { maximumFractionDigits: 2 }),
  }]));
  const periods = {
    "1h": ["Letzte Stunde", "Last hour"], "6h": ["Letzte 6 Stunden", "Last 6 hours"], "24h": ["Letzte 24 Stunden", "Last 24 hours"],
  };
  const metricEnglish = { cpu: "CPU usage", ram: "Memory used", storage: "Local storage used" };
  const sourceEnglish = { "PVE-API": "PVE API", "Linux-Agent": "Linux agent", "Hostaufnahme · Messquelle offen": "Host enrollment · monitoring source pending" };
  const freshness = {
    current: { label: ["Aktuell", "Current"], tone: "good", rank: 2 },
    stale: { label: ["Veraltet", "Stale"], tone: "warn", rank: 1 },
    missing: { label: ["Keine Messung", "No reading"], tone: "", rank: 0 },
  };
  const selectedFormat = (lang = language()) => formatters[lang === "en" ? "en" : "de"];
  const textValue = (value, lang) => value === null ? "—" : `${selectedFormat(lang).number.format(value)} %`;
  const formatTime = (at, lang) => selectedFormat(lang).time.format(at);
  const formatDate = (at, lang) => selectedFormat(lang).date.format(at);
  const metricLabel = (id, lang) => t(data.metrics[id].label, metricEnglish[id], lang);
  const sourceLabel = (source, lang) => source ? t(source, Object.hasOwn(sourceEnglish, source) ? sourceEnglish[source] : source, lang)
    : t("Messquelle offen", "Monitoring source pending", lang);

  function topValue(reading) {
    return reading.samples.reduce((max, sample) => sample.value === null ? max : Math.max(max ?? 0, sample.value), null);
  }

  function scopeReadings(state, metric, period) {
    return state.inventory.hosts.filter((target) => !state.host || target.id === state.host).map((target) => {
      const reading = data.read(state, target.id, metric, period);
      return { target, reading, peak: topValue(reading) };
    });
  }

  function readingNote(reading, lang) {
    if (reading.latestAt === null) return t("Keine Messung im Zeitraum", "No readings in this period", lang);
    const label = reading.freshness === "stale" ? t("Letzter bekannter Wert", "Last known reading", lang)
      : t("Letzte Messung", "Latest reading", lang);
    const day = formatDate(reading.latestAt, lang);
    const measurementTime = formatTime(reading.latestAt, lang);
    return `${label} · ${day === formatDate(data.asOf, lang) ? measurementTime : `${day} ${measurementTime}`}`;
  }

  function sourceSummary(state, metric = "cpu", period = "1h", lang) {
    const readings = scopeReadings(state, metric, period);
    if (!readings.length) return t("Keine Hosts im Geltungsbereich", "No hosts in scope", lang);
    const counts = { current: 0, stale: 0, missing: 0 };
    for (const { reading } of readings) counts[reading.freshness]++;
    const fragments = [t(`${counts.current} aktuell`, `${counts.current} current`, lang)];
    if (counts.stale) fragments.push(t(`${counts.stale} veraltet`, `${counts.stale} stale`, lang));
    if (counts.missing) fragments.push(t(`${counts.missing} ohne Messung`, `${counts.missing} with no readings`, lang));
    return fragments.join(" · ");
  }

  function plot(series, period, label) {
    const left = 34;
    const right = 480;
    const bottom = 120;
    const height = 100;
    const start = data.asOf - data.periods[period] * 60_000;
    const x = (at) => left + (at - start) * (right - left) / (data.asOf - start);
    const y = (value) => bottom - value * height / 100;
    const grid = [0, 25, 50, 75, 100].map((value) => `<line x1="${left}" x2="${right}" y1="${y(value)}" y2="${y(value)}"/>
      <text x="${left - 4}" y="${y(value) + 4}" text-anchor="end">${value} %</text>`).join("");
    const seriesLines = series.map(({ reading, id }) => {
      const segments = [];
      let line = [];
      for (const sample of reading.samples) {
        if (sample.value === null) {
          if (line.length) segments.push(line);
          line = [];
        } else line.push([x(sample.at).toFixed(2), y(sample.value).toFixed(2)]);
      }
      if (line.length) segments.push(line);
      return `<g class="monitor-trace monitor-trace-${id}">${segments.map((segment) => segment.length > 1
        ? `<polyline points="${segment.map((point) => point.join(",")).join(" ")}"/>`
        : `<circle cx="${segment[0][0]}" cy="${segment[0][1]}" r="2.6"/>`).join("")}</g>`;
    }).join("");
    const startLabel = period === "1h" ? formatTime(start) : `${formatDate(start)} ${formatTime(start)}`;
    return `<svg class="monitor-plot" viewBox="0 0 500 150" role="img" aria-label="${label}">
      <g class="monitor-grid">${grid}<text x="${left}" y="141">${startLabel}</text>
        <text x="${right}" y="141" text-anchor="end">${formatTime(data.asOf)}</text></g>
      ${seriesLines}</svg>`;
  }

  function chooser(state) {
    const options = (items, selected) => Object.entries(items).map(([id, label]) => `<option value="${id}" ${id === selected ? "selected" : ""}>${label}</option>`).join("");
    const metricOptions = Object.fromEntries(Object.keys(data.metrics).map((id) => [id, metricLabel(id)]));
    const periodOptions = Object.fromEntries(Object.entries(periods).map(([id, label]) => [id, t(...label)]));
    const measurementTime = `${formatDate(data.asOf)} · ${formatTime(data.asOf)}`;
    return `<div class="panel monitor-filters">
      <label for="monitor-metric">${t("Messgröße", "Metric")}</label><select id="monitor-metric">${options(metricOptions, state.monitorMetric)}</select>
      <label for="monitor-period">${t("Zeitraum", "Period")}</label><select id="monitor-period">${options(periodOptions, state.monitorPeriod)}</select>
      <small>${t(`Demo-Messstand ${measurementTime} Uhr`, `Demo data as of ${measurementTime}`)}</small>
    </div>`;
  }

  function valueTable(reading) {
    return `<details class="monitor-samples"><summary>${t("Messpunkte als Tabelle", "Show readings as table")}</summary>
      <div class="table-wrap" tabindex="0" aria-label="${t("Messpunkte im gewählten Zeitraum", "Readings in the selected period")}"><table class="data-table">
        <thead><tr><th scope="col">${t("Messzeit", "Time")}</th><th scope="col">${t("Wert", "Value")}</th></tr></thead>
        <tbody>${reading.samples.toReversed().map(({ at, value }) => `<tr><td><time datetime="${new Date(at).toISOString()}">${formatDate(at)} ${formatTime(at)}</time></td>
          <td>${value === null ? t(...freshness.missing.label) : textValue(value)}</td></tr>`).join("")}</tbody>
      </table></div></details>`;
  }

  function seriesPanel(state, row) {
    if (!row) return "";
    const { reading, target, peak } = row;
    const { escape, monitorMetric: metric, monitorPeriod: period } = state;
    const name = escape(target.name);
    const id = escape(target.id);
    const label = metricLabel(metric);
    const status = freshness[reading.freshness];
    const cases = window.opstendViews.attention({ ...state, host: target.id }).filter((job) => job.attention.kind === "incident");
    const latest = textValue(reading.latestValue);
    const peakLabel = textValue(peak);
    const received = reading.samples.filter((sample) => sample.value !== null).length;
    const chartLabel = t(`${name}, ${label}, zuletzt ${latest}, Spitze ${peakLabel}.`, `${name}, ${label}, latest ${latest}, peak ${peakLabel}.`);
    const olderReading = peak === null && period !== "24h" && data.read(state, target.id, metric, "24h").latestAt !== null;
    return `<section class="panel monitor-series" aria-labelledby="monitor-series-title">
      <div class="panel-head"><div><h2 id="monitor-series-title" tabindex="-1">${name} · ${label}</h2>
        <p>${escape(sourceLabel(reading.source))} · ${readingNote(reading)}</p></div>${state.badge(t(...status.label), status.tone)}</div>
      <div class="monitor-summary"><div><span>${t("Letzter Messwert", "Latest reading")}</span><strong>${latest}</strong></div>
        <div><span>${t("Spitze im Zeitraum", "Peak in this period")}</span><strong>${peakLabel}</strong></div>
        <div><span>${t("Empfangene Messpunkte", "Received samples")}</span><strong>${received} / ${reading.samples.length}</strong></div></div>
      ${peak === null ? `<p class="panel-pad compact">${t("Für diesen Zeitraum liegen keine Demo-Messwerte vor.", "There are no demo readings for this period.")}
        ${olderReading ? t("Wähle einen längeren Zeitraum für ältere Werte.", "Choose a longer period to see older readings.") : ""}</p>`
        : plot([{ reading, id: metric }], period, chartLabel)}
      ${reading.samples.length ? valueTable(reading) : ""}
      <div class="monitor-context service-tools"><button type="button" class="button" data-view="host" data-host="${id}">${t("Maschine öffnen", "Open host")}</button>
        <button type="button" class="button" data-view="events" data-host="${id}">${t(`Protokoll auf ${name}`, `Event log for ${name}`)}</button>
        ${cases.map((job) => `<button type="button" class="text-button" data-view="changes" data-host="${id}" data-job="${escape(job.id)}">${escape(window.opstendViews.displayAttention(job).action)}</button>`).join("")}</div>
    </section>`;
  }

  function comparison(state, rows, selected) {
    return `<section class="panel monitor-hosts" aria-labelledby="monitor-hosts-title">
      <div class="panel-head"><div><h2 id="monitor-hosts-title">${state.host ? t("Datenquelle", "Data source") : t("Hostvergleich", "Host comparison")}</h2>
        <p>${state.host ? t("Messstand der ausgewählten Maschine", "Readings for the selected host") : t("Fehlende und veraltete Messwerte zuerst", "Missing and stale readings first")}</p></div></div>
      ${rows.length ? `<div class="table-wrap" tabindex="0" aria-label="${t("Messwerte je Host", "Readings by host")}"><table class="data-table"><thead>
        <tr><th scope="col">Host</th><th scope="col">${t("Letzter Wert", "Latest")}</th><th scope="col">${t("Spitze", "Peak")}</th><th scope="col">${t("Messstand", "Data status")}</th></tr></thead><tbody>
        ${rows.map(({ target, reading, peak }) => {
          const status = freshness[reading.freshness];
          return `<tr><th scope="row"><button class="text-button" type="button" data-monitor-host="${state.escape(target.id)}" aria-pressed="${selected === target.id}">${state.escape(target.name)}</button>
            <small>${state.escape(sourceLabel(reading.source))}</small></th><td>${textValue(reading.latestValue)}</td><td>${textValue(peak)}</td>
            <td>${state.badge(t(...status.label), status.tone)}<small>${reading.latestAt === null ? t("Im gewählten Zeitraum", "In the selected period") : formatTime(reading.latestAt)}</small></td></tr>`;
        }).join("")}</tbody></table></div>` : `<p class="panel-pad compact">${t("Im gewählten Bereich ist kein Host erfasst.", "No hosts are listed in this scope.")}</p>`}
    </section>`;
  }

  function monitoring(state) {
    const rows = scopeReadings(state, state.monitorMetric, state.monitorPeriod);
    rows.sort((a, b) => freshness[a.reading.freshness].rank - freshness[b.reading.freshness].rank
      || (b.reading.latestValue ?? -1) - (a.reading.latestValue ?? -1) || a.target.name.localeCompare(b.target.name));
    const selected = rows.find((row) => row.target.id === state.monitorHost)
      || rows.find((row) => row.reading.freshness === "current") || rows.find((row) => row.reading.latestValue !== null) || rows[0];
    return `<header class="page-intro"><p class="eyebrow">${state.escape(state.host || t("Ganze Flotte", "Entire fleet"))}</p><h1>${t("Überwachung", "Monitoring")}</h1></header>
      ${chooser(state)}<div class="monitor-layout">${comparison(state, rows, selected?.target.id)}${seriesPanel(state, selected)}</div>`;
  }

  function hostSummary(state, id) {
    const scope = { ...state, host: id };
    const cpu = data.read(scope, id, "cpu", "1h");
    const ram = data.read(scope, id, "ram", "1h");
    const status = freshness[cpu.freshness];
    const cpuLabel = textValue(cpu.latestValue);
    const ramLabel = textValue(ram.latestValue);
    const chartLabel = t(`CPU und RAM, zuletzt ${cpuLabel} CPU und ${ramLabel} RAM.`, `CPU and RAM, latest ${cpuLabel} CPU and ${ramLabel} RAM.`);
    return `<section class="panel" aria-labelledby="host-monitor-title"><div class="panel-head"><div>
        <h2 id="host-monitor-title">${t("Auslastung", "Utilization")}</h2><p>${t(...periods["1h"])} · ${readingNote(cpu)}</p></div>${state.badge(t(...status.label), status.tone)}</div>
      ${cpu.latestValue === null && ram.latestValue === null ? `<p class="panel-pad compact">${t("Keine CPU- oder RAM-Messwerte im gewählten Zeitraum.", "No CPU or RAM readings in the selected period.")}</p>`
        : `<div class="monitor-host-plot">${plot([{ reading: cpu, id: "cpu" }, { reading: ram, id: "ram" }], "1h", chartLabel)}
          <div class="monitor-legend"><span>CPU ${cpuLabel}</span><span>RAM ${ramLabel}</span></div></div>`}
      <div class="monitor-context"><button type="button" class="text-button" data-view="monitoring" data-host="${state.escape(id)}" data-monitor-host="${state.escape(id)}" data-monitor-period="1h">${t("Überwachung öffnen", "Open monitoring")}</button></div></section>`;
  }

  window.opstendMonitoring = { sourceSummary, hostSummary, readingNote, textValue, sourceLabel, metricLabel };
  window.opstendViews.monitoring = monitoring;
})();
