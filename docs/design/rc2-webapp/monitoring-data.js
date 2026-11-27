(function () {
  "use strict";

  const resources = {
    "nuc-a": { cpu: 32, ram: 19, ramTotal: 48, disk: 470, diskTotal: 1024, port: "P2 · 10 Gbit/s", source: "PVE-API", reserve: "6 GiB RAM" },
    "host-b": { cpu: 22, ram: 12, ramTotal: 32, disk: 210, diskTotal: 512, port: "P3 · 2,5 Gbit/s", source: "Linux-Agent", reserve: "4 GiB RAM" },
    "nuc-c": { cpu: 21, ram: 9, ramTotal: 32, disk: 140, diskTotal: 512, port: "P5 · 2,5 Gbit/s", source: "Linux-Agent", reserve: "4 GiB RAM" },
    "nuc-d": { cpu: 8, ram: 4, ramTotal: 32, disk: 67, diskTotal: 512, port: "P6 · 2,5 Gbit/s", source: "Linux-Agent", reserve: "4 GiB RAM" },
    "edge-01": { cpu: 14, ram: 3, ramTotal: 8, disk: 34, diskTotal: 128, port: "Virtueller Uplink · Linkrate unbekannt", source: "Linux-Agent", reserve: "1 GiB RAM" },
  };
  const metrics = {
    cpu: { label: "CPU-Auslastung", unit: "%" },
    ram: { label: "Arbeitsspeicher belegt", unit: "%" },
    storage: { label: "Lokaler Speicher belegt", unit: "%" },
  };
  const periods = { "1h": 60, "6h": 360, "24h": 1440 };
  const asOf = Date.parse("2026-11-27T13:21:00Z");
  const minute = 60_000;
  const step = 5;
  const staleAfter = 15;

  const timing = {
    "nuc-a": { offset: 2, spike: 115 },
    "host-b": { offset: 4, gap: [20, 30], spike: 15 },
    "nuc-c": { offset: 7 },
    "nuc-d": { offset: 9, newest: 135 },
    "edge-01": { offset: 11, newest: 35 },
  };
  const observedAddresses = {
    "nuc-a": "10.20.10.11", "host-b": "10.20.10.12", "nuc-c": "10.20.10.13",
    "nuc-d": "10.20.10.14", "edge-01": "10.31.0.5",
  };
  const variation = {
    cpu: [-5, -8, 6, 9, -4, 12, 25, 11, -6, 2, 8, -3],
    ram: [-3, -2, -1, 0, 1, 2, 3, 2, 2, 1, 1, 0],
  };

  function baseline(resource, metric) {
    if (metric === "ram") return Math.round(resource.ram / resource.ramTotal * 100);
    if (metric === "storage") return Math.round(resource.disk / resource.diskTotal * 100);
    return resource.cpu;
  }

  function historicalValue(profile, metric, latest, age) {
    if (age === (profile.newest ?? 0)) return latest;
    if (metric === "storage") return Math.max(0, latest - Math.floor(age / 240));
    if (metric === "cpu" && age === profile.spike) return 91;

    const pattern = variation[metric];
    const index = (age / step + Math.floor(age / 35) + profile.offset) % pattern.length;
    return Math.max(0, Math.min(100, latest + pattern[index]));
  }

  function read(state, hostId, metricId, periodId) {
    const empty = { source: null, freshness: "missing", latestAt: null, latestValue: null, samples: [], unit: "%" };
    const inScope = (!state?.host || state.host === hostId)
      && state?.inventory?.hosts?.some((host) => host.id === hostId);
    if (!inScope || !Object.hasOwn(metrics, metricId) || !Object.hasOwn(periods, periodId)) return empty;
    if (!Object.hasOwn(resources, hostId)) return { ...empty, source: "Hostaufnahme · Messquelle offen" };

    const resource = resources[hostId];
    const profile = timing[hostId];
    const latest = baseline(resource, metricId);
    const sample = (age) => {
      const inGap = profile.gap && age >= profile.gap[0] && age <= profile.gap[1];
      const missing = age < (profile.newest ?? 0) || inGap;
      return { at: asOf - age * minute, value: missing ? null : historicalValue(profile, metricId, latest, age) };
    };
    const duration = periods[periodId];
    const samples = Array.from({ length: duration / step + 1 }, (_, index) => sample(duration - index * step));
    const last = samples.findLast((entry) => entry.value !== null);
    if (!last) return { ...empty, source: resource.source, samples };

    const freshness = asOf - last.at > staleAfter * minute ? "stale" : "current";
    return { source: resource.source, freshness, latestAt: last.at, latestValue: last.value, samples, unit: metrics[metricId].unit };
  }

  function capacity(host) {
    return resources[host.id] || { cpu: null, ram: null, disk: null, ramTotal: host.physical?.ram || 0,
      diskTotal: host.physical?.storage || 0, source: "Hostaufnahme", port: "Uplink offen", reserve: "Nach Aufnahmerichtlinie" };
  }

  function projectHost(host) {
    const machine = capacity(host);
    const observationAt = observedAddresses[host.id] === host.ip && timing[host.id]
      ? asOf - (timing[host.id].newest ?? 0) * minute : null;
    const offline = ["Offline", "Ausgefallen", "Nicht erreichbar"].includes(host.status);
    const freshness = observationAt === null ? "missing" : asOf - observationAt > staleAfter * minute ? "stale" : "current";
    const reachability = offline ? "offline" : freshness === "current" ? "reachable" : "unknown";
    const report = freshness === "stale" ? "Zuletzt erreichbar" : reachability === "reachable" ? "Erreichbar" : "Ungeprüft";
    const condition = offline || ["Wartung", "Warnung"].includes(host.status) ? host.status : report;
    return { ...host, status: condition, observation: { reachability, freshness: offline ? "missing" : freshness,
      at: offline ? null : observationAt, source: offline ? "Demo-Inventar" : observationAt === null ? null : machine.source } };
  }

  function capacityCoverage(state, metric) {
    const usageKey = metric === "ram" ? "ram" : "disk";
    const totalKey = metric === "ram" ? "ramTotal" : "diskTotal";
    const hosts = state.inventory.hosts.filter(({ id }) => !state.host || id === state.host);
    const summary = { used: 0, measuredCapacity: 0, capacity: 0, measuredHosts: 0, knownHosts: 0, hosts: hosts.length };
    for (const host of hosts) {
      const resource = capacity(host);
      if (!(resource[totalKey] > 0)) continue;
      summary.knownHosts += 1;
      summary.capacity += resource[totalKey];
      if (read(state, host.id, metric, "1h").freshness !== "current") continue;
      summary.measuredHosts += 1;
      summary.used += resource[usageKey];
      summary.measuredCapacity += resource[totalKey];
    }
    return summary;
  }

  window.opstendMonitoringData = { resources, metrics, periods, asOf, read, capacity, projectHost, capacityCoverage };
})();
