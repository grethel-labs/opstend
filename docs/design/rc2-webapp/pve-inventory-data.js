(function () {
  "use strict";

  const profile = "pve-native/v1";
  const coverage = "token_scope";
  const asOf = Date.parse("2026-11-27T13:21:00Z");
  const storageKey = "opstend-pve-inventory-fixture";
  const changed = "opstend:pve-inventory-changed";
  const profiles = Object.freeze([
    Object.freeze({ id: "observed", label: "Sichtbares Inventar", labelEn: "Visible inventory" }),
    Object.freeze({ id: "restricted", label: "Eingeschränkter Token", labelEn: "Restricted token" }),
    Object.freeze({ id: "stale", label: "Snapshot abgelaufen", labelEn: "Expired snapshot" }),
    Object.freeze({ id: "unavailable", label: "Quelle nicht verfügbar", labelEn: "Source unavailable" }),
  ]);
  const ids = new Set(profiles.map(({ id }) => id));
  const references = {
    "nuc-a": { node: "nuc-a" },
    medien: { node: "nuc-a", vmid: 201, guest: "qemu:201" },
    fotos: { node: "nuc-a", vmid: 202, guest: "lxc:202" },
    entwicklung: { node: "nuc-a", vmid: 203, guest: "qemu:203" },
  };
  const queries = new Map();
  const invalid = Symbol("invalid");
  const idle = Object.freeze({ pending: true, snapshot: null });
  const failed = (error) => ({ pending: false, snapshot: null, error });
  const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  const oneOf = (values) => (value) => values.includes(value) ? value : invalid;
  const matching = (pattern) => (value) => typeof value === "string" && pattern.test(value) ? value : invalid;
  const integer = (min, max) => (value) => Number.isSafeInteger(value) && value >= min && value <= max ? value : invalid;
  const optional = (parse) => (value) => value == null ? null : parse(value);
  const count = integer(0, Number.MAX_SAFE_INTEGER);
  const quantity = (value) => typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : invalid;
  const resourceName = matching(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/);
  const nodeName = matching(/^[A-Za-z0-9][A-Za-z0-9-]{0,62}$/);
  const poolName = (value) => typeof value === "string" && value.length <= 255
    && /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+){0,2}$/.test(value) ? value : invalid;
  const vmidValue = integer(100, 999_999_999);
  const resourceStatus = optional(oneOf(["online", "offline", "running", "stopped", "paused", "available", "unknown"]));

  function timestamp(value) {
    if (typeof value !== "string"
      || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)$/.test(value)
      || value.startsWith("0000-")) return invalid;
    const time = Date.parse(value);
    return Number.isFinite(time) && new Date(time).toISOString().slice(0, 19) === value.slice(0, 19) ? value : invalid;
  }

  function fields(schema) {
    return (value) => {
      if (!isRecord(value)) return invalid;
      const result = {};
      for (const [key, parse] of Object.entries(schema)) {
        const field = parse(value[key]);
        if (field === invalid) return invalid;
        result[key] = field;
      }
      return result;
    };
  }

  function rows(parse, limit, identity) {
    return (value) => {
      if (!Array.isArray(value) || value.length > limit) return invalid;
      const result = value.map(parse);
      if (result.includes(invalid)) return invalid;
      if (identity && new Set(result.map(identity)).size !== result.length) return invalid;
      return result;
    };
  }

  const evidence = fields({
    source: oneOf(["cluster_resources", "guest_config", "guest_rrd", "guest_tasks", "permissions"]),
    state: oneOf(["observed", "absent", "restricted", "missing", "unavailable", "invalid", "budget"]),
    observed_at: timestamp,
  });

  function resourceEvidence(value) {
    const reading = evidence(value);
    return reading?.source === "cluster_resources" && reading.state === "observed" ? reading : invalid;
  }

  function observation(source, parseItems) {
    return (value) => {
      if (!isRecord(value)) return invalid;
      const reading = evidence(value.evidence);
      if (reading?.source !== source) return invalid;
      const items = reading.state === "observed" ? parseItems(value.items) : [];
      return items === invalid ? invalid : { evidence: reading, items };
    };
  }

  const node = fields({
    evidence: resourceEvidence, node: nodeName, status: resourceStatus,
    cpu_capacity: optional(quantity), max_memory_bytes: optional(count),
    max_disk_bytes: optional(count), uptime_seconds: optional(count),
  });
  const attachment = fields({
    index: integer(0, 255), bridge: optional(resourceName), vlan_tag: optional(integer(1, 4094)),
  });
  const measurement = fields({
    time: timestamp, cpu_fraction: optional(quantity), cpu_capacity: optional(quantity),
    memory_bytes: optional(quantity), max_memory_bytes: optional(quantity), host_memory_bytes: optional(quantity),
    disk_bytes: optional(quantity), max_disk_bytes: optional(quantity),
    disk_read_bytes_per_second: optional(quantity), disk_write_bytes_per_second: optional(quantity),
    net_in_bytes_per_second: optional(quantity), net_out_bytes_per_second: optional(quantity),
  });
  const task = fields({
    operation: oneOf(["create", "start", "stop", "shutdown", "reboot", "reset", "suspend", "resume", "migrate"]),
    state: oneOf(["running", "succeeded", "warning", "failed"]),
    started_at: timestamp, finished_at: optional(timestamp), warning_count: optional(count),
  });
  const guest = fields({
    evidence: resourceEvidence, node: nodeName, vmid: vmidValue, kind: oneOf(["qemu", "lxc"]),
    name: optional(resourceName), pool: optional(poolName), status: resourceStatus,
    cpu_fraction: optional(quantity), cpu_capacity: optional(count), memory_bytes: optional(count),
    max_memory_bytes: optional(count), disk_bytes: optional(count), max_disk_bytes: optional(count), uptime_seconds: optional(count),
    network: optional(observation("guest_config", rows(attachment, 256, ({ index }) => index))),
    measurements: optional(observation("guest_rrd", rows(measurement, 64, ({ time }) => Date.parse(time)))),
    tasks: optional(observation("guest_tasks", rows(task, 20))),
  });
  const pool = fields({ evidence: resourceEvidence, pool: poolName });
  const datastore = fields({
    evidence: resourceEvidence, node: nodeName, storage: resourceName, status: resourceStatus,
    plugin_type: optional(resourceName), content: rows(resourceName, 16),
    shared: optional((value) => typeof value === "boolean" ? value : invalid), max_disk_bytes: optional(count),
  });
  const inventory = fields({
    nodes: rows(node, 256, ({ node }) => node),
    guests: rows(guest, 256, ({ vmid }) => vmid),
    pools: rows(pool, 256, ({ pool }) => pool),
    datastores: rows(datastore, 256, ({ node, storage }) => [node, storage].join("/")),
  });
  const inventoryStatus = oneOf(["observed", "absent", "restricted", "unavailable", "stale"]);

  function guestId(value) {
    if (value === null) return null;
    const vmid = typeof value === "string" && /^[1-9][0-9]{2,8}$/.test(value) ? Number(value) : value;
    return vmidValue(vmid);
  }

  function fromSnapshot(raw, vmid) {
    if (!isRecord(raw) || raw.profile !== profile || raw.coverage !== coverage
      || !Object.hasOwn(raw, "observed_at") || !Object.hasOwn(raw, "evidence")) return null;
    const status = inventoryStatus(raw.status);
    const observedAt = optional(timestamp)(raw.observed_at);
    const reading = optional(evidence)(raw.evidence);
    const detail = vmid === undefined ? Object.hasOwn(raw, "guest") : vmid !== null;
    if ([status, observedAt, reading].includes(invalid) || detail !== Object.hasOwn(raw, "guest")
      || (observedAt === null) !== (reading === null)) return null;

    const snapshot = { profile, status, coverage, observed_at: observedAt, evidence: reading };
    if (status !== "observed") {
      if (status === "stale" && reading !== null) return null;
      if (status === "absent" && (detail || reading?.state !== "absent")) return null;
      if (status === "restricted" && reading?.state !== "restricted"
        && (!detail || !["observed", "absent"].includes(reading?.state))) return null;
      if (status === "unavailable" && ["observed", "absent", "restricted"].includes(reading?.state)) return null;
      return detail ? { ...snapshot, guest: null } : { ...snapshot, nodes: [], guests: [], pools: [], datastores: [] };
    }
    if (!observedAt || reading?.state !== "observed") return null;
    if (detail) {
      const row = guest(raw.guest);
      const id = vmid === undefined ? row?.vmid : guestId(vmid);
      return row !== invalid && row.vmid === id ? { ...snapshot, guest: row } : null;
    }
    const resources = inventory(raw);
    return resources === invalid ? null : { ...snapshot, ...resources };
  }

  function selected() {
    try {
      const id = window.localStorage.getItem(storageKey);
      if (ids.has(id)) return id;
    } catch {}
    return "observed";
  }

  function announce() {
    window.dispatchEvent(new CustomEvent(changed));
  }

  function discardOtherProfiles() {
    const current = selected();
    for (const [key, entry] of queries) {
      if (entry.profile !== current) {
        queries.delete(key);
        entry.controller.abort();
      }
    }
  }

  function select(id) {
    if (!ids.has(id)) return false;
    if (selected() === id) return true;
    try {
      window.localStorage.setItem(storageKey, id);
    } catch {
      return false;
    }
    discardOtherProfiles();
    announce();
    return true;
  }

  function supportedLocation() {
    return window.location.protocol === "http:" || window.location.protocol === "https:";
  }

  function read(vmid = null) {
    const id = guestId(vmid);
    if (id === invalid) return failed("invalid");
    if (!supportedLocation()) return failed("file");
    const entry = queries.get(id);
    return entry?.profile === selected() ? entry.value : idle;
  }

  async function fetchResponse(id, entry) {
    const path = id === null ? "/inventory" : "/guests/" + id;
    const url = new URL(path, window.location.origin);
    url.searchParams.set("fixture", entry.profile);
    let response;
    try {
      response = await window.fetch(url, {
        headers: { Accept: "application/json" }, cache: "no-store", credentials: "same-origin",
        mode: "same-origin", redirect: "error", signal: entry.controller.signal,
      });
    } catch {
      return failed("transport");
    }
    if (!response.ok) return failed("transport");
    try {
      const snapshot = fromSnapshot(await response.json(), id);
      return snapshot ? { pending: false, snapshot } : failed("invalid");
    } catch {
      return failed("invalid");
    }
  }

  function load(vmid, force) {
    const id = guestId(vmid);
    if (id === invalid || !supportedLocation()) return Promise.resolve(read(vmid));
    discardOtherProfiles();
    const previous = queries.get(id);
    if (previous && !force) return previous.promise;
    const entry = { profile: selected(), controller: new AbortController(), value: idle };
    queries.set(id, entry);
    previous?.controller.abort();
    entry.promise = fetchResponse(id, entry).then((value) => {
      if (queries.get(id) !== entry || entry.profile !== selected()) return read(id);
      entry.value = value;
      announce();
      return value;
    });
    if (force) announce();
    return entry.promise;
  }

  window.addEventListener("storage", (event) => {
    if (event.key !== storageKey && event.key !== null) return;
    discardOtherProfiles();
    announce();
  });

  window.opstendPveInventory = {
    profiles, selected, select, read,
    ensure: (vmid = null) => load(vmid, false),
    refresh: (vmid = null) => load(vmid, true),
    fromSnapshot, asOf,
    referenceFor: (id) => Object.hasOwn(references, id) ? { ...references[id] } : null,
  };
})();
