(function () {
  "use strict";

  const openEyes = "M24 25v6m16-6v6";
  const smilingEyes = "m20 30 4-5 4 5m8 0 4-5 4 5";
  const faces = {
    listening: "M26 24v8m16-8v8",
    thinking: "M25 28h5m10 0h5",
    answered: smilingEyes,
    "missing-data": "M20 28h7m13 0h0",
    limit: "M23 28h3m5 0h2m5 0h3",
    offline: "M21 30h6m10 0h6",
    setup: "M21 26v6m16-7v7",
    verifying: "M24 25v6m13-3h6",
    scanning: "M23 26v4m16-4v4",
    selection: "M20 25v6m20-6v6",
    "awaiting-download": "M23 23v5m18-5v5",
    failed: "m20 25 7 4m17-4-7 4",
    ready: openEyes,
    "awaiting-approval": "M23 26v4m16-4v4",
    executing: openEyes,
    recovered: smilingEyes,
    embarrassed: "M21 28q3 3 6 0m10 0q3 3 6 0",
  };
  const eyePaths = Object.entries(faces).map(([gesture, path]) => `<path data-face="${gesture}" d="${path}"/>`).join("");

  function gear(x, y, scale) {
    return `<g transform="translate(${x} ${y}) scale(${scale})"><g class="zorec-gear">
      <path d="M-1.5-7h3l.6 2.3 1.2.7 2.3-.6 1.5 2.6-1.7 1.6v1.4l1.7 1.6-1.5 2.6-2.3-.6-1.2.7L1.5 7h-3l-.6-1.7-1.2-.7-2.3.6-1.5-2.6 1.7-1.6V-.4L-7.1-2l1.5-2.6 2.3.6 1.2-.7Z"/>
      <circle r="2"/>
    </g></g>`;
  }

  const moods = {
    quiet: "",
    sleepy: '<path d="M38-16h8l-8 8h8m2-12h9l-9 9h9"/>',
    warning: '<path d="M46-22a1.4 1.4 0 0 1 2.4 0l8 13a1.2 1.2 0 0 1-1 1.9H39a1.2 1.2 0 0 1-1-1.9Z"/><path d="M47-18v4m0 3h.01"/>',
    critical: '<path d="M43-22v10m0 4h.01m8-14v10m0 4h.01" stroke-width="2.9"/>',
    working: `${gear(43, -15, 1)}${gear(55, -11, .64)}`,
    approval: '<path d="M42-21h-2v15h14v-15h-2m-10-2h10v4H42Zm1 8h8m-8 4h6"/>',
    maintenance: '<path d="M50-22a5 5 0 0 0-6 6L36-8l3 3 8-8a5 5 0 0 0 6-6l-4 2-2-2Zm5 11 3 5m-4-1h4"/>',
    recovered: '<path d="m38-14 6 6 10-13m1 10v5m-2.5-2.5h5"/>',
    offline: '<path d="M37-18a15 15 0 0 1 20 0m-16 4a9 9 0 0 1 12 0m-8 4a4 4 0 0 1 4 0m-2 4h.01M38-23 56-6"/>',
    embarrassed: '<path d="m43-22-5 5 5 5m-5-5h12a5 5 0 0 1 0 10h-5m10-15v4m-2-2h4"/>',
  };
  const moodSymbols = Object.entries(moods).filter(([, symbol]) => symbol)
    .map(([mood, symbol]) => `<g data-mood-symbol="${mood}">${symbol}</g>`).join("");
  const moodFaces = {
    sleepy: "M20 28q4 4 8 0m8 0q4 4 8 0",
    warning: "M23 24v7m17-4v4",
    critical: "M24 23v9m16-9v9",
    working: "m21 26 7 2m8 0 7-2",
    approval: "M25 23v8m14-8v8",
    recovered: smilingEyes,
    offline: faces.offline,
    embarrassed: faces.embarrassed,
  };
  const moodEyePaths = Object.entries(moodFaces).map(([mood, path]) => `<path data-mood-face="${mood}" d="${path}"/>`).join("");
  const gestureMoods = {
    thinking: "working", verifying: "working", scanning: "working", executing: "working",
    failed: "warning", "missing-data": "warning", limit: "warning",
    offline: "offline", "awaiting-approval": "approval", recovered: "recovered", embarrassed: "embarrassed",
  };
  const follower = "[data-zorec-follow]";
  const dialog = "#zorec-dialog";
  const gazeRadius = 160;

  function render(gesture = "neutral", { follow = false, idle = follow, mood } = {}) {
    const pose = Object.hasOwn(faces, gesture) ? gesture : "neutral";
    const appliedMood = mood ?? gestureMoods[pose];
    const moodAttribute = Object.hasOwn(moods, appliedMood) ? ` data-mood="${appliedMood}"` : "";
    return `<svg class="zorec-mascot" viewBox="0 0 64 64" width="40" height="40" aria-hidden="true" focusable="false"
      data-gesture="${pose}"${follow ? " data-zorec-follow" : ""}${idle ? " data-zorec-idle" : ""}${moodAttribute}>
      <rect class="zorec-mascot-tile" x="1" y="1" width="62" height="62" rx="13"/>
      <g class="zorec-mascot-body">
        <path class="zorec-mascot-shell" d="M15 12h34a9 9 0 0 1 9 9v22l-8 8H14l-8-8V21a9 9 0 0 1 9-9Z" stroke-width="2.5" stroke-linejoin="round"/>
        <rect class="zorec-mascot-screen" x="10" y="16" width="44" height="25" rx="5"/>
        <rect class="zorec-mascot-port" x="42" y="44" width="8" height="4" rx="2"/>
        <g class="zorec-mascot-gaze"><g class="zorec-mascot-eyes" fill="none" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round">
          <g data-face="neutral"><path class="zorec-mascot-wink" d="M24 25v6"/><path d="M40 25v6"/></g>
          ${eyePaths}
          ${moodEyePaths}
        </g></g>
        <g class="zorec-mascot-marks" fill="none" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path data-face="thinking" d="M21 34h1m26 0h1" stroke-width="2" opacity=".6"/>
          <path data-face="setup" d="M43 20v6m-3-3h6"/>
          <path data-face="verifying" d="M19 21h-4v4m30 10h4v-4"/>
          <path class="zorec-mascot-scan" data-face="scanning" d="M15 34h34" stroke-width="2" opacity=".6"/>
          <path data-face="selection" d="m31 32 2 2 3-3"/>
          <path data-face="awaiting-download" d="M32 28v7m-3-3 3 3 3-3" stroke-width="1.8"/>
          <path data-face="awaiting-approval" d="M30 35h4"/>
        </g>
        <path class="zorec-mascot-sweat" d="M53 19q-5 6-5 8a5 5 0 0 0 10 0q0-2-5-8Z"/>
        <g class="zorec-mascot-cheeks"><ellipse cx="20" cy="34.5" rx="4.5" ry="2.3"/><ellipse cx="44" cy="34.5" rx="4.5" ry="2.3"/></g>
      </g>
      <g class="zorec-mood-bubble" stroke-width="1.9" stroke-linejoin="round" stroke-linecap="round">
        <rect x="32" y="-28" width="30" height="27" rx="9"/>
        <circle cx="48" cy="2.8" r="2.7"/>
        <circle cx="43" cy="8.4" r="1.6"/>
        ${moodSymbols}
      </g>
    </svg>`;
  }

  let mounted = false;
  function mount() {
    if (mounted) return;
    mounted = true;

    const canFollow = matchMedia("(any-pointer: fine) and (any-hover: hover) and (prefers-reduced-motion: no-preference)");
    let frame = 0;
    let point;

    function resetGaze() {
      cancelAnimationFrame(frame);
      frame = 0;
      point = undefined;
      const mascot = document.querySelector(follower);
      mascot?.style.removeProperty("--zorec-gaze-x");
      mascot?.style.removeProperty("--zorec-gaze-y");
      mascot?.removeAttribute("data-gazing");
    }

    function moveGaze() {
      frame = 0;
      const mascot = document.querySelector(follower);
      if (!mascot || !point || document.querySelector(`${dialog}[open]`)) return resetGaze();
      const bounds = mascot.getBoundingClientRect();
      const offsetX = point.x - (bounds.left + bounds.width / 2);
      const offsetY = point.y - (bounds.top + bounds.height * 28 / 64);
      const distance = Math.hypot(offsetX, offsetY);
      if (distance > gazeRadius) return resetGaze();
      const scale = Math.max(90, distance);
      mascot.style.setProperty("--zorec-gaze-x", `${(offsetX * 4 / scale).toFixed(2)}px`);
      mascot.style.setProperty("--zorec-gaze-y", `${(offsetY * 3 / scale).toFixed(2)}px`);
      mascot.setAttribute("data-gazing", "");
      point = undefined;
    }

    document.addEventListener("pointermove", (event) => {
      if (event.pointerType !== "mouse" || !canFollow.matches) return;
      point = { x: event.clientX, y: event.clientY };
      if (!frame) frame = requestAnimationFrame(moveGaze);
    }, { passive: true });
    document.documentElement.addEventListener("pointerleave", resetGaze);
    window.addEventListener("blur", resetGaze);
    document.addEventListener("visibilitychange", () => { if (document.hidden) resetGaze(); });
    document.addEventListener("toggle", (event) => {
      if (event.target.matches?.(dialog)) resetGaze();
    }, true);
    canFollow.addEventListener("change", resetGaze);
  }

  window.opstendMascot = { render, mount };
})();
