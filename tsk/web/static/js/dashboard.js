import { fetchJson, postJson } from "/js/api.js";

const state = {
  dashboard: null,
  health: null,
  busy: false,
  dashboardFingerprint: "",
};

const $ = (id) => document.getElementById(id);

const els = {
  connectionDot: $("connectionDot"),
  connectionText: $("connectionText"),
  sidebarKeyDot: $("sidebarKeyDot"),
  sidebarKeyText: $("sidebarKeyText"),
  keyChip: $("keyChip"),
  vehicleName: $("vehicleName"),
  vehicleDetail: $("vehicleDetail"),
  routePills: $("routePills"),
  nextCard: $("nextCard"),
  nextTitle: $("nextTitle"),
  nextDescription: $("nextDescription"),
  nextMeta: $("nextMeta"),
  nextActions: $("nextActions"),
  workflow: $("workflow"),
  workflowCardTitle: $("workflowCardTitle"),
  workflowCardSubtitle: $("workflowCardSubtitle"),
  vehicleMetrics: $("vehicleMetrics"),
  evidenceSummary: $("evidenceSummary"),
  evidenceCardTitle: $("evidenceCardTitle"),
  evidenceCardSubtitle: $("evidenceCardSubtitle"),
  targetCheckpointCard: $("targetCheckpointCard"),
  targetCheckpoint: $("targetCheckpoint"),
  failureCard: $("failureCard"),
  failureList: $("failureList"),
  systemConnectionChip: $("systemConnectionChip"),
  systemKeyValue: $("systemKeyValue"),
  cacheSummary: $("cacheSummary"),
  clearCacheBtn: $("clearCacheBtn"),
  uninstallBtn: $("uninstallBtn"),
  systemUrl: $("systemUrl"),
  systemDevice: $("systemDevice"),
  rebootList: $("rebootList"),
  modalOverlay: $("modalOverlay"),
  modalTitle: $("modalTitle"),
  modalBody: $("modalBody"),
  modalActions: $("modalActions"),
  loadingOverlay: $("loadingOverlay"),
  loadingLabel: $("loadingLabel"),
};

function node(tag, className = "", text = "") {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== "") element.textContent = text;
  return element;
}

function dot(tone = "") {
  return node("span", `dot${tone ? ` ${tone}` : ""}`);
}

function pill(text, tone = "") {
  return node("span", `pill${tone ? ` ${tone}` : ""}`, text);
}

function button(text, className = "btn", onClick = null) {
  const b = node("button", className, text);
  b.type = "button";
  if (onClick) b.addEventListener("click", onClick);
  return b;
}

function link(text, href, className = "btn") {
  const a = node("a", className, text);
  a.href = href;
  return a;
}

function setBusy(busy, label = "Working…") {
  state.busy = busy;
  els.loadingLabel.textContent = label;
  els.loadingOverlay.classList.toggle("visible", busy);
  els.loadingOverlay.setAttribute("aria-hidden", busy ? "false" : "true");
}

function showModal(title, body, actions = [{ label: "OK", kind: "primary" }]) {
  els.modalTitle.textContent = title;
  els.modalBody.textContent = body || "";
  els.modalActions.replaceChildren();

  for (const action of actions) {
    const className = action.kind === "danger" ? "btn danger" : action.kind === "primary" ? "btn primary" : "btn";
    const b = button(action.label, className, () => {
      if (action.onClick) {
        action.onClick();
      } else {
        hideModal();
      }
    });
    els.modalActions.appendChild(b);
  }
  els.modalOverlay.classList.add("visible");
}

function hideModal() {
  els.modalOverlay.classList.remove("visible");
}

function formatKey(key) {
  if (!key) return "No key installed";
  return (key.match(/.{1,4}/g) || [key]).join(" ");
}

function currentView() {
  const view = location.hash.replace(/^#/, "");
  return ["recovery", "research", "system"].includes(view) ? view : "recovery";
}

function selectView(view, updateHash = true) {
  for (const panel of document.querySelectorAll("[data-view-panel]")) {
    panel.hidden = panel.dataset.viewPanel !== view;
  }
  for (const item of document.querySelectorAll("[data-view]")) {
    const active = item.dataset.view === view;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  }
  if (updateHash) {
    const hash = view === "recovery" ? "" : `#${view}`;
    history.replaceState(null, "", `${location.pathname}${hash}`);
  }
  window.scrollTo({ top: 0, behavior: "auto" });
}

function metric(label, value, mono = false) {
  const row = node("div", "metric-row");
  row.appendChild(node("span", "metric-label", label));
  row.appendChild(node("span", `metric-value${mono ? " mono" : ""}`, value || "—"));
  return row;
}

function routeText(route) {
  if (!route?.identified) return "Not established";
  const bus = route.tx_bus >= 0 ? `CAN ${route.tx_bus}` : "CAN ?";
  const path = route.semantic_path ? route.semantic_path.replace("-", " ") : "route unknown";
  return `${bus} · ${path}`;
}

function renderKey(dashboard) {
  const exactF33 = dashboard.target?.kind === "camry_f33";
  const installed = Boolean(dashboard.key?.installed);
  const recovered = Boolean(dashboard.recovered_key?.recovered);
  const key = dashboard.key?.key || "";
  const fingerprint = dashboard.recovered_key?.key_sha256_prefix || "";

  if (exactF33) {
    els.sidebarKeyDot.className = "dot amber";
    els.sidebarKeyText.textContent = "Output disabled";
    els.keyChip.replaceChildren(dot("amber"), node("span", "", "Production output disabled"));
  } else {
    els.sidebarKeyDot.className = `dot ${installed ? "green" : recovered ? "blue" : ""}`.trim();
    els.sidebarKeyText.textContent = installed ? "Key installed" : recovered ? "Key recovered" : "Key: none";
    const label = installed ? "Operational key installed" : recovered ? "Key recovered — not installed" : "No recovered key";
    els.keyChip.replaceChildren(dot(installed ? "green" : recovered ? "blue" : ""), node("span", "", label));
  }
  els.systemKeyValue.textContent = installed ? formatKey(key) : recovered ? `Recovered key · SHA-256 ${fingerprint}` : "No key installed";
  els.uninstallBtn.disabled = !installed || state.busy;
}

function renderVehicle(dashboard) {
  const vehicle = dashboard.vehicle || {};
  const route = dashboard.route || {};
  const exactF33 = dashboard.target?.kind === "camry_f33";
  const targetStatus = dashboard.target?.status || {};

  if (exactF33) {
    els.vehicleName.textContent = "2026 Camry · EPS 8965F3307000";
    els.vehicleDetail.textContent = `Exact F33 / ${targetStatus.secondary_software_id || "8A3113303100"} · passive integration checkpoint`;
  } else if (vehicle.identified) {
    els.vehicleName.textContent = vehicle.app_sw_id || vehicle.spare_part_no || "Toyota EPS";
    const parts = [];
    if (vehicle.spare_part_no && vehicle.spare_part_no !== vehicle.app_sw_id) parts.push(`Spare part ${vehicle.spare_part_no}`);
    if (vehicle.ecu_serial) parts.push(`Serial ${vehicle.ecu_serial}`);
    els.vehicleDetail.textContent = parts.length ? parts.join(" · ") : "EPS identity confirmed";
  } else {
    els.vehicleName.textContent = "EPS not identified";
    els.vehicleDetail.textContent = "Run the read-only identity pass before selecting a target path.";
  }

  els.routePills.replaceChildren();
  if (exactF33) {
    els.routePills.appendChild(pill("Exact F33", "blue"));
    els.routePills.appendChild(pill("B6 · PDU44"));
    els.routePills.appendChild(pill("Output disabled"));
  }
  if (route.identified) {
    els.routePills.appendChild(pill(`${route.tx} → ${route.rx}`, "blue"));
    els.routePills.appendChild(pill(`CAN ${route.tx_bus}`));
    if (route.semantic_path) els.routePills.appendChild(pill(route.semantic_path.replace("-", " ")));
    if (route.elm327_param >= 0) els.routePills.appendChild(pill(`ELM ${route.elm327_param}`));
  }

  const metrics = [
    metric("EPS", vehicle.app_sw_id || "Not identified", true),
    metric("Diagnostic route", route.identified ? `${route.tx} → ${route.rx}` : "Not established", true),
    metric("Physical path", routeText(route)),
    metric("Panda", vehicle.panda || "Unknown", true),
  ];
  if (exactF33) metrics.splice(1, 0, metric("Platform", "TOYOTA_CAMRY_TSS3", true));
  els.vehicleMetrics.replaceChildren(...metrics);
}

function checkpointItem(label, value, tone = "") {
  const item = node("div", "checkpoint-item");
  item.appendChild(node("div", "checkpoint-label", label));
  item.appendChild(node("div", `checkpoint-value${tone ? ` ${tone}` : ""}`, value));
  return item;
}

function renderTargetCheckpoint(dashboard) {
  const exactF33 = dashboard.target?.kind === "camry_f33";
  els.targetCheckpointCard.hidden = !exactF33;
  if (!exactF33) return;

  const status = dashboard.target.status || {};
  const checkpoint = status.checkpoint || {};
  const architecture = status.production_architecture || {};
  const development = status.development_lateral || {};
  const blockers = status.remaining_production_gates || [];
  els.targetCheckpoint.replaceChildren(
    checkpointItem("Static checkpoint", "B6 receiver + integration closed", "success"),
    checkpointItem("CPU-visible recovery", checkpoint.cpu_visible_key_recovery || "negative"),
    checkpointItem("Production architecture", architecture.runtime_model || "RAM-only / reset-to-stock", "primary"),
    checkpointItem("Persistent flash", architecture.persistent_flash || "fallback-only"),
    checkpointItem("Development path", development.available ? "Staged · non-release · live-gated" : "Not staged", "warning"),
    checkpointItem("Live blockers", `${blockers.length} production gates open`, "warning"),
    checkpointItem("Output", checkpoint.output_detail || "Production output disabled", "danger"),
  );
}

function renderNextAction(dashboard) {
  const action = dashboard.recovery?.next_action || {};
  const complete = action.id === "complete";
  els.nextCard.classList.toggle("success", complete);
  els.nextCard.classList.toggle("warning", action.tone === "warning");
  els.nextTitle.textContent = action.title || "Target state unavailable";
  els.nextDescription.textContent = action.description || "";

  els.nextMeta.replaceChildren();
  if (action.vehicle_state) {
    const vehicleTone = action.vehicle_state === "READY" ? "blue" : "";
    els.nextMeta.appendChild(pill(action.vehicle_state, vehicleTone));
  }
  if (action.id === "identify") els.nextMeta.appendChild(pill("Read only"));
  if (action.id === "programming") els.nextMeta.appendChild(pill("Resets EPS"));
  if (action.id === "dataflash") els.nextMeta.appendChild(pill("Programs EPS"));
  if (action.id === "verify") els.nextMeta.appendChild(pill("Offline verification"));
  if (action.id === "integration") els.nextMeta.appendChild(pill("No key install"));
  if (action.id === "stationary") els.nextMeta.appendChild(pill("Zero-actuation gate"));

  els.nextActions.replaceChildren();
  if (action.action === "match") {
    els.nextActions.appendChild(button(action.label || "Find & verify key", "btn primary", runMatcher));
  } else if (action.action === "install-key") {
    els.nextActions.appendChild(button(action.label || "Install verified key", "btn primary", installRecoveredKey));
  } else if (action.action === "research") {
    els.nextActions.appendChild(button(action.label || "Open Research", "btn primary", () => selectView("research")));
  } else if (action.href) {
    els.nextActions.appendChild(link(action.label || "Continue", action.href, "btn primary"));
  }

  const failures = dashboard.recovery?.failures || [];
  if (failures.length && !complete) {
    els.nextActions.appendChild(button("Troubleshoot", "btn", () => selectView("research")));
  }
}

function renderWorkflow(dashboard) {
  const steps = dashboard.recovery?.steps || [];
  const exactF33 = dashboard.target?.kind === "camry_f33";
  els.workflowCardTitle.textContent = exactF33 ? "Six remaining production gates" : "Recovery progress";
  els.workflowCardSubtitle.textContent = exactF33
    ? "Static receiver integration is closed; every live or architecture gate remains blocking."
    : "The generic recovery path stays intentionally explicit.";
  els.workflow.replaceChildren();

  steps.forEach((step, index) => {
    const item = node("div", `workflow-step ${step.state || "pending"}`);
    const indicatorText = step.state === "complete" ? "✓" : step.state === "current" ? "•" : String(index + 1);
    item.appendChild(node("div", "step-indicator", indicatorText));
    item.appendChild(node("div", "step-title", step.title));
    item.appendChild(node("div", "step-detail", step.detail || ""));
    els.workflow.appendChild(item);
  });
}

function evidenceTone(status, ready, hasProgress = false) {
  if (["failed", "rejected", "blocked", "unreachable", "unusable_partial"].includes(status)) return "red";
  if (ready) return "green";
  if (status === "running") return "blue";
  if (status === "partial" || status === "insufficient" || hasProgress) return "amber";
  return "";
}

function evidenceBlock({ name, statusLabel, tone, detail, href }) {
  const block = node("div", "evidence-status");
  const top = node("div", "evidence-topline");
  top.appendChild(dot(tone));
  top.appendChild(node("span", "evidence-name", name));
  top.appendChild(node("span", "evidence-state", statusLabel));
  block.appendChild(top);
  if (detail) block.appendChild(node("p", "evidence-detail", detail));
  if (href) {
    const action = link("Open", href, "pill blue");
    action.style.margin = "10px 0 0 17px";
    block.appendChild(action);
  }
  return block;
}

function renderEvidence(dashboard) {
  const exactF33 = dashboard.target?.kind === "camry_f33";
  if (exactF33) {
    els.evidenceCardTitle.textContent = "F33 lateral evidence";
    els.evidenceCardSubtitle.textContent = "The secured request and F33 stock actuation path are separate; the authority selector is still open.";
    els.evidenceSummary.replaceChildren(
      evidenceBlock({
        name: "Upstream 0x08A request",
        statusLabel: "Recovered",
        tone: "green",
        detail: "Bus-4 0x08A carries Target Lateral ID, target angle at a numerically matching F33 B6 scale, a modulo-64 sequence, and a trailer strongly matching Toyota ordinary-P5 SecOC. Exact F33 neither accepts 0x08A as normal ingress nor generated-COM-transmits it.",
      }),
      evidenceBlock({
        name: "F33 stock-LTA authority",
        statusLabel: "Open",
        tone: "amber",
        detail: "Factory LTA steers with zero B6 through an exact B6-independent internal assist path. The external/local state selecting or modulating that path remains unresolved; 0x08A producer/SecOC ownership is tracked separately. Steering output stays noOutput/zero CAN.",
      }),
    );
    return;
  }
  els.evidenceCardTitle.textContent = "Recovery evidence";
  els.evidenceCardSubtitle.textContent = "Neutral means not collected; red is reserved for a real failure.";
  const can = dashboard.can || {};
  const df = dashboard.dataflash || {};
  const canProgress = Number(can.sync_count || 0) + Number(can.protected_count || 0) > 0;
  const canReady = Boolean(can.ready || can.status === "complete");
  const dfReady = Boolean(df.ready);

  let canLabel = "Not collected";
  if (can.status === "running") canLabel = "Collecting";
  else if (canReady) canLabel = "Ready";
  else if (can.status === "failed") canLabel = "Failed";
  else if (canProgress) canLabel = "Incomplete";

  let dfLabel = "Not dumped";
  if (df.status === "running") dfLabel = "Dumping";
  else if (dfReady) dfLabel = "Complete";
  else if (df.status === "partial") dfLabel = "Usable partial";
  else if (df.status === "unusable_partial") dfLabel = "Unusable partial";
  else if (df.status === "failed") dfLabel = "Failed";

  const discovery = can.profile_discovery || {};
  const eligibleStreams = (discovery.streams || []).filter((stream) => stream.scan_included);
  const inventoryCount = (discovery.can_inventory || []).length;
  const unknownCount = Number(discovery.unknown_structural_candidates || 0);
  const canDetail = `${can.sync_count || 0} sync · ${eligibleStreams.length} eligible classic SecOC stream${eligibleStreams.length === 1 ? "" : "s"} · ${inventoryCount} CAN ID/DLC stream${inventoryCount === 1 ? "" : "s"}` +
    (unknownCount ? ` · ${unknownCount} unknown structural candidate${unknownCount === 1 ? "" : "s"}` : "");
  const dfDetail = dfReady
    ? `${df.bytes || df.total || 32768} / ${df.total || 32768} bytes · ${df.payload_variant || "standard"} payload`
    : df.status === "partial"
      ? `${df.bytes || 0} / ${df.total || 32768} bytes retained with candidate-sized coverage`
      : df.message || "No DataFlash evidence cached.";

  els.evidenceSummary.replaceChildren(
    evidenceBlock({
      name: "CAN evidence",
      statusLabel: canLabel,
      tone: evidenceTone(can.status, canReady, canProgress),
      detail: canDetail,
      href: "/can-collector.html",
    }),
    evidenceBlock({
      name: "DataFlash",
      statusLabel: dfLabel,
      tone: evidenceTone(df.status, dfReady, df.status === "partial"),
      detail: dfDetail,
      href: "/dataflash-collector.html",
    }),
  );
}

function renderFailures(dashboard) {
  const failures = dashboard.recovery?.failures || [];
  els.failureCard.hidden = failures.length === 0;
  els.failureList.replaceChildren();
  for (const failure of failures) {
    const item = node("div", "failure-item");
    item.appendChild(node("div", "failure-name", `${failure.name} · ${failure.status}`));
    if (failure.message) item.appendChild(node("div", "failure-message", failure.message));
    els.failureList.appendChild(item);
  }
}

function renderSystem(dashboard) {
  const key = dashboard.key?.key || "";
  const can = dashboard.can || {};
  const df = dashboard.dataflash || {};
  const hasCan = Number(can.sync_count || 0) + Number(can.protected_count || 0) > 0;
  const hasDf = Boolean(df.ready || df.status === "partial" || Number(df.bytes || 0) > 0);
  const parts = [];
  if (hasCan) parts.push(`${can.sync_count || 0} sync / ${can.protected_count || 0} protected CAN frames`);
  if (hasDf) parts.push(`${df.bytes || 0} / ${df.total || 32768} DataFlash bytes`);
  els.cacheSummary.textContent = parts.length ? parts.join(" · ") : "No cached recovery evidence.";
  els.clearCacheBtn.disabled = !parts.length || state.busy;
  els.systemKeyValue.textContent = formatKey(key);

  els.rebootList.replaceChildren();
  const reboot = dashboard.reboot || {};
  for (const actionName of ["recommended", "alternate", "different", "retry"]) {
    const action = reboot[actionName];
    if (!action) continue;
    const b = node("button", "reboot-action");
    b.type = "button";
    b.appendChild(node("span", "", action.label || actionName));
    b.appendChild(node("span", "chevron", "›"));
    b.addEventListener("click", () => confirmReboot(actionName, action));
    els.rebootList.appendChild(b);
  }
}

function renderDashboard(dashboard) {
  state.dashboard = dashboard;
  renderKey(dashboard);
  renderTargetCheckpoint(dashboard);
  renderVehicle(dashboard);
  renderNextAction(dashboard);
  renderWorkflow(dashboard);
  renderEvidence(dashboard);
  renderFailures(dashboard);
  renderSystem(dashboard);
}

function renderHealth(health) {
  state.health = health;
  const online = health?.status === "ok";
  const url = health?.url || `http://${location.hostname || "tsk.local"}:${health?.port || 11111}`;
  els.connectionDot.className = `dot ${online ? "green" : "red"}`;
  els.connectionText.textContent = online ? url : "Server offline";
  els.systemUrl.textContent = online ? url : "Server offline";
  els.systemDevice.textContent = health?.dry_run ? "Workstation dry-run mode" : "comma device · AGNOS";
  els.systemConnectionChip.replaceChildren(dot(online ? "green" : "red"), node("span", "", online ? "Connected" : "Offline"));
}

async function refreshDashboard() {
  try {
    const { response, result } = await fetchJson("/api/dashboard");
    if (!response.ok) throw new Error(result.message || `HTTP ${response.status}`);
    const fingerprint = JSON.stringify(result);
    if (fingerprint === state.dashboardFingerprint) return;
    state.dashboardFingerprint = fingerprint;
    renderDashboard(result);
  } catch (error) {
    els.connectionDot.className = "dot red";
    els.connectionText.textContent = "Server offline";
  }
}

async function refreshHealth() {
  try {
    const { response, result } = await fetchJson("/api/health");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderHealth(result);
  } catch (error) {
    renderHealth({ status: "offline" });
  }
}

async function runMatcher() {
  if (state.busy) return;
  setBusy(true, "Finding & verifying key…");
  try {
    const { response, result } = await postJson("/api/match", {}, 120000);
    if (result.status === "key_recovered") {
      showModal("Key recovered — not installed", result.message || "The SecOC key was cryptographically recovered and stored privately. Integration verification remains.");
    } else {
      showModal(response.ok ? "Key not found" : "Verification failed", result.message || "No cryptographically verified key was found.");
    }
  } catch (error) {
    showModal("Verification failed", String(error));
  } finally {
    setBusy(false);
    await refreshDashboard();
  }
}

async function installRecoveredKey() {
  if (state.busy) return;
  setBusy(true, "Installing profile-verified key…");
  try {
    const { response, result } = await postJson("/api/install-recovered-key");
    if (response.ok) {
      showModal("Operational key installed", result.message || "The profile-verified recovered key is now installed.");
    } else {
      showModal("Installation blocked", result.message || "Target profile gates are not complete.");
    }
  } catch (error) {
    showModal("Installation blocked", String(error));
  } finally {
    setBusy(false);
    await refreshDashboard();
  }
}

async function clearRecoveryData() {
  hideModal();
  if (state.busy) return;
  setBusy(true, "Clearing recovery data…");
  try {
    const { response, result } = await postJson("/api/clear-cache");
    if (!response.ok) showModal("Could not clear data", result.message || "The cache could not be cleared.");
  } catch (error) {
    showModal("Could not clear data", String(error));
  } finally {
    setBusy(false);
    await refreshDashboard();
  }
}

async function uninstallKey() {
  hideModal();
  if (state.busy) return;
  setBusy(true, "Uninstalling key…");
  try {
    const { response, result } = await postJson("/api/uninstall");
    if (!response.ok) showModal("Could not uninstall key", result.message || "The installed key could not be removed.");
  } catch (error) {
    showModal("Could not uninstall key", String(error));
  } finally {
    setBusy(false);
    await refreshDashboard();
  }
}

function confirmReboot(actionName, action) {
  showModal(action.label || "Confirm action", action.prompt || "Continue?", [
    { label: "Cancel" },
    {
      label: "Confirm",
      kind: actionName === "retry" ? "primary" : "danger",
      onClick: () => runReboot(actionName),
    },
  ]);
}

async function runReboot(actionName) {
  hideModal();
  if (state.busy) return;
  setBusy(true, "Preparing reboot…");
  try {
    const { response, result } = await postJson("/api/reboot", { action: actionName }, 30000);
    if (!response.ok || result.dry_run) {
      showModal(result.title || "Reboot action", result.message || "Action completed.");
    }
  } catch (error) {
    showModal("Connection closed", "The device may already be rebooting. If it does not return, reconnect to the TSK Manager after boot.");
  } finally {
    setBusy(false);
  }
}

for (const item of document.querySelectorAll("[data-view]")) {
  item.addEventListener("click", () => selectView(item.dataset.view));
}

for (const item of document.querySelectorAll("[data-open-view]")) {
  item.addEventListener("click", () => selectView(item.dataset.openView));
}

els.clearCacheBtn.addEventListener("click", () => {
  if (els.clearCacheBtn.disabled) return;
  showModal("Clear recovery data?", "Delete the captured CAN oracle and DataFlash dump. The installed key is not removed.", [
    { label: "Cancel" },
    { label: "Clear data", kind: "danger", onClick: clearRecoveryData },
  ]);
});

els.uninstallBtn.addEventListener("click", () => {
  if (els.uninstallBtn.disabled) return;
  showModal("Uninstall SecOC key?", `Remove the installed key from openpilot?\n\n${formatKey(state.dashboard?.key?.key || "")}`, [
    { label: "Cancel" },
    { label: "Uninstall", kind: "danger", onClick: uninstallKey },
  ]);
});

els.modalOverlay.addEventListener("click", (event) => {
  if (event.target === els.modalOverlay) hideModal();
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && els.modalOverlay.classList.contains("visible")) hideModal();
});

window.addEventListener("hashchange", () => selectView(currentView(), false));

selectView(currentView(), false);
refreshHealth();
refreshDashboard();
window.setInterval(refreshDashboard, 1000);
window.setInterval(refreshHealth, 5000);
