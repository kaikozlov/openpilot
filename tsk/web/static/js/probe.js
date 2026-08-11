(() => {
  const text = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };

  const routeText = (route) => {
    if (!route?.identified) return "Route not identified";
    const bus = route.tx_bus >= 0 ? `CAN ${route.tx_bus}` : "CAN ?";
    const semantic = route.semantic_path ? route.semantic_path.replace(/-/g, " ") : "route";
    return `${bus} · ${semantic}`;
  };

  async function loadContext() {
    try {
      const response = await fetch("/api/dashboard", { cache: "no-store" });
      if (!response.ok) throw new Error(`dashboard ${response.status}`);
      const dashboard = await response.json();
      const vehicle = dashboard.vehicle || {};
      text("probeVehicle", vehicle.app_sw_id || "EPS not identified");
      text("probeRoute", routeText(dashboard.route || {}));
    } catch (err) {
      text("probeVehicle", "TSK Manager");
      text("probeRoute", "Context unavailable");
    }
  }

  function clearTerminal(id = "terminal") {
    const terminal = document.getElementById(id);
    if (terminal) terminal.textContent = "";
  }

  function runButton(button, running, runningLabel = "Running…", idleLabel = null) {
    if (!button) return;
    if (idleLabel && !button.dataset.idleLabel) button.dataset.idleLabel = idleLabel;
    if (!button.dataset.idleLabel) button.dataset.idleLabel = button.textContent;
    button.disabled = running;
    button.textContent = running ? runningLabel : button.dataset.idleLabel;
  }

  window.TSKProbe = {
    loadContext,
    clearTerminal,
    runButton,
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", loadContext, { once: true });
  } else {
    loadContext();
  }
})();
