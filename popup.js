"use strict";
const C = ScannerCore;
const $ = (id) => document.getElementById(id);
let tabId = null,
  currentConfig,
  currentReport,
  currentJob,
  viewingHistory = false,
  polling = false;
let history = [],
  renderedId = null,
  currentTabName = "";
function notice(message = "", error = false) {
  $("notice").textContent = message;
  $("notice").hidden = !message;
  $("notice").classList.toggle("error", error);
}
async function send(action, payload = {}) {
  const response = await chrome.runtime.sendMessage({ action, ...payload });
  if (!response)
    throw new Error(
      "The extension did not respond. Reload it from chrome://extensions and try again.",
    );
  if (response.error) throw new Error(response.error);
  return response;
}
function showPanel(name) {
  for (const section of ["scan", "history", "settings"]) {
    $("panel-" + section).hidden = name !== section;
    $("tab-" + section).setAttribute("aria-selected", String(name === section));
    $("tab-" + section).tabIndex = name === section ? 0 : -1;
  }
  if (name === "history")
    loadHistory().catch((error) => notice(error.message, true));
}
for (const name of ["scan", "history", "settings"])
  $("tab-" + name).addEventListener("click", () => showPanel(name));
document
  .querySelector('[role="tablist"]')
  .addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const names = ["scan", "history", "settings"],
      index = names.findIndex(
        (name) => $("tab-" + name) === document.activeElement,
      );
    const next =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? 2
          : (index + (event.key === "ArrowRight" ? 1 : -1) + 3) % 3;
    showPanel(names[next]);
    $("tab-" + names[next]).focus();
  });
function fillSettings(config) {
  currentConfig = config;
  $("external-services").checked = config.settings.externalServices;
  $("google-api-key").value = config.apiKeys.googleSafeBrowsing;
  $("virustotal-api-key").value = config.apiKeys.virusTotal;
  $("save-history").checked = config.settings.saveHistory;
  $("show-badge").checked = config.settings.showBadge;
  $("cache-minutes").value = String(config.settings.cacheMinutes);
  $("check-settings").replaceChildren();
  for (const [key, definition] of Object.entries(C.CHECKS)) {
    const label = document.createElement("label");
    label.className = "toggle";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.id = "enable-" + key;
    input.checked =
      config.settings.checks[key] &&
      (key !== "exposedDirectories" || config.settings.directoryConsent);
    const span = document.createElement("span");
    span.textContent = definition.label;
    if (
      [
        "ssl",
        "safeBrowsing",
        "vulnerabilities",
        "emailSecurity",
        "exposedDirectories",
      ].includes(key)
    ) {
      const small = document.createElement("small");
      small.textContent =
        key === "exposedDirectories"
          ? "I am authorized to probe directories on the sites I scan."
          : "Requires external security lookups.";
      span.append(small);
    }
    label.append(input, span);
    $("check-settings").append(label);
  }
}
$("show-keys").addEventListener("change", () => {
  for (const id of ["google-api-key", "virustotal-api-key"])
    $(id).type = $("show-keys").checked ? "text" : "password";
});
$("settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  try {
    const config = structuredClone(currentConfig);
    config.apiKeys = {
      googleSafeBrowsing: $("google-api-key").value.trim(),
      virusTotal: $("virustotal-api-key").value.trim(),
    };
    for (const [id, key] of [
      ["external-services", "externalServices"],
      ["save-history", "saveHistory"],
      ["show-badge", "showBadge"],
    ])
      config.settings[key] = $(id).checked;
    config.settings.cacheMinutes = Number($("cache-minutes").value);
    for (const key of Object.keys(C.CHECKS))
      config.settings.checks[key] = $("enable-" + key).checked;
    config.settings.directoryConsent =
      config.settings.checks.exposedDirectories;
    const response = await send("saveConfig", { config });
    currentConfig = response.config;
    resetReport();
    notice("Settings saved. Run a fresh scan to use them.");
  } catch (error) {
    notice(error.message, true);
  } finally {
    button.disabled = false;
  }
});
function renderReport(report, source) {
  currentReport = report;
  $("empty-state").hidden = true;
  $("report").hidden = false;
  $("report-source").textContent = source;
  $("report-url").textContent = report.url;
  $("scan-time").textContent = new Date(report.timestamp).toLocaleString();
  $("overall-score").textContent = report.overallScore ?? "—";
  $("coverage-text").textContent = report.coverage + "%";
  $("coverage").value = report.coverage;
  $("assessed-text").textContent =
    `${report.assessedWeight} of ${report.totalWeight} weighted points assessed`;
  const scorePanel = document.querySelector(".score-panel");
  const failed = Object.values(report.checks).some(
    (check) => check.status === "failed",
  );
  scorePanel.classList.toggle(
    "failed",
    failed ||
      report.threatDetected ||
      (report.overallScore !== null && report.overallScore < 50),
  );
  scorePanel.classList.toggle(
    "warning",
    !failed &&
      !report.threatDetected &&
      (report.coverage < 75 ||
        (report.overallScore !== null && report.overallScore < 80)),
  );
  $("score-explanation").textContent = report.threatDetected
    ? "A reputation service flagged this site. The score is capped at 20. Review the threat finding before continuing."
    : "The score uses completed checks only. Skipped or unavailable checks do not earn points. High scores with low coverage are incomplete.";
  const comparison = report.comparison;
  $("comparison").hidden = !comparison;
  $("comparison-details").hidden = !comparison?.changes?.length;
  $("comparison-changes").replaceChildren();
  for (const change of comparison?.changes || []) {
    const li = document.createElement("li");
    li.textContent = `${C.CHECKS[change.check]?.label || change.check}: ${change.before} (${change.beforeScore ?? "—"}) → ${change.after} (${change.afterScore ?? "—"})`;
    $("comparison-changes").append(li);
  }
  if (comparison)
    $("comparison").textContent = comparison.comparable
      ? `${comparison.scoreDelta > 0 ? "+" : ""}${comparison.scoreDelta ?? "—"} points since ${new Date(comparison.previousTimestamp).toLocaleString()}. ${comparison.changes.length} checks changed.`
      : `Previous scan: ${new Date(comparison.previousTimestamp).toLocaleString()}. Scores are not directly comparable because the page, settings, or assessed checks changed. ${comparison.changes.length} checks changed.`;
  $("checks").replaceChildren();
  for (const [key, definition] of Object.entries(C.CHECKS)) {
    const check = report.checks[key];
    if (!check) continue;
    const details = document.createElement("details");
    details.dataset.check = key;
    const summary = document.createElement("summary");
    const label = document.createElement("span");
    label.className = "label";
    label.textContent = definition.label;
    const status = document.createElement("span");
    status.className = "status " + check.status;
    status.textContent =
      check.status === "error"
        ? "Unavailable"
        : check.status[0].toUpperCase() + check.status.slice(1);
    const points = document.createElement("span");
    points.className = "points";
    points.textContent = `${check.score ?? "—"}/${definition.max}`;
    summary.append(label, status, points);
    const body = document.createElement("div");
    body.className = "detail-body";
    const message = document.createElement("p");
    message.textContent = check.details.message;
    body.append(message);
    const extra = { ...check.details };
    delete extra.message;
    if (Object.keys(extra).length) {
      const pre = document.createElement("pre");
      pre.textContent = JSON.stringify(extra, null, 2);
      body.append(pre);
    }
    details.append(summary, body);
    $("checks").append(details);
  }
  $("advice-list").replaceChildren();
  for (const item of report.recommendations || []) {
    const li = document.createElement("li");
    const priority = document.createElement("span");
    priority.className = "priority";
    priority.textContent = item.priority + " priority";
    const strong = document.createElement("strong");
    strong.textContent = item.title;
    const advice = document.createElement("span");
    advice.textContent = item.advice;
    li.append(priority, strong, advice);
    $("advice-list").append(li);
  }
  $("no-advice").hidden = !!report.recommendations?.length;
  $("export-json").disabled = !report.id;
  $("export-html").disabled = !report.id;
}
function applyJob(job) {
  currentJob = job;
  const scanning = job?.status === "running";
  $("scan-button").disabled = tabId === null || scanning;
  $("fresh-button").disabled = tabId === null || scanning;
  $("cancel-button").hidden = !scanning;
  $("scan-progress").hidden = !scanning;
  if (scanning) {
    $("progress").value = job.completed;
    $("progress-label").textContent = `${job.completed} / ${job.total}`;
    if (!viewingHistory) {
      const partial = {
        url: currentTabName,
        timestamp: new Date(job.startedAt).toISOString(),
        checks: job.checks,
        ...C.scoreReport(job.checks),
        recommendations: C.recommendations(job.checks),
      };
      renderReport(partial, "Scan in progress");
    }
  } else if (job?.report && !viewingHistory && renderedId !== job.id) {
    renderedId = job.id;
    renderReport(
      job.report,
      job.status === "cancelled"
        ? "Partial scan · not saved"
        : job.cached
          ? "Cached scan · use Scan fresh to update"
          : "Latest scan",
    );
    if (job.message) notice(job.message, true);
  } else if (job?.status === "error") notice(job.message, true);
}
async function scan(force) {
  viewingHistory = false;
  renderedId = null;
  notice();
  $("scan-button").disabled = true;
  $("fresh-button").disabled = true;
  try {
    const response = await send("startScan", { tabId, force });
    applyJob(response.job);
  } catch (error) {
    notice(error.message, true);
    applyJob(null);
  }
}
$("scan-button").addEventListener("click", () => scan(false));
$("fresh-button").addEventListener("click", () => scan(true));
$("cancel-button").addEventListener("click", async () => {
  try {
    const response = await send("cancelScan", { tabId });
    applyJob(response.job);
  } catch (error) {
    notice(error.message, true);
  }
});
async function loadHistory() {
  history = (await send("getHistory")).history;
  renderHistory();
}
function renderHistory() {
  const search = $("history-search").value.trim().toLowerCase();
  $("history-list").replaceChildren();
  const matches = history.filter((report) =>
    report.url.toLowerCase().includes(search),
  );
  if (!matches.length) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = history.length
      ? "No reports match this hostname."
      : "No saved scans. Scan a website to start your history.";
    $("history-list").append(p);
  }
  for (const report of matches) {
    const row = document.createElement("div");
    row.className = "history-row";
    const open = document.createElement("button");
    open.className = "history-open";
    const name = document.createElement("span");
    name.textContent = report.url;
    const meta = document.createElement("span");
    meta.className = "muted";
    meta.textContent = `${new Date(report.timestamp).toLocaleString()} · ${report.overallScore ?? "—"}/100 · ${report.coverage}% coverage`;
    open.append(name, meta);
    open.addEventListener("click", () => {
      viewingHistory = true;
      notice();
      renderReport(report, "Saved report");
      showPanel("scan");
    });
    const remove = document.createElement("button");
    remove.className = "history-delete danger";
    remove.textContent = "Delete";
    remove.setAttribute("aria-label", "Delete report for " + report.url);
    remove.addEventListener("click", async () => {
      try {
        await send("deleteReport", { id: report.id });
        if (currentReport?.id === report.id) resetReport();
        await loadHistory();
        notice("Report deleted.");
      } catch (error) {
        notice(error.message, true);
      }
    });
    row.append(open, remove);
    $("history-list").append(row);
  }
}
function resetReport() {
  currentReport = null;
  currentJob = null;
  viewingHistory = false;
  renderedId = null;
  $("report").hidden = true;
  $("empty-state").hidden = false;
  applyJob(null);
}
$("history-search").addEventListener("input", renderHistory);
$("clear-history").addEventListener("click", async () => {
  if (
    !confirm(
      "Delete all saved and cached reports and stop active scans? Your API settings will be kept.",
    )
  )
    return;
  try {
    await send("clearHistory");
    resetReport();
    await loadHistory();
    notice("All scan data cleared.");
  } catch (error) {
    notice(error.message, true);
  }
});
function download(format) {
  if (!currentReport?.id) {
    notice("Wait for the scan to finish before exporting.", true);
    return;
  }
  const blob = new Blob(
    [
      format === "json"
        ? JSON.stringify(C.publicReport(currentReport), null, 2)
        : C.reportHtml(currentReport),
    ],
    { type: format === "json" ? "application/json" : "text/html" },
  );
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `security-report-${new URL(currentReport.url).hostname.replace(/[^a-z0-9.-]/gi, "_")}-${currentReport.timestamp.slice(0, 10)}.${format}`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}
$("export-json").addEventListener("click", () => download("json"));
$("export-html").addEventListener("click", () => download("html"));
(async () => {
  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    try {
      currentTabName = C.sanitizeUrl(tab?.url, true);
      if (
        ["chromewebstore.google.com", "chrome.google.com"].includes(
          new URL(currentTabName).hostname,
        )
      )
        throw new Error("Restricted page");
      tabId = tab.id;
      $("current-url").textContent = currentTabName;
    } catch {
      $("current-url").textContent =
        "Open a regular HTTP or HTTPS website to scan.";
    }
    const state = await send("getState", { tabId });
    fillSettings(state.config);
    applyJob(state.job);
  } catch (error) {
    notice(error.message, true);
  }
})();
setInterval(async () => {
  if (polling || !currentJob || currentJob.status !== "running") return;
  polling = true;
  try {
    const state = await send("getState", { tabId });
    if (!state.job) {
      resetReport();
      notice("Scan data was cleared or the page changed.");
    } else applyJob(state.job);
  } catch (error) {
    notice(error.message, true);
  } finally {
    polling = false;
  }
}, 700);
