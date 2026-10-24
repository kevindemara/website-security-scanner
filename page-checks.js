/* This function is injected in Chrome's isolated world. Keep it self-contained. */
function inspectPage(expectedUrl) {
  if (location.href !== expectedUrl)
    throw new Error(
      "The page changed during the scan. Scan the current page again.",
    );
  const clean = (value) => {
    try {
      const u = new URL(value, location.href);
      return ["http:", "https:"].includes(u.protocol)
        ? u.origin + u.pathname.slice(0, 200)
        : u.protocol;
    } catch {
      return "Invalid URL";
    }
  };
  const mixed = new Map();
  if (location.protocol === "https:") {
    const add = (value, kind) => {
      try {
        const u = new URL(value, location.href);
        if (u.protocol === "http:")
          mixed.set(clean(u.href), { url: clean(u.href), kind });
      } catch {
        /* Unparseable resource. */
      }
    };
    for (const el of Array.from(
      document.querySelectorAll(
        'script[src],img[src],img[srcset],iframe[src],link[rel="stylesheet"][href],audio[src],video[src],source[src],source[srcset]',
      ),
    ).slice(0, 1000)) {
      add(
        el.getAttribute("src") || el.getAttribute("href"),
        el.tagName.toLowerCase(),
      );
      for (const source of (el.getAttribute("srcset") || "")
        .split(",")
        .slice(0, 100))
        add(source.trim().split(/\s+/)[0], el.tagName.toLowerCase());
    }
    for (const entry of performance.getEntriesByType("resource").slice(0, 1000))
      add(entry.name, entry.initiatorType);
  }
  const forms = [];
  for (const form of Array.from(document.forms).slice(0, 100)) {
    const elements = Array.from(form.elements).slice(0, 1000);
    const password = elements.some((el) =>
      el.matches('input[type="password"]'),
    );
    const destinations = [
      form,
      ...elements
        .filter(
          (el) =>
            el.hasAttribute("formaction") || el.hasAttribute("formmethod"),
        )
        .slice(0, 20),
    ];
    for (const destination of destinations) {
      const actionValue =
        destination === form
          ? form.getAttribute("action") || location.href
          : destination.getAttribute("formaction") ||
            form.getAttribute("action") ||
            location.href;
      let action;
      try {
        action = new URL(actionValue, document.baseURI);
      } catch {
        forms.push({
          severity: "warning",
          reason: "Invalid form destination.",
          action: "Invalid URL",
        });
        continue;
      }
      const method = (
        destination === form
          ? form.method || "get"
          : destination.getAttribute("formmethod") || form.method || "get"
      ).toLowerCase();
      const insecure =
        (password && location.protocol !== "https:") ||
        action.protocol === "http:" ||
        !["http:", "https:"].includes(action.protocol) ||
        (password && method !== "post");
      const external = password && action.origin !== location.origin;
      if (insecure || external)
        forms.push({
          severity: insecure ? "failed" : "warning",
          reason: insecure
            ? "Unencrypted form, unsafe destination, or password submitted without POST."
            : "Password form submits to another origin; verify this sign-in provider.",
          action: clean(action.href),
          method,
          passwordField: password,
        });
    }
  }
  const detachedPasswords = Array.from(
    document.querySelectorAll('input[type="password"]'),
  ).some((input) => !input.form);
  if (detachedPasswords && location.protocol !== "https:")
    forms.push({
      severity: "failed",
      reason: "Password field on an unencrypted page (no form element).",
      action: location.origin,
    });
  return {
    protocol: location.protocol,
    mixed: [...mixed.values()].slice(0, 20),
    mixedCount: mixed.size,
    forms: forms.slice(0, 20),
    formCount: forms.length,
    failedForms: forms.filter((form) => form.severity === "failed").length,
    inspectedForms: Math.min(document.forms.length, 100),
    limitation:
      "Inspects the current top-level DOM and recorded resource requests only. Does not observe future interactions, shadow DOM, or forms inside frames. At most 100 forms, 1,000 controls per form, 20 submission overrides per form, and 1,000 resources of each kind are inspected.",
  };
}
function pageResults(data) {
  const C = globalThis.ScannerCore;
  const failed =
    data.failedForms > 0 ||
    data.forms.some((form) => form.severity === "failed");
  return {
    mixedContent:
      data.protocol !== "https:"
        ? C.skipped(
            "Mixed content applies to HTTPS pages. This page uses HTTP.",
          )
        : C.result(
            data.mixedCount ? "failed" : "passed",
            data.mixedCount ? 0 : 10,
            data.mixedCount
              ? `${data.mixedCount} HTTP resource references detected on this HTTPS page.`
              : "No HTTP resource references found in the inspected page.",
            { resources: data.mixed, limitation: data.limitation },
          ),
    forms: C.result(
      failed ? "failed" : data.formCount ? "warning" : "passed",
      failed ? 0 : data.formCount ? 5 : 10,
      data.formCount
        ? `${data.formCount} potentially unsafe form or password configurations found.`
        : `No unsafe configuration found in ${data.inspectedForms} inspected forms.`,
      { findings: data.forms, limitation: data.limitation },
    ),
  };
}
if (typeof module !== "undefined")
  module.exports = { inspectPage, pageResults };
