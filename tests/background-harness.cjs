const fs = require("node:fs"),
  path = require("node:path"),
  vm = require("node:vm"),
  { webcrypto } = require("node:crypto");
const root = path.resolve(__dirname, "..");
module.exports = async function harness({
  saved,
  session = {},
  request,
  inspect,
  clockScale = 1,
} = {}) {
  const listeners = {},
    local = saved ? { securityScannerConfig: structuredClone(saved) } : {},
    sessionData = structuredClone(session),
    badges = {},
    tabs = new Map([
      [1, { id: 1, url: "https://scanner.org/private?token=secret#fragment" }],
      [2, { id: 2, url: "https://second.org/" }],
    ]),
    calls = [];
  const area = (data) => ({
    get: async (keys) =>
      keys === null
        ? structuredClone(data)
        : Object.fromEntries(
            (Array.isArray(keys) ? keys : [keys])
              .filter((k) => k in data)
              .map((k) => [k, structuredClone(data[k])]),
          ),
    set: async (values) => Object.assign(data, structuredClone(values)),
  });
  const event = (name) => ({ addListener: (fn) => (listeners[name] = fn) });
  const timers = new Set();
  const context = vm.createContext({
    console,
    URL,
    Headers,
    Response,
    Request,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    DOMException,
    AbortController,
    ReadableStream,
    structuredClone,
    crypto: webcrypto,
    setTimeout: (fn, ms) => {
      const id = setTimeout(() => {
        timers.delete(id);
        fn();
      }, ms * clockScale);
      timers.add(id);
      return id;
    },
    clearTimeout: (id) => {
      clearTimeout(id);
      timers.delete(id);
    },
    setInterval,
    clearInterval,
    fetch: async (url, options) => {
      if (String(url).startsWith("chrome-extension://fixture/"))
        return new Response(
          fs.readFileSync(path.join(root, new URL(url).pathname.slice(1))),
        );
      calls.push({ url: String(url), options });
      if (request) return request(String(url), options);
      return new Response("", { headers: require("./fixtures.cjs").headers });
    },
    chrome: {
      runtime: {
        id: "fixture",
        getURL: (file) => "chrome-extension://fixture/" + file,
        onInstalled: event("install"),
        onMessage: event("message"),
      },
      storage: { local: area(local), session: area(sessionData) },
      tabs: {
        get: async (id) => {
          if (!tabs.has(id)) throw Error("Tab closed");
          return structuredClone(tabs.get(id));
        },
        query: async () => [...tabs.values()],
        onRemoved: event("removed"),
        onUpdated: event("updated"),
      },
      scripting: {
        executeScript: async (options) =>
          inspect
            ? inspect(options)
            : [
                {
                  result: {
                    protocol: "https:",
                    mixed: [],
                    mixedCount: 0,
                    forms: [],
                    formCount: 0,
                    inspectedForms: 0,
                    limitation: "Fixture",
                  },
                },
              ],
      },
      action: {
        setBadgeText: async ({ tabId, text }) => (badges[tabId] = text),
        setBadgeBackgroundColor: async () => {},
        setTitle: async () => {},
      },
    },
  });
  context.importScripts = (...files) =>
    files.forEach((file) =>
      vm.runInContext(fs.readFileSync(path.join(root, file), "utf8"), context, {
        filename: file,
      }),
    );
  vm.runInContext(
    fs.readFileSync(path.join(root, "background.js"), "utf8"),
    context,
    { filename: "background.js" },
  );
  await vm.runInContext("configReady", context);
  const send = (
    message,
    sender = { id: "fixture", url: "chrome-extension://fixture/popup.html" },
  ) =>
    new Promise((resolve) => {
      if (!listeners.message(message, sender, resolve)) resolve(undefined);
    });
  const wait = async (id = 1) => {
    for (let i = 0; i < 500; i++) {
      const s = await send({ action: "getState", tabId: id });
      if (s.job && s.job.status !== "running") return s.job;
      await new Promise((r) => setTimeout(r, 5));
    }
    throw Error("Scan did not finish");
  };
  const close = async () => {
    for (const id of tabs.keys())
      await send({ action: "cancelScan", tabId: id });
    for (const timer of timers) clearTimeout(timer);
  };
  return {
    send,
    wait,
    local,
    session: sessionData,
    tabs,
    calls,
    listeners,
    badges,
    context,
    close,
  };
};
