const fs = require("node:fs"),
  path = require("node:path"),
  cp = require("node:child_process"),
  assert = require("node:assert/strict");
const root = path.resolve(__dirname, ".."),
  files = require("./release-files.cjs");
process.chdir(root);
for (const file of files) {
  assert.ok(fs.existsSync(file), "Missing release file: " + file);
  if (file.endsWith(".js"))
    cp.execFileSync(process.execPath, ["--check", file]);
}
const m = JSON.parse(fs.readFileSync("manifest.json", "utf8")),
  c = JSON.parse(fs.readFileSync("config.json", "utf8"));
assert.equal(m.version, "1.0.5");
assert.equal(m.manifest_version, 3);
assert.equal(m.version, require("../package.json").version);
assert.ok(m.description.length <= 132);
assert.deepEqual(m.permissions.slice().sort(), [
  "activeTab",
  "scripting",
  "storage",
]);
assert.ok(
  m.host_permissions.every(
    (host) => !host.includes("*://") && !host.includes("https://*"),
  ),
);
assert.equal(m.web_accessible_resources, undefined);
assert.ok(
  Object.values(c.apiKeys).every((key) => key === ""),
  "Never package API keys.",
);
for (const [dimension, file] of Object.entries(m.icons)) {
  const b = fs.readFileSync(file);
  assert.equal(b.readUInt32BE(16), Number(dimension));
  assert.equal(b.readUInt32BE(20), Number(dimension));
}
for (const page of ["popup.html", "privacy.html"]) {
  const text = fs.readFileSync(page, "utf8");
  assert.doesNotMatch(text, /<script[^>]+src=["']https?:/i);
  assert.doesNotMatch(text, /\son\w+\s*=/i);
  const ids = [...text.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]);
  assert.equal(new Set(ids).size, ids.length, "Duplicate IDs in " + page);
  for (const m of text.matchAll(/(?:src|href)="([^"]+)"/g)) {
    if (!/^(https?:|mailto:|#)/.test(m[1]))
      assert.ok(files.includes(m[1]), "Asset missing from release: " + m[1]);
  }
}
for (const file of files.filter((f) => f.endsWith(".js")))
  assert.doesNotMatch(
    fs.readFileSync(file, "utf8"),
    /\beval\s*\(|new Function\s*\(/,
    "Remote/evaluated code is not permitted in release.",
  );
console.log(
  "Release validation passed: " +
    files.length +
    " allowlisted files, version 1.0.5, icons, local assets, syntax, CSP-compatible scripts, and no embedded keys.",
);
