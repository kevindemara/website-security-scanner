const fs = require("node:fs"),
  path = require("node:path");
const { chromium } = require("playwright");
module.exports = async function launch(extension, userDataDir = "") {
  const args = [
    "--disable-extensions-except=" + extension,
    "--load-extension=" + extension,
    "--enable-unsafe-extension-debugging",
  ];
  const options = {
    headless: true,
    ignoreDefaultArgs: ["--disable-extensions"],
    args,
    acceptDownloads: true,
    viewport: { width: 460, height: 800 },
  };
  const executable =
    process.env.SCANNER_CHROMIUM_EXECUTABLE || chromium.executablePath();
  try {
    return await chromium.launchPersistentContext(userDataDir, {
      ...options,
      executablePath: executable,
    });
  } catch (error) {
    if (
      process.platform !== "win32" ||
      !error.message.includes("spawn UNKNOWN")
    )
      throw error;
    // Some Windows environments cannot resolve Chromium's private version assembly.
    // A disposable sibling copy can load the same chrome_elf.dll through the normal
    // DLL search path. Do not modify the original downloaded executable or a user's browser.
    const source = fs.readFileSync(executable),
      text = source.toString("latin1");
    const pattern =
      /<dependency><dependentAssembly><assemblyIdentity[^>]*name="\d+\.\d+\.\d+\.\d+"[^>]*\/><\/dependentAssembly><\/dependency>/g;
    const matches = [...text.matchAll(pattern)];
    if (matches.length !== 1) throw error;
    const repaired = Buffer.from(
      text.replace(pattern, (m) => " ".repeat(m.length)),
      "latin1",
    );
    const testExecutable = path.join(
      path.dirname(executable),
      "security-scanner-test-browser.exe",
    );
    if (
      !fs.existsSync(testExecutable) ||
      !fs.readFileSync(testExecutable).equals(repaired)
    )
      fs.writeFileSync(testExecutable, repaired);
    console.log(
      "Browser runtime: isolated executable copy used for Windows side-by-side assembly workaround.",
    );
    return chromium.launchPersistentContext(userDataDir, {
      ...options,
      executablePath: testExecutable,
    });
  }
};
