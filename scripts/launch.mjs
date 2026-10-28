// One-step local launcher for B24-engine.
// First run: installs dependencies and builds. Later runs: starts the server and opens the browser.
import { existsSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { platform } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
process.chdir(root);
const win = platform() === "win32";
const PORT = process.env.PORT || "3000";
const url = `http://localhost:${PORT}`;

function run(cmd, args) {
  const r = spawnSync(cmd, args, { stdio: "inherit", shell: win });
  return r.status === 0;
}

console.log("B24-engine");
if (!existsSync(path.join(root, "node_modules"))) {
  console.log("\n[1/2] Installing dependencies (first run only)...");
  if (!run("npm", ["install"])) process.exit(1);
}
if (!existsSync(path.join(root, ".next", "BUILD_ID"))) {
  console.log("\n[2/2] Building the app (first run only)...");
  if (!run("npm", ["run", "build"])) process.exit(1);
}

function openBrowser() {
  const cmd = platform() === "darwin" ? ["open", [url]] : win ? ["cmd", ["/c", "start", "", url]] : ["xdg-open", [url]];
  try {
    const child = spawn(cmd[0], cmd[1], { stdio: "ignore", detached: true, shell: false });
    child.on("error", () => console.log(`Open ${url} in your browser.`));
    child.unref();
  } catch {
    /* no browser launcher: the URL is printed below */
  }
}

console.log(`\nStarting B24-engine at ${url}  (Ctrl+C to stop)`);
console.log("Tip: open it once in Chrome or Edge and use 'Install' to get a desktop icon.\n");
setTimeout(openBrowser, 3500);
const child = spawn("npm", ["start"], { stdio: "inherit", shell: win, env: { ...process.env, PORT } });
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => child.kill(sig));
child.on("exit", (code) => process.exit(code ?? 0));
