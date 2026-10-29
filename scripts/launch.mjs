// One-step local launcher for B24-engine.
// First run: installs dependencies and builds. Later runs: starts the server and opens the browser.
import { existsSync, rmSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import { platform } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
process.chdir(root);
const win = platform() === "win32";

// Returns true when nothing is listening on the port. Checked before starting, so an old B24 window
// still running on the port does not make the new start fail silently.
function portFree(port) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once("error", () => resolve(false));
    probe.once("listening", () => probe.close(() => resolve(true)));
    probe.listen(port);
  });
}

async function pickPort(start) {
  for (let p = start; p < start + 20; p++) if (await portFree(p)) return p;
  return null;
}

const requested = Number(process.env.PORT) || 3000;
const PORT = String((await pickPort(requested)) ?? requested);
const url = `http://localhost:${PORT}`;
if (PORT !== String(requested)) console.log(`\nPort ${requested} is already in use (an earlier B24-engine may still be running). Using port ${PORT} instead.`);

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
  // A leftover .next from an older copy (or `next dev`) holds generated types for pages that
  // no longer exist, which fails the type check. Start the build from a clean folder.
  rmSync(path.join(root, ".next"), { recursive: true, force: true });
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
