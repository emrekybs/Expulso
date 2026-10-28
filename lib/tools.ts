import "server-only";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
const WIN = process.platform === "win32";
const PY = WIN ? "python" : "python3";

export interface ToolDef {
  purpose: string;
  install: string;
  /** Arguments that print the version. null when the tool has no such flag. */
  versionArgs: string[] | null;
  /** Commands that update the tool. Run in order, stopping at the first failure. */
  update?: { label: string; steps: string[][] };
  /** Shown instead of an update button when there is no safe command to run. */
  updateNote?: string;
  /** Used by a module when installed. The module falls back to its built-in engine otherwise. */
  usedBy?: string;
}

/** External command-line tools B24-engine can use when they are installed on this machine. */
export const TOOL_INFO: Record<string, ToolDef> = {
  subfinder: {
    purpose: "Passive subdomain discovery (ProjectDiscovery)",
    install: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    versionArgs: ["-version"],
    update: { label: "Update with go install", steps: [["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"]] },
    usedBy: "Subdomains",
  },
  assetfinder: {
    purpose: "Passive subdomain discovery (tomnomnom)",
    install: "go install github.com/tomnomnom/assetfinder@latest",
    versionArgs: null,
    update: { label: "Update with go install", steps: [["go", "install", "github.com/tomnomnom/assetfinder@latest"]] },
    usedBy: "Subdomains",
  },
  findomain: {
    purpose: "Passive subdomain discovery (Findomain)",
    install: "Download a release from https://github.com/Findomain/Findomain/releases and put it on your PATH",
    versionArgs: ["--version"],
    updateNote: "Download the newest release from GitHub and replace the file.",
    usedBy: "Subdomains",
  },
  amass: {
    purpose: "Passive subdomain discovery (OWASP Amass)",
    install: "go install -v github.com/owasp-amass/amass/v4/...@master",
    versionArgs: ["-version"],
    update: { label: "Update with go install", steps: [["go", "install", "-v", "github.com/owasp-amass/amass/v4/...@master"]] },
    usedBy: "Subdomains",
  },
  nuclei: {
    purpose: "Information-gathering templates only: technology and panel detection (no vulnerability templates)",
    install: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
    versionArgs: ["-version"],
    update: {
      label: "Update binary and templates",
      steps: [
        ["nuclei", "-update"],
        ["nuclei", "-update-templates"],
      ],
    },
    usedBy: "nuclei (info only)",
  },
  nmap: {
    purpose: "Service and version detection for open ports",
    install: "sudo apt install nmap   (macOS: brew install nmap · Windows: winget install Insecure.Nmap)",
    versionArgs: ["--version"],
    updateNote: "Update through your package manager (apt, brew or winget).",
    usedBy: "Port Scan (service and version detection)",
  },
  feroxbuster: {
    purpose: "Fast directory and file discovery",
    install: "Download from https://github.com/epi052/feroxbuster/releases, or: cargo install feroxbuster",
    versionArgs: ["--version"],
    update: { label: "Self-update", steps: [["feroxbuster", "--update"]] },
    usedBy: "Directories",
  },
  dirsearch: {
    purpose: "Directory and file discovery",
    install: `${PY} -m pip install dirsearch`,
    versionArgs: ["--version"],
    update: { label: "Update with pip", steps: [[PY, "-m", "pip", "install", "-U", "dirsearch"]] },
    usedBy: "Directories",
  },
};

export interface ToolStatus {
  name: string;
  status: "ok" | "missing" | "error";
  installed: boolean;
  path: string | null;
  version: string | null;
  error?: string;
  purpose: string;
  install: string;
  usedBy?: string;
  updatable: boolean;
  updateLabel?: string;
  updateNote?: string;
}

export async function toolPath(name: string): Promise<string | null> {
  if (!/^[a-z0-9_-]+$/i.test(name)) return null;
  try {
    const { stdout } = await exec(WIN ? "where" : "which", [name], { timeout: 4000 });
    return stdout.split(/\r?\n/)[0].trim() || null;
  } catch {
    return null;
  }
}

function firstLine(text: string): string | null {
  return text.split(/\r?\n/).map((l) => l.trim()).find(Boolean)?.slice(0, 120) ?? null;
}

async function versionOf(path: string, args: string[] | null): Promise<{ version: string | null; error?: string }> {
  if (!args) return { version: "installed (no version flag)" };
  try {
    const { stdout, stderr } = await exec(path, args, { timeout: 8000, shell: WIN });
    return { version: firstLine(`${stdout}\n${stderr}`) };
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string; killed?: boolean; code?: number | string };
    const out = firstLine(`${err.stdout ?? ""}\n${err.stderr ?? ""}`);
    if (out) return { version: out };
    return { version: null, error: err.killed ? "Version check timed out." : `Version check failed (exit ${String(err.code ?? "?")}).` };
  }
}

async function statusOf(name: string, def: ToolDef): Promise<ToolStatus> {
  const base = {
    name,
    purpose: def.purpose,
    install: def.install,
    usedBy: def.usedBy,
    updatable: !!def.update,
    updateLabel: def.update?.label,
    updateNote: def.updateNote,
  };
  const path = await toolPath(name);
  if (!path) return { ...base, status: "missing", installed: false, path: null, version: null };
  const v = await versionOf(path, def.versionArgs);
  return v.error
    ? { ...base, status: "error", installed: true, path, version: null, error: v.error }
    : { ...base, status: "ok", installed: true, path, version: v.version };
}

export async function toolStatuses(): Promise<ToolStatus[]> {
  return Promise.all(Object.entries(TOOL_INFO).map(([name, def]) => statusOf(name, def)));
}

export interface ToolRun {
  ok: boolean;
  lines: string[];
  error?: string;
}

/**
 * Runs an installed tool and returns its stdout lines. Tools often exit non-zero or are cut by the
 * timeout after printing useful output, so partial stdout is still returned.
 */
export async function runTool(name: string, args: string[], timeoutMs: number): Promise<ToolRun> {
  const path = await toolPath(name);
  if (!path) return { ok: false, lines: [], error: `${name} is not installed. Install it with: ${TOOL_INFO[name]?.install ?? "see the tool's documentation"}` };
  try {
    const { stdout } = await exec(path, args, { timeout: timeoutMs, maxBuffer: 50 * 1024 * 1024 });
    return { ok: true, lines: stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean) };
  } catch (e) {
    const err = e as { stdout?: string; killed?: boolean; code?: number | string };
    const lines = (err.stdout ?? "").split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (lines.length) return { ok: true, lines };
    return { ok: false, lines: [], error: err.killed ? `${name} timed out after ${Math.round(timeoutMs / 1000)} s.` : `${name} exited with an error (code ${String(err.code ?? "?")}).` };
  }
}

export interface UpdateResult {
  ok: boolean;
  name: string;
  steps: { command: string; ok: boolean }[];
  output: string;
  error?: string;
}

const UPDATE_TIMEOUT_MS = 900_000;
const OUTPUT_TAIL = 8000;

async function runSteps(name: string, steps: string[][]): Promise<UpdateResult> {
  const results: UpdateResult["steps"] = [];
  let output = "";
  for (const argv of steps) {
    const [cmd, ...args] = argv;
    const command = argv.join(" ");
    try {
      const { stdout, stderr } = await exec(cmd, args, { timeout: UPDATE_TIMEOUT_MS, maxBuffer: 20 * 1024 * 1024, cwd: process.cwd(), shell: WIN });
      output += `$ ${command}\n${stdout}${stderr}\n`;
      results.push({ command, ok: true });
    } catch (e) {
      const err = e as { stdout?: string; stderr?: string; code?: number | string; killed?: boolean };
      const reason = err.killed ? "Stopped: time limit reached." : err.code === "ENOENT" ? `${cmd} was not found on PATH.` : `Exited with code ${String(err.code ?? "?")}.`;
      output += `$ ${command}\n${err.stdout ?? ""}${err.stderr ?? ""}\n${reason}\n`;
      results.push({ command, ok: false });
      return { ok: false, name, steps: results, output: output.slice(-OUTPUT_TAIL), error: reason };
    }
  }
  return { ok: true, name, steps: results, output: output.slice(-OUTPUT_TAIL) };
}

/** Updates an installed tool with a fixed command from TOOL_INFO. Names outside the catalogue are refused. */
export async function runToolUpdate(name: string): Promise<UpdateResult> {
  const def = TOOL_INFO[name];
  if (!def) return { ok: false, name, steps: [], output: "", error: "Unknown tool." };
  if (!def.update) return { ok: false, name, steps: [], output: "", error: def.updateNote ?? "This tool has no automatic update." };
  if (!(await toolPath(name))) return { ok: false, name, steps: [], output: "", error: `${name} is not installed. Install it first: ${def.install}` };
  return runSteps(name, def.update.steps);
}

/** Installs the Chromium build that screenshots and PDF reports use. */
export async function runChromiumInstall(): Promise<UpdateResult> {
  return runSteps("chromium", [["npx", "playwright", "install", "chromium"]]);
}
