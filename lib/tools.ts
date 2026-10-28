import "server-only";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);

/** External command-line tools B24-engine can use when they are installed on this machine. */
export const TOOL_INFO: Record<string, { purpose: string; install: string }> = {
  subfinder: {
    purpose: "Passive subdomain discovery (ProjectDiscovery)",
    install: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
  },
  assetfinder: {
    purpose: "Passive subdomain discovery (tomnomnom)",
    install: "go install github.com/tomnomnom/assetfinder@latest",
  },
  findomain: {
    purpose: "Passive subdomain discovery (Findomain)",
    install: "Download a release from https://github.com/Findomain/Findomain/releases and put it on your PATH",
  },
  nuclei: {
    purpose: "Information-gathering templates only: technology and panel detection (no vulnerability templates)",
    install: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
  },
};

export interface ToolStatus {
  name: string;
  installed: boolean;
  path: string | null;
  purpose: string;
  install: string;
}

export async function toolPath(name: string): Promise<string | null> {
  if (!/^[a-z0-9_-]+$/i.test(name)) return null;
  try {
    const { stdout } = await exec(process.platform === "win32" ? "where" : "which", [name], { timeout: 4000 });
    return stdout.split(/\r?\n/)[0].trim() || null;
  } catch {
    return null;
  }
}

export async function toolStatuses(): Promise<ToolStatus[]> {
  return Promise.all(
    Object.entries(TOOL_INFO).map(async ([name, info]) => {
      const path = await toolPath(name);
      return { name, installed: !!path, path, purpose: info.purpose, install: info.install };
    }),
  );
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
