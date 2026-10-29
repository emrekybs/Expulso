import "server-only";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);

// Installs tools from their GitHub releases into data/tools/bin, so the panel can install them with one
// click. Linux only, no sudo, no package manager. Only the fixed catalogue in lib/tools.ts reaches here.

export const TOOLS_DIR = path.join(process.cwd(), "data", "tools");
export const BIN_DIR = path.join(TOOLS_DIR, "bin");
const TMP_DIR = path.join(TOOLS_DIR, "tmp");

export interface ReleaseSpec {
  /** owner/repo on GitHub. */
  repo: string;
  /** Regular expression (source) that picks the Linux amd64 asset from the latest release. */
  asset: string;
  kind: "zip" | "tar.gz" | "sqlmap";
  /** File name of the binary inside the archive. */
  binary: string;
}

export interface InstallResult {
  ok: boolean;
  name: string;
  path?: string;
  log: string[];
  error?: string;
}

/** The asset of the latest release whose name matches the spec. Pure, so it can be unit tested. */
export function pickAsset<T extends { name: string }>(assets: T[], pattern: string): T | undefined {
  const re = new RegExp(pattern);
  return assets.find((a) => re.test(a.name));
}

/** Depth-first search for a file with the given name. */
export function findFileIn(dir: string, name: string): string | null {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isFile() && entry.name === name) return full;
    if (entry.isDirectory()) {
      const found = findFileIn(full, name);
      if (found) return found;
    }
  }
  return null;
}

async function latestAsset(spec: ReleaseSpec): Promise<{ url: string; name: string; tag: string }> {
  const res = await fetch(`https://api.github.com/repos/${spec.repo}/releases/latest`, {
    headers: { accept: "application/vnd.github+json", "user-agent": "B24-engine" },
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`GitHub answered HTTP ${res.status} for ${spec.repo}. Try again later.`);
  const rel = (await res.json()) as { tag_name: string; assets: { name: string; browser_download_url: string }[] };
  const asset = pickAsset(rel.assets, spec.asset);
  if (!asset) throw new Error(`${rel.tag_name} of ${spec.repo} has no Linux amd64 asset.`);
  return { url: asset.browser_download_url, name: asset.name, tag: rel.tag_name };
}

async function download(url: string, dest: string): Promise<void> {
  const res = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(300000) });
  if (!res.ok) throw new Error(`Download failed (HTTP ${res.status}).`);
  await fsp.writeFile(dest, Buffer.from(await res.arrayBuffer()));
}

async function extract(archive: string, kind: "zip" | "tar.gz", dest: string): Promise<void> {
  await fsp.mkdir(dest, { recursive: true });
  if (kind === "zip") await exec("python3", ["-m", "zipfile", "-e", archive, dest], { timeout: 120000 });
  else await exec("tar", ["-xzf", archive, "-C", dest], { timeout: 120000 });
}

/** Installs the latest release of one tool. Returns a log the UI shows, so failures are visible. */
export async function installRelease(name: string, spec: ReleaseSpec): Promise<InstallResult> {
  const log: string[] = [];
  try {
    await fsp.mkdir(BIN_DIR, { recursive: true });
    await fsp.mkdir(TMP_DIR, { recursive: true });

    if (spec.kind === "sqlmap") {
      log.push("Downloading sqlmap (master branch archive)");
      const archive = path.join(TMP_DIR, "sqlmap.zip");
      const extractTo = path.join(TMP_DIR, "sqlmap-x");
      await download("https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip", archive);
      await fsp.rm(extractTo, { recursive: true, force: true });
      await extract(archive, "zip", extractTo);
      const dir = fs.readdirSync(extractTo).map((d) => path.join(extractTo, d)).find((d) => fs.existsSync(path.join(d, "sqlmap.py")));
      if (!dir) throw new Error("sqlmap.py was not found in the archive.");
      const target = path.join(TOOLS_DIR, "sqlmap");
      await fsp.rm(target, { recursive: true, force: true });
      await fsp.rename(dir, target);
      await fsp.rm(TMP_DIR, { recursive: true, force: true });
      log.push(`Installed to ${target}. sqlmap runs with python3.`);
      return { ok: true, name, path: path.join(target, "sqlmap.py"), log };
    }

    log.push(`Looking up the latest ${spec.repo} release`);
    const asset = await latestAsset(spec);
    log.push(`Downloading ${asset.name} (${asset.tag})`);
    const archive = path.join(TMP_DIR, asset.name);
    await download(asset.url, archive);
    const extractTo = path.join(TMP_DIR, `${name}-x`);
    await fsp.rm(extractTo, { recursive: true, force: true });
    await extract(archive, spec.kind, extractTo);
    const found = findFileIn(extractTo, spec.binary);
    if (!found) throw new Error(`${spec.binary} was not found in ${asset.name}.`);
    const dest = path.join(BIN_DIR, spec.binary);
    await fsp.copyFile(found, dest);
    await fsp.chmod(dest, 0o755);
    await fsp.rm(TMP_DIR, { recursive: true, force: true });
    log.push(`Installed ${asset.tag} to ${dest}`);
    return { ok: true, name, path: dest, log };
  } catch (e) {
    const error = (e as Error).message || "Install failed.";
    log.push(`Failed: ${error}`);
    await fsp.rm(TMP_DIR, { recursive: true, force: true }).catch(() => undefined);
    return { ok: false, name, log, error };
  }
}
