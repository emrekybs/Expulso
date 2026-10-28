// Built-in wordlists for content discovery. Kept modest so a run fits serverless time limits.

export const ADMIN_PATHS = [
  "admin", "administrator", "admin/login", "admin.php", "login", "login.php", "signin", "sign-in", "wp-admin", "wp-login.php",
  "user/login", "users/login", "account/login", "auth", "auth/login", "panel", "cpanel", "controlpanel", "dashboard", "console",
  "manage", "manager", "management", "backend", "admincp", "admin_area", "adminpanel", "admin-console", "administrator/index.php",
  "phpmyadmin", "pma", "myadmin", "dbadmin", "adminer.php", "webadmin", "sysadmin", "portal", "secure", "members", "moderator",
  "umbraco", "typo3", "ghost", "wp-admin/admin.php", "administration", "login.aspx", "admin/login.aspx", "owa", "citrix",
  "remote", "vpn", "sslvpn", "jenkins", "gitlab", "grafana", "kibana", "rundeck", "jira", "confluence", "sonar", "nagios",
];

export const COMMON_PATHS = [
  "", "index.html", "index.php", "home", "about", "contact", "api", "api/v1", "api/v2", "v1", "v2", "graphql", "rest",
  "assets", "static", "public", "uploads", "upload", "files", "file", "images", "img", "media", "docs", "doc", "documentation",
  "download", "downloads", "backup", "backups", "bak", "old", "new", "temp", "tmp", "test", "testing", "demo", "dev", "staging",
  "css", "js", "scripts", "includes", "inc", "lib", "vendor", "node_modules", "config", "configs", "settings", "setup", "install",
  "data", "db", "database", "sql", "logs", "log", "error_log", "debug", "status", "health", "healthz", "ping", "metrics", "server-info",
  "cgi-bin", "wp-content", "wp-includes", "wp-json", "sites", "server-status", "robots.txt", "sitemap.xml", "humans.txt",
  ".well-known", "swagger", "swagger-ui.html", "openapi.json", "api-docs", "actuator", "actuator/health", "console",
  "search", "feed", "rss", "news", "blog", "shop", "store", "cart", "checkout", "account", "profile", "register", "signup",
  "forgot-password", "reset", "logout", "mail", "webmail", "email", "ftp", "sftp", "git", "svn", "ci", "build", "release",
];

export const BACKUP_SUFFIXES = ["", ".bak", ".old", ".orig", ".save", ".swp", ".zip", ".tar.gz", ".tgz", ".sql", "~"];
export const BACKUP_BASES = ["backup", "www", "web", "site", "db", "database", "dump", "export", "data", "config", "wp-config.php", "config.php", ".env", "app"];

export function buildWordlist(kind: "admin" | "common" | "all", extensions: string[]): string[] {
  const set = new Set<string>();
  const add = (p: string) => set.add("/" + p.replace(/^\/+/, ""));
  const applyExt = (base: string) => {
    add(base);
    for (const e of extensions) if (base && !base.includes(".")) add(`${base}.${e.replace(/^\./, "")}`);
  };
  if (kind === "admin" || kind === "all") ADMIN_PATHS.forEach(applyExt);
  if (kind === "common" || kind === "all") COMMON_PATHS.forEach(applyExt);
  if (kind === "all") for (const base of BACKUP_BASES) for (const suf of BACKUP_SUFFIXES) add(`${base}${suf}`);
  return [...set];
}

const ADMIN_RE = /(^|\/)(admin|administrator|login|signin|sign-in|wp-login|wp-admin|panel|cpanel|dashboard|console|backend|phpmyadmin|pma|adminer|portal|manage|auth|secure|owa|citrix|vpn|jenkins|gitlab|grafana|kibana|jira|confluence)(\b|\.|\/|$)/i;

export function looksLikeAdmin(path: string, title: string, body: string): boolean {
  if (ADMIN_RE.test(path)) return true;
  if (/log ?in|sign ?in|admin|password|username|authentication required/i.test(title)) return true;
  if (/<input[^>]+type=["']password["']/i.test(body)) return true;
  return false;
}
