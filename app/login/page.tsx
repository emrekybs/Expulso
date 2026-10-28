"use client";
import { useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await fetch("/api/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username, password }) });
      const json = await res.json();
      if (json.ok) {
        const next = params.get("next");
        router.replace(next && next.startsWith("/") ? next : "/");
        router.refresh();
      } else {
        setError(json.error || "Sign in failed.");
      }
    } catch {
      setError("Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-box">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src="/logo-dark.png" alt="Logo" className="login-logo logo-dark" />
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src="/logo.png" alt="Logo" className="login-logo logo-light" />
        <form className="card card-pad" onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div>
            <h1 style={{ margin: 0, fontSize: 20 }}>Sign in</h1>
            <p style={{ margin: "4px 0 0", color: "var(--muted)", fontSize: 13 }}>Passive recon &amp; OSINT workspace</p>
          </div>
          {error && (
            <div role="alert" className="alert bad" style={{ margin: 0 }}>
              <span>{error}</span>
            </div>
          )}
          <label className="field">
            Username
            <input type="text" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
          </label>
          <label className="field">
            Password
            <span style={{ position: "relative", display: "block" }}>
              <input type={show ? "text" : "password"} autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} style={{ width: "100%", boxSizing: "border-box", paddingRight: 64 }} />
              <button type="button" onClick={() => setShow((s) => !s)} className="mini-btn" style={{ position: "absolute", right: 6, top: 5, width: "auto", height: 30, padding: "0 10px", fontSize: 12 }}>
                {show ? "Hide" : "Show"}
              </button>
            </span>
          </label>
          <button type="submit" className="btn-primary" disabled={busy} style={{ height: 46 }}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
        <p style={{ margin: 0, fontSize: 12, color: "var(--muted)", textAlign: "center" }}>Access is limited to authorized staff. Sessions are signed and expire automatically.</p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  );
}
