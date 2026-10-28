import { NextResponse } from "next/server";
import { SESSION_COOKIE, issueToken, verifyCredentials, credentials } from "@/lib/auth";

export const runtime = "nodejs";

export async function POST(req: Request) {
  let body: { username?: string; password?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request." }, { status: 400 });
  }
  const username = String(body.username ?? "");
  const password = String(body.password ?? "");
  if (!verifyCredentials(username, password)) {
    return NextResponse.json({ ok: false, error: "Incorrect username or password." }, { status: 401 });
  }
  const { token, maxAge } = issueToken(username || credentials().username);
  const res = NextResponse.json({ ok: true });
  res.cookies.set(SESSION_COOKIE, token, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge });
  return res;
}
