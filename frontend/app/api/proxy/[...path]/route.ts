// Server-side proxy: the browser talks to this route, which adds the API key.
// The key lives only in server env (BACKEND_API_KEY), never in client JS.
// Only an allowlist of read paths (plus /investigate) is forwarded, and the
// key held here is the read-only analyst key.
import { NextRequest, NextResponse } from "next/server";

const BACKEND = process.env.BACKEND_URL || "http://localhost:8000";
const KEY = process.env.BACKEND_API_KEY || "";

const GET_ALLOWED = [/^overview$/, /^incidents(\/[0-9a-f-]{36})?$/, /^detections$/, /^predict\/next$/,
  /^graph\/blast-radius$/, /^health$/];
const POST_ALLOWED = [/^investigate$/];

async function forward(req: NextRequest, path: string[], allowed: RegExp[]) {
  const joined = path.join("/");
  if (!allowed.some((r) => r.test(joined))) {
    return NextResponse.json({ error: "not found" }, { status: 404 });
  }
  const url = `${BACKEND}/${joined}${req.nextUrl.search}`;
  const init: RequestInit = {
    method: req.method,
    headers: { "Content-Type": "application/json", "X-API-Key": KEY },
    cache: "no-store",
  };
  if (req.method === "POST") init.body = await req.text();
  try {
    const res = await fetch(url, init);
    return new NextResponse(res.body, {
      status: res.status,
      headers: { "Content-Type": res.headers.get("Content-Type") || "application/json" },
    });
  } catch {
    return NextResponse.json({ error: "backend unavailable" }, { status: 502 });
  }
}

export async function GET(req: NextRequest, ctx: { params: { path: string[] } }) {
  return forward(req, ctx.params.path, GET_ALLOWED);
}
export async function POST(req: NextRequest, ctx: { params: { path: string[] } }) {
  return forward(req, ctx.params.path, POST_ALLOWED);
}
