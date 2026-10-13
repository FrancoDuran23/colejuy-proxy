// ColeJUY SA proxy (Vicugna). Same contract as Vercel /api/sa-proxy.
import http from "node:http";
import crypto from "node:crypto";
const API = "https://api.santaanasrl.com.ar/api";
const KEY = (process.env.SA_PROXY_KEY || "").trim();
const send = (res, status, obj, extra = {}) => { res.writeHead(status, { "Content-Type": "application/json", ...extra }); res.end(typeof obj === "string" ? obj : JSON.stringify(obj)); };
function authorized(req) {
  if (!KEY) return false;
  const given = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "") || String(req.headers["x-sa-proxy-key"] || "");
  if (!given || given.length !== KEY.length) return false;
  const h = (v) => crypto.createHash("sha256").update(v).digest();
  return crypto.timingSafeEqual(h(given), h(KEY));
}
http.createServer(async (req, res) => {
  const path = (req.url || "/").split("?")[0].replace(/\/+$/, "");
  if (req.method === "GET" && (path === "" || path === "/healthz")) return send(res, 200, { ok: true });
  if (path !== "/api/sa-proxy") return send(res, 404, { error: "not_found" });
  if (req.method !== "POST") return send(res, 405, { error: "method_not_allowed" });
  if (!authorized(req)) return send(res, 401, { error: "unauthorized" });
  let raw = ""; for await (const c of req) { raw += c; if (raw.length > 16384) return send(res, 413, { error: "too_large" }); }
  let body; try { body = JSON.parse(raw); } catch { return send(res, 400, { error: "bad_json" }); }
  const lineId = typeof body?.lineId === "string" ? body.lineId.trim() : "";
  const jwt = typeof body?.jwt === "string" ? body.jwt.trim() : "";
  if (!/^[\w-]{1,32}$/.test(lineId) || !jwt || jwt.length > 4096) return send(res, 400, { error: "bad_payload" });
  let up;
  try { up = await fetch(`${API}/transport/vehicles?lineId=${encodeURIComponent(lineId)}`, { headers: { accept: "application/json", Authorization: `Bearer ${jwt}` }, signal: AbortSignal.timeout(10000) }); }
  catch (e) { return send(res, 502, { error: "upstream_fetch", message: String(e?.message || "fail").slice(0, 120) }); }
  const text = await up.text(); const ct = up.headers.get("content-type") || "";
  if (ct.includes("application/json")) return send(res, up.status, text, { "Cache-Control": "no-store", "X-Upstream-Status": String(up.status) });
  send(res, up.status >= 400 ? up.status : 502, { error: "upstream_non_json", status: up.status, server: up.headers.get("server"), snippet: text.slice(0, 200) }, { "Cache-Control": "no-store" });
}).listen(Number(process.env.PORT) || 8080, "0.0.0.0", () => console.log("listening", Number(process.env.PORT) || 8080));
