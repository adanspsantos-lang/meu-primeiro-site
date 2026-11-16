export const config = { matcher: ["/((?!login\\.html|manual\\.pdf|favicon\\.ico|robots\\.txt).*)"] };

// produto -> variável de ambiente com a senha
const PRODUTOS = {
  clube: "SENHA_CLUBE",
  essencial: "SENHA_ESSENCIAL",
  roteiros: "SENHA_ROTEIROS",
  calendario: "SENHA_CALENDARIO",
  fundos: "SENHA_FUNDOS",
  promover: "SENHA_PROMOVER",
};
const enc = new TextEncoder();
async function sha(s) {
  const b = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
const senhaDe = (p) => (process.env[PRODUTOS[p]] || "").trim();
async function token(p) {
  const s = senhaDe(p);
  if (!s) return null;
  return p + "." + (await sha(p + ":" + s + ":" + (process.env.SEGREDO || "storykit")));
}
async function acessos(req) {
  const m = (req.headers.get("cookie") || "").match(/(?:^|;\s*)sk=([^;]+)/);
  const set = new Set();
  if (!m) return set;
  for (const tk of decodeURIComponent(m[1]).split("~")) {
    const p = tk.split(".")[0];
    if (PRODUTOS[p] && tk === (await token(p))) set.add(p);
  }
  return set;
}
async function cookieDe(set) {
  const tks = [];
  for (const p of set) { const t = await token(p); if (t) tks.push(t); }
  return `sk=${encodeURIComponent(tks.join("~"))}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax`;
}
const redir = (loc, cookie) => new Response(null, { status: 303, headers: cookie ? { Location: loc, "Set-Cookie": cookie } : { Location: loc } });

export default async function middleware(req) {
  const url = new URL(req.url);
  const tem = await acessos(req);

  if (url.pathname === "/entrar" && req.method === "POST") {
    const f = await req.formData();
    const s = String(f.get("senha") || "").trim().toLowerCase();
    const achou = s ? Object.keys(PRODUTOS).filter((p) => senhaDe(p) && senhaDe(p).toLowerCase() === s) : [];
    if (!achou.length) return redir(tem.size ? "/?erro=1#/senha" : "/login.html?erro=1");
    achou.forEach((p) => tem.add(p));
    return redir("/?ok=" + achou[0] + "#/", await cookieDe(tem));
  }
  if (url.pathname === "/sair") return redir("/login.html", "sk=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax");

  if (!tem.size) {
    if (url.pathname.startsWith("/d/") || url.pathname === "/acesso") return new Response("Não autorizado", { status: 401 });
    return new Response(null, { status: 307, headers: { Location: "/login.html" } });
  }
  if (url.pathname === "/acesso") {
    return new Response(JSON.stringify({ produtos: [...tem] }), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
  }
  const p = url.pathname;
  let ok = true;
  if (p.startsWith("/d/clube/")) ok = tem.has("clube");
  else if (p.startsWith("/d/x/cover/")) ok = true;
  else if (p.startsWith("/d/x/")) ok = tem.has(p.split("/")[3]);
  else if (p.startsWith("/d/")) ok = tem.has("essencial") || tem.has("clube");
  if (!ok) return new Response("Conteúdo não incluído no seu plano", { status: 403 });
  return new Response(null, { headers: { "x-middleware-next": "1" } });
}
