export const config = { matcher: ["/((?!login\\.html|favicon\\.ico).*)"] };

const enc = new TextEncoder();
async function sha(s) {
  const b = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function senhaDe(tier) {
  return (tier === "clube" ? process.env.SENHA_CLUBE : process.env.SENHA_ESSENCIAL) || "";
}
async function token(tier) {
  const s = senhaDe(tier);
  if (!s) return null;
  return tier + "." + (await sha(tier + ":" + s + ":" + (process.env.SEGREDO || "storykit")));
}

export default async function middleware(req) {
  const url = new URL(req.url);

  if (url.pathname === "/entrar" && req.method === "POST") {
    const f = await req.formData();
    const s = String(f.get("senha") || "").trim();
    let tier = null;
    if (s && s === senhaDe("clube")) tier = "clube";
    else if (s && s === senhaDe("essencial")) tier = "essencial";
    if (!tier) return new Response(null, { status: 303, headers: { Location: "/login.html?erro=1" } });
    const t = await token(tier);
    return new Response(null, {
      status: 303,
      headers: { Location: "/", "Set-Cookie": `sk=${t}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax` },
    });
  }
  if (url.pathname === "/sair") {
    return new Response(null, { status: 303, headers: { Location: "/login.html", "Set-Cookie": "sk=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" } });
  }

  const m = (req.headers.get("cookie") || "").match(/(?:^|;\s*)sk=([^;]+)/);
  let tier = null;
  if (m) {
    for (const t of ["clube", "essencial"]) {
      const tk = await token(t);
      if (tk && m[1] === tk) { tier = t; break; }
    }
  }
  if (!tier) {
    if (url.pathname.startsWith("/d/")) return new Response("Não autorizado", { status: 401 });
    return new Response(null, { status: 307, headers: { Location: "/login.html" } });
  }
  if (url.pathname.startsWith("/d/clube/") && tier !== "clube") return new Response("Exclusivo do Clube", { status: 403 });
  return new Response(null, { headers: { "x-middleware-next": "1" } });
}
