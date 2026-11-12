// tablo · Pon sekirize pou tablo de bò Bwat Sekrèm (tableau-de-bord/ sou GitHub Pages)
// - Kont tablo yo nan tab public.tablo_itilizate (modpas bcrypt, blokaj apre 5 echèk). Yo pa nan auth.users.
// - Token Airtable la rete sou sèvè a : sekrè TABLO_AIRTABLE_TOKEN. Navigatè a pa janm wè l.
// - Sesyon : jeton siyen (HMAC-SHA256) ki dire 12 è, voye nan antèt « x-tablo-sesyon ».
// Aksyon (POST JSON { aksyon, ... }) :
//   eta                                   → { gen_itilizate }                       (piblik)
//   premye_admin { kod, non, modpas }     → kreye premye admin lan (kòd yon sèl fwa)  (piblik)
//   konekte { non, modpas }               → { sesyon, mwen, itilizate }             (piblik)
//   mwen                                  → { mwen, itilizate }
//   verifye { non, modpas }               → { ok, mwen? }   (konfimasyon admin/sipèvizè nan paj la)
//   modpas_mwen { ansyen, nouvo }
//   kreye { non, modpas, role, pages, uid? }                  (admin)
//   modifye { uid, non, role, pages, modpas? }                (admin)
//   efase { uid }                                             (admin)
//   airtable { metod, chemen, ko? }       → repons Airtable la jan l ye a
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const URL_ = Deno.env.get("SUPABASE_URL")!;
const SERVICE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const db = createClient(URL_, SERVICE, { auth: { persistSession: false } });
const AT = "https://api.airtable.com";
const BAZ_EKRI = new Set(["appffRHvMN6t5q2rg"]); // sèl baz paj la ekri ladan l (pwen prezans, frè, foto iregilarite)
const WOL = ["admin", "superviseur", "traitement", "validation"];
const PAJ = ["releve", "alertes", "quotidien", "simulateur", "excedents", "portefeuilles", "evolution", "frais"];
const DIRE_SESYON = 12 * 3600 * 1000;
const MODPAS_MIN = 8;

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-tablo-sesyon",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Max-Age": "86400",
};
const rep = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

// ---------- Sesyon siyen ----------
const enc = new TextEncoder();
let kleHmac: CryptoKey | null = null;
async function kle() {
  if (!kleHmac) {
    const baz = await crypto.subtle.digest("SHA-256", enc.encode("tablo-sesyon:" + SERVICE));
    kleHmac = await crypto.subtle.importKey("raw", baz, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  }
  return kleHmac;
}
const b64u = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const deb64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
async function siyen(id: string, hash: string) {
  const kò = b64u(enc.encode(JSON.stringify({ id, pv: hash.slice(-10), exp: Date.now() + DIRE_SESYON })));
  return kò + "." + b64u(await crypto.subtle.sign("HMAC", await kle(), enc.encode(kò)));
}
async function liSesyon(t: string | null) {
  if (!t || !t.includes(".")) return null;
  const [kò, sig] = t.split(".");
  try {
    if (!(await crypto.subtle.verify("HMAC", await kle(), deb64u(sig), enc.encode(kò)))) return null;
    const p = JSON.parse(new TextDecoder().decode(deb64u(kò)));
    if (!p.id || !p.exp || p.exp < Date.now()) return null;
    const { data: u } = await db.from("tablo_itilizate").select("*").eq("id", p.id).maybeSingle();
    if (!u || !u.aktif || u.modpas_hash.slice(-10) !== p.pv) return null; // modpas chanje oswa kont efase → sesyon an tonbe
    return u;
  } catch { return null; }
}

// ---------- Itilizatè ----------
type U = { id: string; non: string; uid: string; role: string; pages: string[]; aliases: unknown[]; modpas_hash: string };
const piblik = (u: U) => ({ name: u.non, uid: u.uid, role: u.role, admin: u.role === "admin",
  pages: u.role === "admin" ? PAJ : (u.pages || []).filter((p) => PAJ.includes(p)), aliases: u.aliases || [] });
async function tout() {
  const { data } = await db.from("tablo_itilizate").select("*").eq("aktif", true).order("non");
  return (data || []).map(piblik);
}
async function nouvoUid() {
  for (let i = 0; i < 50; i++) {
    const id = "U-" + Array.from(crypto.getRandomValues(new Uint8Array(2))).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    const { data } = await db.from("tablo_itilizate").select("id").eq("uid", id).maybeSingle();
    if (!data) return id;
  }
  throw new Error("ID pa disponib");
}
async function hash(p: string) {
  const { data, error } = await db.rpc("tablo_hash", { p });
  if (error) throw new Error(error.message);
  return data as string;
}
const pajOf = (role: string, pages: unknown) =>
  role === "admin" ? PAJ : (Array.isArray(pages) ? pages.map(String).filter((p) => PAJ.includes(p)) : []);
async function verifye(non: string, modpas: string) {
  const { data, error } = await db.rpc("tablo_verifye", { p_non: String(non || ""), p_modpas: String(modpas || "") });
  if (error) throw new Error(error.message);
  return data as { ok: boolean; id?: string; rezon?: string; segond?: number };
}
const erèVerifye = (v: { rezon?: string; segond?: number }) =>
  v.rezon === "bloke" ? `Trop de tentatives. Réessaie dans ${v.segond} s.` : "Nom d'utilisateur ou mot de passe incorrect.";

// ---------- Airtable ----------
const CHEMEN_LI = /^\/v0\/(meta\/bases(\/app[A-Za-z0-9]{14}\/tables)?|app[A-Za-z0-9]{14}\/[^/?#]+(\/rec[A-Za-z0-9]{14})?)(\?[^#]*)?$/;
const CHEMEN_EKRI = /^\/v0\/(app[A-Za-z0-9]{14})\/[^/?#]+$/;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return rep(405, { erè: "POST sèlman" });
  let b: Record<string, any>;
  try { b = await req.json(); } catch { return rep(400, { erè: "JSON invalide" }); }
  const aksyon = String(b.aksyon || "");

  try {
    // ----- Piblik -----
    if (aksyon === "eta") {
      const { count } = await db.from("tablo_itilizate").select("id", { count: "exact", head: true });
      return rep(200, { gen_itilizate: (count || 0) > 0 });
    }
    if (aksyon === "premye_admin") {
      const { count } = await db.from("tablo_itilizate").select("id", { count: "exact", head: true });
      if ((count || 0) > 0) return rep(409, { erè: "Le compte administrateur existe déjà." });
      const { data: ok } = await db.rpc("tablo_kod_ok", { p_kod: String(b.kod || "").trim().toUpperCase() });
      if (!ok) return rep(403, { erè: "Code d'installation incorrect." });
      const non = String(b.non || "").trim(), modpas = String(b.modpas || "");
      if (!non) return rep(400, { erè: "Indique un nom." });
      if (modpas.length < 12) return rep(400, { erè: "Mot de passe trop court (12 caractères minimum)." });
      const { error } = await db.from("tablo_itilizate").insert({ non, uid: await nouvoUid(), role: "admin", pages: PAJ, modpas_hash: await hash(modpas) });
      if (error) return rep(400, { erè: error.message });
      await db.from("tablo_konfig").delete().eq("kle", "kod_premye_admin"); // kòd la itilize : li pa vo anyen ankò
      return rep(200, { ok: true });
    }
    if (aksyon === "konekte") {
      const v = await verifye(b.non, b.modpas);
      if (!v.ok) return rep(401, { erè: erèVerifye(v) });
      const { data: u } = await db.from("tablo_itilizate").select("*").eq("id", v.id).single();
      return rep(200, { sesyon: await siyen(u.id, u.modpas_hash), mwen: piblik(u), itilizate: await tout() });
    }

    // ----- Fòk ou konekte -----
    const mwen = await liSesyon(req.headers.get("x-tablo-sesyon"));
    if (!mwen) return rep(401, { erè: "Session expirée — reconnecte-toi.", sesyon_fini: true });
    const seAdmin = mwen.role === "admin";

    if (aksyon === "airtable") {
      const token = Deno.env.get("TABLO_AIRTABLE_TOKEN") || "";
      if (!token) return rep(503, { error: { type: "TABLO_TOKEN_MANQUANT", message: "Le secret TABLO_AIRTABLE_TOKEN n'est pas configuré sur Supabase." } });
      const metod = String(b.metod || "GET").toUpperCase(), chemen = String(b.chemen || "");
      if (metod === "GET") {
        if (!CHEMEN_LI.test(chemen)) return rep(403, { error: { type: "CHEMIN_REFUSE", message: "Chemin Airtable non autorisé." } });
      } else if (metod === "PATCH") {
        const m = chemen.match(CHEMEN_EKRI);
        if (!m || !BAZ_EKRI.has(m[1])) return rep(403, { error: { type: "ECRITURE_REFUSEE", message: "Écriture non autorisée sur cette base." } });
      } else return rep(403, { error: { type: "METHODE_REFUSEE", message: "Méthode non autorisée." } });
      const r = await fetch(AT + chemen, {
        method: metod,
        headers: { Authorization: `Bearer ${token}`, ...(metod === "PATCH" ? { "Content-Type": "application/json" } : {}) },
        body: metod === "PATCH" ? String(b.ko ?? "") : undefined,
      });
      return new Response(await r.text(), { status: r.status, headers: { ...cors, "Content-Type": "application/json",
        ...(r.headers.get("retry-after") ? { "Retry-After": r.headers.get("retry-after")! } : {}) } });
    }

    if (aksyon === "mwen") return rep(200, { mwen: piblik(mwen), itilizate: await tout() });

    if (aksyon === "verifye") {
      const v = await verifye(b.non, b.modpas);
      if (!v.ok) return rep(200, { ok: false, erè: erèVerifye(v) });
      const { data: u } = await db.from("tablo_itilizate").select("*").eq("id", v.id).single();
      return rep(200, { ok: true, mwen: piblik(u) });
    }

    if (aksyon === "modpas_mwen") {
      const nouvo = String(b.nouvo || "");
      if (nouvo.length < MODPAS_MIN) return rep(400, { erè: `Le nouveau mot de passe doit faire au moins ${MODPAS_MIN} caractères.` });
      const v = await verifye(mwen.non, b.ansyen);
      if (!v.ok) return rep(400, { erè: v.rezon === "bloke" ? erèVerifye(v) : "Mot de passe actuel incorrect." });
      const h = await hash(nouvo);
      await db.from("tablo_itilizate").update({ modpas_hash: h, updated_at: new Date().toISOString() }).eq("id", mwen.id);
      return rep(200, { ok: true, sesyon: await siyen(mwen.id, h) });
    }

    // ----- Admin sèlman -----
    if (!seAdmin) return rep(403, { erè: "Réservé aux administrateurs." });
    const role = String(b.role || "");
    const nbAdmin = async () => (await db.from("tablo_itilizate").select("id", { count: "exact", head: true }).eq("role", "admin").eq("aktif", true)).count || 0;

    if (aksyon === "kreye") {
      const non = String(b.non || "").trim(), modpas = String(b.modpas || "");
      if (!non) return rep(400, { erè: "Indique un nom d'utilisateur." });
      if (!WOL.includes(role)) return rep(400, { erè: "Rôle invalide." });
      if (modpas.length < MODPAS_MIN) return rep(400, { erè: `Le mot de passe doit faire au moins ${MODPAS_MIN} caractères.` });
      const pages = pajOf(role, b.pages);
      if (role !== "admin" && !pages.length) return rep(400, { erè: "Coche au moins une page (ou Administrateur)." });
      let uid = String(b.uid || "").trim().toUpperCase();
      if (uid) {
        if (!/^U-[0-9A-F]{4,8}$/.test(uid)) return rep(400, { erè: "ID permanent invalide." });
        const { data: d } = await db.from("tablo_itilizate").select("id").eq("uid", uid).maybeSingle();
        if (d) return rep(409, { erè: `L'ID ${uid} est déjà utilisé.` });
      } else uid = await nouvoUid();
      const { error } = await db.from("tablo_itilizate").insert({ non, uid, role, pages, modpas_hash: await hash(modpas) });
      if (error) return rep(409, { erè: error.code === "23505" ? "Ce nom existe déjà." : error.message });
      return rep(200, { ok: true, itilizate: await tout() });
    }

    const { data: sib } = await db.from("tablo_itilizate").select("*").eq("uid", String(b.uid || "")).eq("aktif", true).maybeSingle();
    if (!sib) return rep(404, { erè: "Utilisateur introuvable." });

    if (aksyon === "modifye") {
      const non = String(b.non || "").trim(), modpas = String(b.modpas || "");
      if (!non) return rep(400, { erè: "Indique un nom d'utilisateur." });
      if (!WOL.includes(role)) return rep(400, { erè: "Rôle invalide." });
      const pages = pajOf(role, b.pages);
      if (role !== "admin" && !pages.length) return rep(400, { erè: "Coche au moins une page (ou Administrateur)." });
      if (sib.role === "admin" && role !== "admin" && (await nbAdmin()) <= 1) return rep(400, { erè: "Il doit rester au moins un administrateur." });
      if (modpas && modpas.length < MODPAS_MIN) return rep(400, { erè: `Le mot de passe doit faire au moins ${MODPAS_MIN} caractères.` });
      const chanj: Record<string, unknown> = { non, role, pages, updated_at: new Date().toISOString() };
      if (non !== sib.non) chanj.aliases = [...(sib.aliases || []), { name: sib.non, until: Date.now() }];
      if (modpas) { chanj.modpas_hash = await hash(modpas); chanj.echek = 0; chanj.bloke_jiska = null; }
      const { error } = await db.from("tablo_itilizate").update(chanj).eq("id", sib.id);
      if (error) return rep(409, { erè: error.code === "23505" ? "Ce nom existe déjà." : error.message });
      const { data: apre } = await db.from("tablo_itilizate").select("*").eq("id", sib.id).single();
      return rep(200, { ok: true, itilizate: await tout(),
        sesyon: sib.id === mwen.id && modpas ? await siyen(apre.id, apre.modpas_hash) : undefined });
    }

    if (aksyon === "efase") {
      if (sib.role === "admin" && (await nbAdmin()) <= 1) return rep(400, { erè: "Impossible : il doit rester au moins un administrateur." });
      await db.from("tablo_itilizate").delete().eq("id", sib.id);
      return rep(200, { ok: true, itilizate: await tout() });
    }

    return rep(400, { erè: "Action inconnue." });
  } catch (e) {
    console.error(e);
    return rep(500, { erè: "Erreur serveur : " + (e instanceof Error ? e.message : String(e)) });
  }
});
