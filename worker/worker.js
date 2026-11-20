// Email Finder API - Cloudflare Worker (optional backend).
//
// Endpoints:
//   GET /find?first=jane&last=doe&domain=acme.com  -> ranked candidates
//   GET /scan?url=https://company.com/careers      -> emails published on a page
//   GET /check?email=jane@acme.com                 -> MX + plugin verification
//   GET /health
//
// Design: sources are plugins. Each source is { name, enabled(env), run(ctx) }.
// v1 ships with the pattern generator and MX check; add HUNTER_API_KEY
// (wrangler secret) and the Hunter source turns on with no other changes.
//
// Note on SMTP-level verification: Cloudflare Workers cannot open outbound
// connections on port 25, so raw SMTP RCPT probing is not possible here.
// Mailbox-level verification comes from key-based finder APIs (Hunter etc.)
// through the plugin seam below, which run it from their own infrastructure.

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

const clean = (s) => (s || "").toLowerCase().normalize("NFD")
  .replace(/[̀-ͯ]/g, "").replace(/[^a-z]/g, "").slice(0, 40);
const cleanDomain = (s) => (s || "").toLowerCase().trim()
  .replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/[\/?#].*$/, "").slice(0, 100);
const validDomain = (d) => /^[a-z0-9][a-z0-9\-\.]*\.[a-z]{2,}$/.test(d);

function buildPatterns(first, last, domain) {
  const f = first, l = last, fi = f[0] || "", li = l[0] || "";
  const out = [];
  const add = (local, pattern, rank) => {
    if (local) out.push({ email: local + "@" + domain, pattern, rank });
  };
  if (f && l) {
    add(`${f}.${l}`, "first.last", 90);
    add(`${fi}${l}`, "flast", 74);
    add(`${f}`, "first", 70);
    add(`${f}${l}`, "firstlast", 56);
    add(`${f}_${l}`, "first_last", 46);
    add(`${fi}.${l}`, "f.last", 42);
    add(`${f}${li}`, "firstl", 38);
    add(`${l}.${f}`, "last.first", 26);
    add(`${l}`, "last", 22);
    add(`${f}-${l}`, "first-last", 16);
  } else if (f) add(f, "first", 60);
  return out;
}

const EMAIL_RE = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
const JUNK_LOCAL = /^(noreply|no-reply|donotreply|do-not-reply|mailer-daemon|postmaster|webmaster|example|email|your-email|name|user|username|test)/i;
const JUNK_ANYWHERE = /(sentry|wixpress|@2x|@3x|example\.|domain\.com|email\.com|\.png$|\.jpe?g$|\.gif$|\.svg$|\.webp$|\.css$|\.js$|localhost|u003|@sentry)/i;

function extractEmails(text) {
  const found = new Map();
  const scan = (s) => {
    for (let raw of s.match(EMAIL_RE) || []) {
      const e = raw.toLowerCase().replace(/^[.\-_]+|[.\-_]+$/g, "");
      if (e.length > 80 || JUNK_LOCAL.test(e) || JUNK_ANYWHERE.test(e)) continue;
      if (!found.has(e)) found.set(e, e);
    }
  };
  scan(text);
  for (const mt of text.match(/mailto:([^"'>\s?]+)/gi) || []) scan(mt.replace(/^mailto:/i, ""));
  return [...found.values()].slice(0, 30);
}

async function dns(name, type) {
  const r = await fetch(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    { headers: { accept: "application/dns-json" } }
  );
  if (!r.ok) throw new Error("DNS lookup failed");
  return r.json();
}

async function mxInfo(domain) {
  const mx = await dns(domain, "MX");
  const hosts = (mx.Answer || []).filter((a) => a.type === 15)
    .map((a) => a.data.replace(/^\d+\s+/, "").replace(/\.$/, ""));
  if (hosts.length) return { ok: true, mx: hosts };
  const a = await dns(domain, "A");
  return { ok: (a.Answer || []).some((x) => x.type === 1), mx: [], fallback: true };
}

/* ---- Source plugins ---------------------------------------------------- */

const patternSource = {
  name: "pattern",
  enabled: () => true,
  run: async ({ first, last, domain }) => buildPatterns(first, last, domain),
};

const hunterSource = {
  name: "hunter",
  enabled: (env) => !!env.HUNTER_API_KEY,
  run: async ({ first, last, domain, env }) => {
    const u = new URL("https://api.hunter.io/v2/email-finder");
    u.searchParams.set("domain", domain);
    u.searchParams.set("first_name", first);
    u.searchParams.set("last_name", last);
    u.searchParams.set("api_key", env.HUNTER_API_KEY);
    const r = await fetch(u);
    if (!r.ok) return [];
    const d = (await r.json()).data || {};
    if (!d.email) return [];
    return [{
      email: d.email,
      pattern: "hunter",
      rank: 80,
      source: "hunter",
      verified: !!(d.verification && d.verification.status === "valid"),
    }];
  },
};

// Add more sources here (ZeroBounce, Apollo, ...): one object each,
// enabled() gated on its secret. Nothing else in this file changes.
const SOURCES = [patternSource, hunterSource];

function labelFor(c, mxOk) {
  if (c.verified) return "verified";
  if (c.published) return "published";
  if (c.publicAssoc) return "seen-publicly";
  if (mxOk === false) return "unlikely";
  if (mxOk === null || mxOk === undefined) return "inconclusive";
  return "guess";
}

/* ------------------------------------------------------------------------ */

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(request.url);

    if (url.pathname === "/health") return json({ ok: true });

    if (url.pathname === "/find") {
      const first = clean(url.searchParams.get("first"));
      const last = clean(url.searchParams.get("last"));
      const domain = cleanDomain(url.searchParams.get("domain"));
      if (!first || !validDomain(domain)) return json({ error: "need first name and a valid domain" }, 400);

      const ctx = { first, last, domain, env };
      const active = SOURCES.filter((s) => s.enabled(env));
      const settled = await Promise.allSettled(active.map((s) => s.run(ctx)));

      const byEmail = new Map();
      settled.forEach((res) => {
        if (res.status !== "fulfilled") return;
        for (const c of res.value || []) {
          const ex = byEmail.get(c.email);
          if (ex) {
            ex.rank = Math.max(ex.rank, c.rank);
            ex.verified = ex.verified || c.verified;
            if (c.source !== "pattern") ex.source = c.source;
          } else byEmail.set(c.email, { ...c });
        }
      });

      let mx = { ok: null, mx: [] };
      try { mx = await mxInfo(domain); } catch (e) {}

      const candidates = [...byEmail.values()]
        .map((c) => ({ ...c, confidence: labelFor(c, mx.ok) }))
        .sort((a, b) => {
          const order = { verified: 6, published: 5, "seen-publicly": 4, guess: 2, inconclusive: 1, unlikely: 0 };
          return (order[b.confidence] - order[a.confidence]) || (b.rank - a.rank);
        });

      return json({ domain, mx, sources: active.map((s) => s.name), candidates });
    }

    if (url.pathname === "/scan") {
      let target = (url.searchParams.get("url") || "").trim();
      if (!/^https?:\/\//i.test(target)) target = "https://" + target;
      let parsed;
      try { parsed = new URL(target); } catch (e) { return json({ error: "Invalid URL" }, 400); }
      if (!/^https?:$/.test(parsed.protocol)) return json({ error: "Invalid URL" }, 400);
      let text = "";
      try {
        const r = await fetch(target, {
          headers: { "User-Agent": "Mozilla/5.0 (compatible; EmailFinder/1.0)" },
          redirect: "follow",
        });
        if (!r.ok) return json({ error: "page returned status " + r.status }, 502);
        text = (await r.text()).slice(0, 500000);
      } catch (e) {
        return json({ error: "could not fetch that page" }, 502);
      }
      return json({ url: target, emails: extractEmails(text) });
    }

    if (url.pathname === "/check") {
      const email = (url.searchParams.get("email") || "").trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/.test(email)) return json({ error: "invalid email" }, 400);
      const domain = email.split("@")[1];
      let mx = { ok: null, mx: [] };
      try { mx = await mxInfo(domain); } catch (e) {}
      const result = { email, mx, verdict: mx.ok === false ? "unlikely" : "inconclusive" };
      // Plugin verification: if Hunter is configured, ask it for a mailbox verdict.
      if (env.HUNTER_API_KEY) {
        try {
          const u = new URL("https://api.hunter.io/v2/email-verifier");
          u.searchParams.set("email", email);
          u.searchParams.set("api_key", env.HUNTER_API_KEY);
          const r = await fetch(u);
          if (r.ok) {
            const d = (await r.json()).data || {};
            result.hunter = { status: d.status, result: d.result, score: d.score };
            if (d.status === "valid") result.verdict = "verified";
            else if (d.status === "invalid") result.verdict = "unlikely";
            else if (d.status === "accept_all") result.verdict = "inconclusive";
          }
        } catch (e) {}
      }
      return json(result);
    }

    return json({ error: "not found" }, 404);
  },
};
