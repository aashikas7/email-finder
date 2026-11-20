"use strict";
/* Email Finder - app logic.
   Pure helpers are exported for tests (module.exports) and used by the page.
   All network calls are free and keyless: DNS-over-HTTPS, Clearbit
   autocomplete, Gravatar, and a CORS relay for public page scans.
   Optional: a Cloudflare Worker (window.EF_API) adds server-side sources. */

/* ================= pure helpers ================= */

function cleanName(s) {
  return (s || "").toLowerCase().normalize("NFD")
    .replace(/[̀-ͯ]/g, "").replace(/[^a-z]/g, "");
}

function cleanDomain(s) {
  return (s || "").trim().toLowerCase()
    .replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/[\/?#].*$/, "");
}

function validDomain(d) {
  return /^[a-z0-9][a-z0-9\-\.]*\.[a-z]{2,}$/.test(d);
}

/* LinkedIn URL -> name from the public slug only. Never fetches LinkedIn. */
function parseLinkedIn(input) {
  const t = (input || "").trim();
  if (!t) return null;
  let slug = null;
  const m = t.match(/linkedin\.com\/in\/([^\/?#]+)/i);
  if (m) slug = m[1];
  else if (/^[a-z0-9\-\._%]+$/i.test(t) && t.indexOf("-") > 0) slug = t;
  if (!slug) return null;
  try { slug = decodeURIComponent(slug); } catch (e) {}
  let parts = slug.replace(/\/+$/, "").split("-").filter(Boolean);
  while (parts.length > 1 && /^[0-9a-f]{4,}$/i.test(parts[parts.length - 1]) && /\d/.test(parts[parts.length - 1])) parts.pop();
  while (parts.length > 1 && /^\d+$/.test(parts[parts.length - 1])) parts.pop();
  if (!parts.length) return null;
  const first = cleanName(parts[0]);
  const last = parts.length > 1 ? cleanName(parts[parts.length - 1]) : "";
  if (!first) return null;
  return { first, last };
}

/* Standard corporate patterns, ordered by how common they are. */
function buildPatterns(first, last, domain) {
  const f = first, l = last, fi = f[0] || "", li = l[0] || "";
  const out = [];
  const add = (local, pattern, rank) => { if (local) out.push({ email: local + "@" + domain, pattern, rank }); };
  if (f && l) {
    add(f + "." + l, "first.last", 90);
    add(fi + l, "flast", 74);
    add(f, "first", 70);
    add(f + l, "firstlast", 56);
    add(f + "_" + l, "first_last", 46);
    add(fi + "." + l, "f.last", 42);
    add(f + li, "firstl", 38);
    add(l + "." + f, "last.first", 26);
    add(l, "last", 22);
    add(f + "-" + l, "first-last", 16);
  } else if (f) {
    add(f, "first", 60);
  }
  return out;
}

const EMAIL_RE = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;

const JUNK_LOCAL = /^(noreply|no-reply|donotreply|do-not-reply|mailer-daemon|postmaster|webmaster|example|email|your-email|name|user|username|test|admin@admin)/i;
const JUNK_ANYWHERE = /(sentry|wixpress|@2x|@3x|example\.|domain\.com|email\.com|\.png$|\.jpe?g$|\.gif$|\.svg$|\.webp$|\.css$|\.js$|localhost|u003|@sentry)/i;
const ROLE_RE = /^(info|contact|hello|hi|support|help|admin|team|sales|press|media|enquiries?|connect|mail|office|careers?|jobs?|hr[._-]?|recruit\w*|talent\w*|hiring|staffing|people|human[._-]?resources|apply|applications?|work[._-]?with[._-]?us|join[._-]?us)/i;

function extractEmails(text) {
  if (!text) return [];
  const found = new Map();
  const scan = (s) => {
    const matches = s.match(EMAIL_RE) || [];
    for (let raw of matches) {
      let e = raw.toLowerCase().replace(/^[.\-_]+|[.\-_]+$/g, "");
      if (e.length > 80) continue;
      if (JUNK_LOCAL.test(e) || JUNK_ANYWHERE.test(e)) continue;
      if (!found.has(e)) found.set(e, e);
    }
  };
  scan(text);
  // mailto: links are deliberate publication, scan them too (already covered by bare scan, kept for clarity)
  const mailtos = text.match(/mailto:([^"'>\s?]+)/gi) || [];
  for (const mt of mailtos) scan(mt.replace(/^mailto:/i, ""));
  return [...found.values()].slice(0, 30);
}

function emailKind(email) {
  return ROLE_RE.test(email.split("@")[0]) ? "role" : "personal";
}

/* Confidence labels, no invented percentages.
   verified: a connected verification API confirmed the mailbox.
   published: the address appears verbatim on a page or public profile.
   seen-publicly: public association (Gravatar / PGP key); not deliverability.
   guess: generated pattern + domain accepts mail. Never implies best email. */
function labelFor(c, mxOk) {
  if (c.verified) return "verified";
  if (c.published) return "published";
  if (c.publicAssoc) return "seen-publicly";
  if (mxOk === false) return "unlikely";
  if (mxOk === null || mxOk === undefined) return "inconclusive";
  return "guess";
}

/* Emails visible in a GitHub user's public profile or recent public commits. */
function emailsFromGithubPayload(user, events) {
  const out = new Set();
  if (user && typeof user.email === "string" && user.email.includes("@")) out.add(user.email.toLowerCase());
  for (const ev of events || []) {
    const commits = ev && ev.payload && ev.payload.commits;
    if (!commits) continue;
    for (const c of commits) {
      const e = c && c.author && c.author.email;
      if (typeof e === "string" && e.includes("@") && !e.endsWith("users.noreply.github.com")) out.add(e.toLowerCase());
    }
  }
  return [...out];
}

const CONSUMER_MAIL = {
  "gmail.com": "Gmail (consumer)", "googlemail.com": "Gmail (consumer)",
  "yahoo.com": "Yahoo (consumer)", "ymail.com": "Yahoo (consumer)",
  "outlook.com": "Outlook.com (consumer)", "hotmail.com": "Outlook.com (consumer)",
  "live.com": "Outlook.com (consumer)", "msn.com": "Outlook.com (consumer)",
  "icloud.com": "iCloud (consumer)", "me.com": "iCloud (consumer)",
  "aol.com": "AOL (consumer)", "proton.me": "Proton (consumer)", "protonmail.com": "Proton (consumer)",
  "zoho.com": "Zoho (consumer)", "gmx.com": "GMX (consumer)",
  "rediffmail.com": "Rediffmail (consumer)", "yandex.com": "Yandex (consumer)", "mail.com": "Mail.com (consumer)"
};

function mxProvider(mxHosts, domain) {
  if (domain && CONSUMER_MAIL[domain]) return CONSUMER_MAIL[domain];
  const s = (mxHosts || []).join(" ").toLowerCase();
  if (s.includes("google")) return "Google-hosted mail";
  if (s.includes("outlook") || s.includes("microsoft")) return "Microsoft-hosted mail";
  if (s.includes("zoho")) return "Zoho";
  if (s.includes("mailgun")) return "Mailgun";
  if (s.includes("mimecast")) return "Mimecast";
  if (s.includes("proofpoint")) return "Proofpoint";
  return null;
}

/* Refuse private/internal or credentialed URLs before any relay is used. */
function scanUrlSafety(input) {
  let t = (input || "").trim();
  if (/^[a-z][a-z0-9+.\-]*:\/\//i.test(t) && !/^https?:\/\//i.test(t)) {
    return { ok: false, reason: "Only http/https pages can be scanned." };
  }
  if (!/^https?:\/\//i.test(t)) t = "https://" + t;
  let u;
  try { u = new URL(t); } catch (e) { return { ok: false, reason: "That URL is not valid." }; }
  if (!/^https?:$/.test(u.protocol)) return { ok: false, reason: "Only http/https pages can be scanned." };
  if (u.username || u.password) return { ok: false, reason: "That URL contains credentials. It will not be sent anywhere." };
  const h = u.hostname.toLowerCase();
  if (h === "localhost" || /\.(local|internal|lan|corp|home|intranet)$/.test(h)) {
    return { ok: false, reason: "That looks like a private or internal address. It will not be sent to a relay." };
  }
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 0 || a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254)) {
      return { ok: false, reason: "That looks like a private or internal address. It will not be sent to a relay." };
    }
  }
  if (h === "[::1]" || h.startsWith("[fe80") || h.startsWith("[fd") || h.startsWith("[fc")) {
    return { ok: false, reason: "That looks like a private or internal address. It will not be sent to a relay." };
  }
  return { ok: true, url: t };
}

const EXPORTS = { cleanName, cleanDomain, validDomain, parseLinkedIn, buildPatterns, extractEmails, emailKind, labelFor, mxProvider, scanUrlSafety, emailsFromGithubPayload };
if (typeof module !== "undefined" && module.exports) { module.exports = EXPORTS; }
if (typeof window !== "undefined") { window.EF = EXPORTS; }

/* ================= browser wiring ================= */
if (typeof document !== "undefined") (function () {
  const $ = (s) => document.querySelector(s);
  const API = (window.EF_API || "").replace(/\/+$/, "");
  const esc = (s) => { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; };

  if (API) {
    $("#stMode").textContent = "API + browser";
    $("#stSources").textContent = "API · DNS · Clearbit · Gravatar · GitHub · PGP";
  }

  /* ---------- shared lookups ---------- */
  async function dns(name, type) {
    const r = await fetch("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(name) + "&type=" + type, { headers: { accept: "application/dns-json" } });
    if (!r.ok) throw new Error("DNS lookup failed");
    return r.json();
  }
  async function mxInfo(domain) {
    try {
      const mx = await dns(domain, "MX");
      const hosts = (mx.Answer || []).filter((a) => a.type === 15).map((a) => a.data.replace(/^\d+\s+/, "").replace(/\.$/, ""));
      if (hosts.length) return { ok: true, mx: hosts };
      const a = await dns(domain, "A");
      const hasA = (a.Answer || []).some((x) => x.type === 1);
      return { ok: hasA, mx: [], fallback: hasA };
    } catch (e) { return { ok: null, mx: [], error: String(e) }; }
  }
  async function sha256hex(s) {
    const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
  }
  async function gravatarExists(email) {
    try {
      const h = await sha256hex(email.trim().toLowerCase());
      const r = await fetch("https://www.gravatar.com/avatar/" + h + "?d=404&s=16");
      return r.status === 200;
    } catch (e) { return null; }
  }
  async function pgpExists(email) {
    try {
      const r = await fetch("https://keys.openpgp.org/vks/v1/by-email/" + encodeURIComponent(email.trim().toLowerCase()));
      return r.status === 200;
    } catch (e) { return null; }
  }
  /* Public GitHub presence for the name; returns exact-domain emails with provenance. */
  async function githubFind(first, last, domain) {
    if (!first || !last) return [];
    try {
      const q = encodeURIComponent('"' + first + " " + last + '" in:fullname');
      const r = await fetch("https://api.github.com/search/users?q=" + q + "&per_page=3", { headers: { accept: "application/vnd.github+json" } });
      if (!r.ok) return [];
      const items = ((await r.json()).items || []).slice(0, 3);
      const hits = [];
      for (const it of items) {
        let user = null, events = [];
        try { const ru = await fetch(it.url); if (ru.ok) user = await ru.json(); } catch (e) {}
        try { const re = await fetch(it.url + "/events/public"); if (re.ok) events = await re.json(); } catch (e) {}
        for (const e of emailsFromGithubPayload(user, events)) {
          if (e.endsWith("@" + domain)) hits.push({ email: e, profile: it.html_url });
        }
      }
      return hits;
    } catch (e) { return []; }
  }
  const mxCache = new Map();
  async function mxCached(domain) {
    if (!mxCache.has(domain)) mxCache.set(domain, await mxInfo(domain));
    return mxCache.get(domain);
  }

  const LABEL_TEXT = { verified: "Verified", published: "Published", "seen-publicly": "Seen publicly", guess: "Unverified guess", inconclusive: "Inconclusive", unlikely: "Unlikely" };
  function badge(label) { return '<span class="badge ' + label + '">' + (LABEL_TEXT[label] || label) + "</span>"; }
  async function copyBtn(btn) {
    try { await navigator.clipboard.writeText(btn.dataset.e); btn.textContent = "Copied"; setTimeout(() => (btn.textContent = "Copy"), 1200); }
    catch (e) { btn.textContent = btn.dataset.e; }
  }
  function wireCopy(scope) {
    scope.querySelectorAll(".copy").forEach((b) => b.addEventListener("click", () => copyBtn(b)));
  }
  function fail(el, msg) { el.textContent = msg; el.style.display = "block"; }

  /* ================= tool 1: find someone's email ================= */
  $("#li").addEventListener("input", () => {
    const p = parseLinkedIn($("#li").value);
    if (p) {
      $("#first").value = p.first;
      $("#last").value = p.last;
      $("#parseNote").textContent = "Read from the URL slug: " + p.first + (p.last ? " " + p.last : "") + ". Not verified, edit if it looks wrong.";
      $("#company").focus();
    }
  });

  let acTimer = null;
  $("#company").addEventListener("input", () => {
    clearTimeout(acTimer);
    const q = $("#company").value.trim();
    if (q.length < 2) { hideAc(); return; }
    acTimer = setTimeout(async () => {
      try {
        const r = await fetch("https://autocomplete.clearbit.com/v1/companies/suggest?query=" + encodeURIComponent(q));
        if (!r.ok) { hideAc(); return; }
        renderAc(await r.json());
      } catch (e) { hideAc(); }
    }, 180);
  });
  function renderAc(items) {
    const ac = $("#ac");
    if (!items || !items.length) { hideAc(); return; }
    if (document.activeElement && document.activeElement.id === "domain") return;
    if (document.activeElement && document.activeElement.id !== "company") return;
    ac.innerHTML = "";
    items.slice(0, 6).forEach((it) => {
      const d = document.createElement("div");
      const n = document.createElement("span"); n.textContent = it.name || it.domain;
      const dom = document.createElement("small"); dom.textContent = it.domain || "";
      d.append(n, dom);
      d.addEventListener("click", () => {
        $("#company").value = it.name || it.domain;
        if (it.domain) $("#domain").value = it.domain;
        hideAc();
      });
      ac.appendChild(d);
    });
    ac.style.display = "block";
  }
  function hideAc() { $("#ac").style.display = "none"; }
  $("#domain").addEventListener("focus", hideAc);
  $("#domain").addEventListener("input", hideAc);
  $("#li").addEventListener("focus", hideAc);
  $("#company").addEventListener("blur", () => setTimeout(hideAc, 200));
  document.addEventListener("click", (e) => { if (!e.target.closest(".acwrap")) hideAc(); });
  $("#company").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); $("#go").click(); } });
  $("#li").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); $("#company").focus(); } });
  $("#domain").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); $("#go").click(); } });

  async function apiFind(first, last, domain) {
    if (!API) return [];
    try {
      const r = await fetch(API + "/find?first=" + encodeURIComponent(first) + "&last=" + encodeURIComponent(last) + "&domain=" + encodeURIComponent(domain));
      if (!r.ok) return [];
      const j = await r.json();
      return (j.candidates || []).map((c) => ({ email: c.email, pattern: c.pattern || c.source || "api", rank: 80, source: c.source || "api", verified: !!c.verified }));
    } catch (e) { return []; }
  }

  $("#go").addEventListener("click", async () => {
    const err = $("#err"); err.style.display = "none";
    $("#results").classList.add("hidden");
    const first = cleanName($("#first").value);
    const last = cleanName($("#last").value);
    let domain = cleanDomain($("#domain").value);
    if (!first) return fail(err, "Add a LinkedIn URL or a first name first.");
    if (!domain) {
      const q = $("#company").value.trim();
      if (q) {
        $("#status").innerHTML = '<span class="spin"></span>Resolving company domain…';
        try {
          const r = await fetch("https://autocomplete.clearbit.com/v1/companies/suggest?query=" + encodeURIComponent(q));
          const items = r.ok ? await r.json() : [];
          if (items.length && items[0].domain) { domain = items[0].domain; $("#domain").value = domain; }
        } catch (e) {}
      }
      if (!domain) { $("#status").textContent = ""; return fail(err, "Could not resolve the company domain. Type it in the Domain field, e.g. company.com."); }
    }
    if (!validDomain(domain)) return fail(err, "That domain does not look valid: " + domain);

    $("#go").disabled = true;
    $("#status").innerHTML = '<span class="spin"></span>Checking mail records for <b>' + esc(domain) + "</b>…";

    const [mx, api, gh] = await Promise.all([mxCached(domain), apiFind(first, last, domain), githubFind(first, last, domain)]);
    let candidates = buildPatterns(first, last, domain);
    for (const c of api) {
      const existing = candidates.find((x) => x.email === c.email);
      if (existing) { existing.rank = Math.max(existing.rank, c.rank); if (c.verified) existing.verified = true; existing.source = c.source; }
      else candidates.push(c);
    }
    for (const h of gh) {
      const existing = candidates.find((x) => x.email === h.email);
      if (existing) { existing.published = true; existing.source = "GitHub profile or public commits"; existing.profile = h.profile; }
      else candidates.unshift({ email: h.email, pattern: "published on GitHub", rank: 100, published: true, source: "GitHub", profile: h.profile });
    }
    if (!candidates.length) { $("#go").disabled = false; $("#status").textContent = ""; return fail(err, "Could not build any pattern for that name."); }

    $("#status").innerHTML = '<span class="spin"></span>Checking which candidates exist in the wild…';
    const top = candidates.slice().sort((a, b) => b.rank - a.rank).slice(0, 4);
    await Promise.all(top.map(async (c) => {
      const [g, p] = await Promise.all([gravatarExists(c.email), pgpExists(c.email)]);
      if (g === true) { c.publicAssoc = true; c.whyPublic = "this exact address has a public Gravatar profile"; }
      if (p === true) { c.publicAssoc = true; c.whyPublic = "this exact address has a published PGP key"; }
    }));

    candidates.forEach((c) => { c.conf = labelFor(c, mx.ok); });
    candidates.sort((a, b) => {
      const order = { verified: 6, published: 5, "seen-publicly": 4, guess: 2, inconclusive: 1, unlikely: 0 };
      return (order[b.conf] - order[a.conf]) || (b.rank - a.rank);
    });

    const bits = [];
    if (mx.ok === true) bits.push("<b>" + esc(domain) + "</b> accepts mail" + (mx.mx.length ? " (" + esc(mxProvider(mx.mx, domain) || mx.mx[0]) + ")" : ""));
    else if (mx.ok === false) bits.push("<b>" + esc(domain) + "</b> has no mail records, treat every candidate with care");
    else bits.push("Could not check mail records for <b>" + esc(domain) + "</b>");
    $("#status").innerHTML = bits.join(" · ");

    const best = candidates[0];
    const EVIDENCED = ["verified", "published", "seen-publicly"];
    if (EVIDENCED.includes(best.conf)) {
      const reasons = [];
      if (best.conf === "published") reasons.push("found verbatim on their public GitHub profile or commits" + (best.profile ? ' (<a href="' + esc(best.profile) + '">source</a>)' : ""));
      if (best.conf === "verified") reasons.push("confirmed by a connected verification API" + (best.source ? " (" + esc(best.source) + ")" : ""));
      if (best.conf === "seen-publicly") {
        reasons.push(best.whyPublic || "this exact address appears publicly");
        reasons.push("a public association: proof the address was used publicly at some point, not proof the mailbox is deliverable today or tied to this employer");
      }
      if (mx.ok === true && mx.mx.length) reasons.push("domain accepts mail");
      $("#best").style.borderColor = "";
      $("#best").innerHTML =
        badge(best.conf) +
        '<div class="em">' + esc(best.email) + "</div>" +
        '<div class="why">' + reasons.join(" · ") + "</div>" +
        '<div style="margin-top:10px"><button class="copy" data-e="' + esc(best.email) + '">Copy</button></div>';
    } else {
      $("#best").style.borderColor = "var(--line)";
      $("#best").innerHTML =
        '<b>No address-specific evidence found.</b>' +
        '<div class="why">Every candidate below is an unverified guess generated from common corporate patterns' +
        (mx.ok === true ? "; the domain accepts mail, nothing more" : "") +
        ". The most common pattern is usually first.last. Verify an address (tool 3, or a verification API via the backend) before relying on it.</div>";
    }

    const body = $("#altBody");
    body.innerHTML = "";
    candidates.forEach((c) => {
      const tr = document.createElement("tr");
      tr.innerHTML = '<td class="mono">' + esc(c.email) + '</td><td class="sub2">' + esc(c.pattern) + "</td>" +
        "<td>" + badge(c.conf) + '</td><td><button class="copy" data-e="' + esc(c.email) + '">Copy</button></td>';
      body.appendChild(tr);
    });
    wireCopy($("#results"));
    $("#srcLine").textContent = "Sources: " + (API ? "finder API, " : "") + "DNS-over-HTTPS (MX), Clearbit autocomplete, Gravatar, PGP keyserver, public GitHub. No LinkedIn scraping.";
    $("#results").classList.remove("hidden");
    $("#go").disabled = false;
  });

  /* ================= tool 2: published emails on a page ================= */
  async function fetchPageText(target) {
    if (API) {
      try {
        const r = await fetch(API + "/scan?url=" + encodeURIComponent(target));
        if (r.ok) { const j = await r.json(); if (j.emails) return { emails: j.emails, via: "api" }; } else if (r.status === 400) { const j = await r.json().catch(() => ({})); throw new Error(j.error || "Invalid URL"); }
      } catch (e) { if (String(e.message || e).indexOf("Invalid") === 0) throw e; }
    }
    // direct fetch first (some pages allow it), then free reader relays
    try {
      const r = await fetch(target);
      if (r.ok) return { text: await r.text(), via: "direct" };
    } catch (e) {}
    try {
      const r = await fetch("https://r.jina.ai/" + target);
      if (r.ok) return { text: await r.text(), via: "relay" };
    } catch (e) {}
    const r = await fetch("https://api.allorigins.win/raw?url=" + encodeURIComponent(target));
    if (!r.ok) throw new Error("Could not fetch that page (status " + r.status + "). It may block readers.");
    return { text: await r.text(), via: "relay" };
  }

  $("#scanGo").addEventListener("click", async () => {
    const err = $("#scanErr"); err.style.display = "none";
    $("#scanResults").classList.add("hidden");
    const url = $("#pageUrl").value.trim();
    if (!url) return fail(err, "Paste a job posting, careers page or contact page URL first.");
    const safety = scanUrlSafety(url);
    if (!safety.ok) return fail(err, safety.reason);
    $("#scanGo").disabled = true;
    $("#scanStatus").innerHTML = '<span class="spin"></span>Fetching the page…';
    try {
      const got = await fetchPageText(safety.url);
      const emails = got.emails || extractEmails(got.text || "");
      if (!emails.length) {
        $("#scanStatus").textContent = "No published email addresses found on that page.";
        $("#scanGo").disabled = false;
        return;
      }
      $("#scanStatus").innerHTML = '<span class="spin"></span>Checking mail records…';
      const domains = [...new Set(emails.map((e) => e.split("@")[1]))];
      const mxByDomain = new Map();
      await Promise.all(domains.map(async (d) => mxByDomain.set(d, await mxCached(d))));
      const body = $("#scanBody");
      body.innerHTML = "";
      emails.forEach((e) => {
        const mx = mxByDomain.get(e.split("@")[1]) || { ok: null };
        const state = mx.ok === true ? "domain accepts mail" : mx.ok === false ? "domain has no mail records" : "mail records unchecked";
        const tr = document.createElement("tr");
        tr.innerHTML = '<td class="mono">' + esc(e) + "</td>" +
          "<td>" + badge("published") + "</td>" +
          '<td class="sub2">' + (emailKind(e) === "role" ? "role address" : "looks personal") + " · " + esc(state) + "</td>" +
          '<td><button class="copy" data-e="' + esc(e) + '">Copy</button></td>';
        body.appendChild(tr);
      });
      wireCopy($("#scanResults"));
      $("#scanStatus").innerHTML = emails.length + " address" + (emails.length > 1 ? "es" : "") + ' found verbatim on <a href="' + esc(safety.url) + '">the source page</a>' + (got.via === "relay" ? " (fetched through a free reader relay)" : got.via === "api" ? " (fetched by the backend)" : "") + ". Published here means on that page; if it is an aggregator repeating addresses, the company's own site is the stronger source.";
      $("#scanResults").classList.remove("hidden");
    } catch (e2) {
      $("#scanStatus").textContent = "";
      fail(err, String(e2.message || e2));
    }
    $("#scanGo").disabled = false;
  });
  $("#pageUrl").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); $("#scanGo").click(); } });

  /* ================= tool 3: check an email ================= */
  $("#checkGo").addEventListener("click", async () => {
    const err = $("#checkErr"); err.style.display = "none";
    $("#checkResult").classList.add("hidden");
    const email = $("#checkEmail").value.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/.test(email)) return fail(err, "That does not look like a valid email address.");
    $("#checkGo").disabled = true;
    $("#checkStatus").innerHTML = '<span class="spin"></span>Checking…';
    const domain = email.split("@")[1];
    const [mx, grav] = await Promise.all([mxCached(domain), gravatarExists(email)]);
    let verdict, detail, cls;
    if (mx.ok === false) {
      verdict = "Unlikely to work"; cls = "unlikely";
      detail = "The domain " + domain + " has no mail records, so nothing can be delivered there.";
    } else if (grav === true) {
      verdict = "Seen publicly"; cls = "seen-publicly";
      detail = "This exact address has a public Gravatar profile: proof it was used publicly at some point, not proof the mailbox is deliverable today or tied to a current employer. The domain also accepts mail.";
    } else if (mx.ok === true) {
      verdict = "Inconclusive"; cls = "inconclusive";
      detail = "The domain accepts mail" + (mx.mx.length ? " (" + (mxProvider(mx.mx, domain) || mx.mx[0]) + ")" : "") + ", but nothing confirms this specific mailbox. Some domains accept mail for any address (catch-all); MX records cannot tell, and this tool does not claim to. Mailbox-level confirmation needs a verification API, which the optional backend supports.";
    } else {
      verdict = "Inconclusive"; cls = "inconclusive";
      detail = "Mail records for " + domain + " could not be checked right now.";
    }
    $("#checkVerdict").innerHTML = '<span class="badge ' + cls + '">' + verdict + '</span> <b class="mono" style="font-size:16px">' + esc(email) + "</b>" + '<div class="why">' + esc(detail) + "</div>";
    $("#checkStatus").textContent = "";
    $("#checkResult").classList.remove("hidden");
    $("#checkGo").disabled = false;
  });
  $("#checkEmail").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); $("#checkGo").click(); } });
})();
