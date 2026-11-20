# Email Finder

Find work emails with honest provenance: published, verified, likely, or
guess. No LinkedIn scraping, no invented confidence scores. Works for
companies worldwide.

Live at: https://aashikas7.github.io/email-finder/ (after public deploy)

## Three tools in one page

1. **Find someone's email** - paste a LinkedIn profile URL (only the public
   name slug is read; LinkedIn is never fetched) or type a name, plus a
   company. The company resolves to a domain via Clearbit autocomplete (free,
   no key), standard corporate patterns are generated, the domain's MX
   records are checked over DNS-over-HTTPS, and top candidates are checked
   against Gravatar's existence endpoint. Name and company stay editable; a
   URL slug alone is never presented as verified identity.
2. **Find published emails on a page** - paste a job posting, careers page or
   contact page. Addresses found verbatim are labeled Published with a link
   to the source page, classified role vs personal, and each domain is
   MX-checked. Pages are fetched directly or through free reader relays
   (r.jina.ai, allorigins.win); with the optional worker, the fetch happens
   server-side. Private/internal and credentialed URLs are refused.
3. **Check an email you already have** - syntax, MX records, and a Gravatar
   existence check, returning Verified / Inconclusive / Unlikely with the
   reason spelled out, including the catch-all caveat.

## Confidence labels (no fake percentages)

- **Published** - the address appears verbatim on a page you pointed at, or
  on the person's public GitHub. The tool links the source page; a company's
  own site or the person's own profile is stronger than an aggregator
  repeating an address.
- **Verified** - a connected verification API confirmed the mailbox. Only
  possible with the optional backend and an API key.
- **Seen publicly** - the exact address appears publicly (Gravatar, PGP
  key). Proof of past public use, not of current deliverability or employer.
- **Unverified guess** - generated from common patterns; the domain accepts
  mail, nothing more. No candidate is presented as the best email without
  address-specific evidence.
- **Inconclusive** - the checks could not say either way.
- **Unlikely** - the domain has no mail records.

MX records cannot detect catch-all domains, and the tool does not claim to.
Private/internal or credentialed URLs are refused before any page relay is
used.

## Files

- `index.html` - page markup and styles (dark theme, matches PM Radar).
- `app.js` - all logic. Pure helpers are unit-testable (`node test.js`).
- `config.js` - set `window.EF_API` to enable the optional backend.
- `worker/` - optional Cloudflare Worker adding server-side sources.

## Optional backend (Cloudflare Workers, free tier)

The frontend works fully on its own. The worker adds a plugin seam for
finder APIs (Hunter is pre-wired) plus server-side page scanning:

```bash
cd worker
npx wrangler login
npx wrangler deploy
npx wrangler secret put HUNTER_API_KEY   # optional, enables the Hunter source
```

Then put the worker URL in `config.js`:

```js
window.EF_API = "https://email-finder.<your-subdomain>.workers.dev";
```

To add another source (ZeroBounce, Apollo, ...), add one object to `SOURCES`
in `worker/worker.js` gated on its secret. No other code changes.

Note: Cloudflare Workers cannot open outbound port 25, so raw SMTP mailbox
probing is not possible there. Mailbox-level verification comes from
key-based finder APIs through the plugin seam.

## Cost

Everything runs on free tiers: GitHub Pages (hosting), Cloudflare
DNS-over-HTTPS, Clearbit autocomplete, Gravatar, allorigins.win (page fetch
relay), and optionally the Cloudflare Workers free plan.
