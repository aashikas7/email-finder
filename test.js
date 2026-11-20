const EF = require("./app.js");
let fails = 0;
function eq(got, want, name) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) { console.log("ok  " + name); }
  else { fails++; console.log("FAIL " + name + "\n  got  " + g + "\n  want " + w); }
}

// parseLinkedIn
eq(EF.parseLinkedIn("https://www.linkedin.com/in/jane-doe/"), { first: "jane", last: "doe" }, "simple slug");
eq(EF.parseLinkedIn("https://www.linkedin.com/in/jane-doe-2b8a1c3/"), { first: "jane", last: "doe" }, "slug with hash");
eq(EF.parseLinkedIn("https://www.linkedin.com/in/aashika-singh-7"), { first: "aashika", last: "singh" }, "trailing number");
eq(EF.parseLinkedIn("linkedin.com/in/marie-curie?trk=public"), { first: "marie", last: "curie" }, "query string");
eq(EF.parseLinkedIn("jane-doe-99a81b2"), { first: "jane", last: "doe" }, "bare slug");
eq(EF.parseLinkedIn("https://www.linkedin.com/in/madonna/"), { first: "madonna", last: "" }, "single name");
eq(EF.parseLinkedIn("https://www.linkedin.com/in/jean-fran%C3%A7ois-paul-9b8a7c"), { first: "jean", last: "paul" }, "accented, hash");
eq(EF.parseLinkedIn("https://www.linkedin.com/company/flobiz"), null, "company URL rejected");
eq(EF.parseLinkedIn("hello"), null, "junk rejected");

// buildPatterns
const pats = EF.buildPatterns("jane", "doe", "acme.com");
eq(pats[0].email, "jane.doe@acme.com", "top pattern");
eq(pats.length, 10, "pattern count");
eq(EF.buildPatterns("madonna", "", "acme.com")[0].email, "madonna@acme.com", "first-only pattern");

// cleanDomain / validDomain
eq(EF.cleanDomain("https://www.Acme.com/careers"), "acme.com", "cleanDomain");
eq(EF.validDomain("acme.com"), true, "valid domain");
eq(EF.validDomain("acme"), false, "invalid domain");

// extractEmails
const html = '<a href="mailto:hr@acme.com">mail</a> contact jane.doe@acme.com or noreply@acme.com, logo@2x.png, user@example.com, careers@flobiz.in';
const found = EF.extractEmails(html);
eq(found.includes("hr@acme.com"), true, "mailto found");
eq(found.includes("jane.doe@acme.com"), true, "bare found");
eq(found.includes("careers@flobiz.in"), true, "second domain found");
eq(found.includes("noreply@acme.com"), false, "noreply dropped");
eq(found.includes("user@example.com"), false, "example dropped");
eq(found.some((e) => e.includes("2x")), false, "image junk dropped");

// emailKind / labels
eq(EF.emailKind("hr@acme.com"), "role", "role address");
eq(EF.emailKind("jane.doe@acme.com"), "personal", "personal address");
eq(EF.emailKind("talentacquisition@tebra.com"), "role", "talentacquisition is a role inbox");
eq(EF.emailKind("jobs@yubico.com"), "role", "jobs is a role inbox");
eq(EF.labelFor({ rank: 90 }, true), "guess", "pattern+MX is an unverified guess");
eq(EF.labelFor({ rank: 30 }, true), "guess", "guess label");
eq(EF.labelFor({ rank: 90 }, false), "unlikely", "unlikely label");
eq(EF.labelFor({ rank: 90, verified: true }, false), "verified", "verified beats unlikely");
eq(EF.labelFor({ rank: 90 }, null), "inconclusive", "inconclusive label");
eq(EF.labelFor({ rank: 90, published: true }, true), "published", "published label");
eq(EF.labelFor({ rank: 90, publicAssoc: true }, true), "seen-publicly", "seen-publicly label");

// scan URL safety
eq(EF.scanUrlSafety("stripe.com/jobs").ok, true, "plain domain ok");
eq(EF.scanUrlSafety("stripe.com/jobs").url, "https://stripe.com/jobs", "https upgrade");
eq(EF.scanUrlSafety("https://user:pass@acme.com/x").ok, false, "credentialed URL refused");
eq(EF.scanUrlSafety("http://192.168.1.10/admin").ok, false, "private IP refused");
eq(EF.scanUrlSafety("http://10.0.0.5/").ok, false, "10.x refused");
eq(EF.scanUrlSafety("http://localhost:3000").ok, false, "localhost refused");
eq(EF.scanUrlSafety("http://wiki.internal/pages").ok, false, ".internal refused");
eq(EF.scanUrlSafety("ftp://acme.com").ok, false, "non-http refused");

// github payload parsing
const ghUser = { email: "Jane.Doe@acme.com" };
const ghEvents = [{ payload: { commits: [{ author: { email: "jane@users.noreply.github.com" } }, { author: { email: "jane.doe@acme.com" } }] } }];
eq(EF.emailsFromGithubPayload(ghUser, ghEvents).sort(), ["jane.doe@acme.com"], "github emails, noreply dropped, lowercased");
eq(EF.emailsFromGithubPayload(null, []), [], "github empty");

// mxProvider
eq(EF.mxProvider(["aspmx.l.google.com"], "acme.com"), "Google-hosted mail", "google mx");
eq(EF.mxProvider(["aspmx.l.google.com"], "gmail.com"), "Gmail (consumer)", "consumer gmail not Workspace");

console.log(fails ? "\n" + fails + " FAILURES" : "\nall tests passed");
process.exit(fails ? 1 : 0);
