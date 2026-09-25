#!/usr/bin/env node
/**
 * DNS Deliverability Audit
 * Zero-dependency live DNS audit of a sending domain.
 *
 *   node audit-deliverability.cjs example.com
 *   node audit-deliverability.cjs example.com --html > report.html
 *   node audit-deliverability.cjs example.com --json
 *   node audit-deliverability.cjs example.com --selector=mycustom,other
 *
 * Note on DKIM: selectors are NOT enumerable from DNS. A scan can only probe
 * known names. If the client tells you their selector, pass it with --selector.
 *
 * This is the fulfilment tool for the "deliverability audit" service AND the
 * evidence generator for the proof pack. Everything it reports is read live
 * from public DNS — nothing is assumed, nothing is cached.
 */

const dnsMod = require('dns');
const dns = dnsMod.promises;

// The OS resolver negative-caches failed lookups, so a transient failure can be
// replayed as a confident "record missing" for minutes. Where outbound DNS is
// permitted, prefer a public resolver: --resolver=1.1.1.1,8.8.8.8
// Some networks block direct UDP/53, so this stays opt-in.
const customResolvers = (process.argv.find((a) => a.startsWith('--resolver=')) || '')
  .replace('--resolver=', '').split(',').map((s) => s.trim()).filter(Boolean);
if (customResolvers.length) {
  try { dnsMod.setServers(customResolvers); } catch { /* fall back to system */ }
}

const domain = process.argv[2];
const asHTML = process.argv.includes('--html');
const asJSON = process.argv.includes('--json');

if (!domain || domain.startsWith('--')) {
  console.error('usage: node audit_deliverability.cjs <domain> [--html|--json]');
  process.exit(1);
}

// Selectors worth probing. Ordered roughly by how often they appear in the wild.
const extraSelectors = (process.argv.find((a) => a.startsWith('--selector=')) || '')
  .replace('--selector=', '').split(',').map((s) => s.trim()).filter(Boolean);

const DKIM_SELECTORS = [...new Set([
  ...extraSelectors,
  'google', 'default', 'selector1', 'selector2', 's1', 's2',
  'zmail', 'zoho', 'zohomail',
  // Cloudflare Email Routing signs forwarded mail on a dated selector. Absent
  // from this list the tool reported "no DKIM" on a domain that plainly had it.
  'cf2024-1', 'cf2023-1', 'cf2022-1',
  'k1', 'k2', 'k3', 'mail', 'dkim', 'email', 'smtp',
  'resend', 'sendgrid', 'mandrill', 'mailjet', 'sparkpost',
  'pm', 'pic', 'protonmail', 'protonmail2', 'protonmail3',
  'fd', 'fd2', 'mimecast20', 'everlytickey1', 'everlytickey2',
  'hs1-', 'hs2-', 'ctct1', 'ctct2', 'sig1', 'litesrv',
  'mxvault', 'dkim1', 'dkim2', 'key1', 'key2',
])];

const MX_PROVIDERS = [
  [/aspmx.*google|googlemail|smtp\.google/i, 'Google Workspace'],
  [/zoho/i, 'Zoho Mail'],
  [/outlook|protection\.outlook|office365/i, 'Microsoft 365'],
  [/cloudflare/i, 'Cloudflare Email Routing'],
  [/mimecast/i, 'Mimecast'],
  [/proofpoint|pphosted/i, 'Proofpoint'],
  [/messagingengine|fastmail/i, 'Fastmail'],
  [/protonmail/i, 'Proton Mail'],
  [/improvmx/i, 'ImprovMX'],
  [/mailgun|sendgrid|amazonses/i, 'Transactional ESP (not a mailbox host)'],
  [/secureserver|godaddy/i, 'GoDaddy'],
  [/registrar-servers|privateemail/i, 'Namecheap Private Email'],
  [/yandex/i, 'Yandex'],
  [/titan|flockmail/i, 'Titan Mail'],
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Resolvers throttle under burst load. A transient SERVFAIL must never be
// reported to a client as "record missing", so retry anything that is not an
// authoritative "does not exist".
// A throttled resolver returns ENOTFOUND for records that plainly exist, so
// even "does not exist" gets one confirming retry. Reporting a missing SPF
// that is actually present would be worse than a slow scan.
async function resolveWithRetry(fn, name, attempts = 5) {
  for (let i = 0; i < attempts; i++) {
    try { return await fn(name); }
    catch (e) {
      if (i === attempts - 1) return null;
      await sleep(150 * (i + 1) ** 2); // 150, 600, 1350, 2400ms
    }
  }
  return null;
}

// Confirm the resolver is answering before drawing conclusions from silence.
async function preflight(domain) {
  const apex = domain.split('.').slice(-2).join('.');
  for (let i = 0; i < 6; i++) {
    if (await resolveWithRetry((n) => dns.resolve(n, 'NS'), apex, 1)) return true;
    await sleep(400 * (i + 1));
  }
  return false;
}

// attempts=5 for records that must not be missed. DKIM selector probes pass
// attempts=2: most selectors legitimately do not exist, and retrying 40 absent
// names five times each turns a 5-second audit into a several-minute one.
const txt = async (name, attempts = 5) => {
  const r = await resolveWithRetry((n) => dns.resolveTxt(n), name, attempts);
  return r ? r.map((x) => x.join('')) : [];
};

// Probe in small batches rather than 50-wide, which is what triggers throttling.
async function inBatches(items, size, fn) {
  for (let i = 0; i < items.length; i += size) {
    await Promise.all(items.slice(i, i + size).map(fn));
    if (i + size < items.length) await sleep(60); // stay under resolver rate limits
  }
}

const parentOf = (d) => {
  const p = d.split('.');
  return p.length > 2 ? p.slice(1).join('.') : null;
};

// A single resolver can serve an INCOMPLETE TXT RRset, and that silently breaks
// the lookup count. Measured 2026-08-03: for zoho.com, 1.1.1.1 returned 19 TXT
// records with the v=spf1 one absent, over UDP and TCP alike, while 8.8.8.8 and
// 9.9.9.9 both returned 23 including it. The consequence is not cosmetic: an
// include: whose SPF is invisible contributes 1 instead of its whole subtree, so
// mail.missflorenski.com reported 1/10 when the true recursive count is 5.
//
// So SPF resolution never trusts one resolver. Query several independently and
// take the first that actually yields an SPF record. Nothing here is inferred
// from a single answer, which is the same rule the audits themselves run on.
const SPF_RESOLVERS = ['8.8.8.8', '1.1.1.1', '9.9.9.9'];

async function txtFromAnyResolver(name) {
  const attempts = [async () => txt(name, 2)];
  for (const server of SPF_RESOLVERS) {
    attempts.push(async () => {
      // dns.promises.Resolver, NOT dns.Resolver. The latter is callback-only and
      // returns undefined, so the whole probe silently resolves to nothing.
      const r = new dns.Resolver({ timeout: 3000, tries: 2 });
      r.setServers([server]);
      const recs = await r.resolveTxt(name).catch(() => null);
      return recs ? recs.map((x) => x.join('')) : [];
    });
  }
  let best = [];
  for (const attempt of attempts) {
    const recs = await attempt().catch(() => []);
    if (recs.some((t) => /^v=spf1/i.test(t))) return recs; // authoritative enough
    if (recs.length > best.length) best = recs;
  }
  return best;
}

// Count DNS lookups an SPF record forces. Hard-capped at 10 by RFC 7208;
// exceeding it makes SPF PERMERROR, which silently kills authentication.
async function countSpfLookups(record, depth = 0, seen = new Set()) {
  if (depth > 5) return 0;
  let n = 0;
  const mechanisms = record.split(/\s+/);
  for (const m of mechanisms) {
    const lower = m.toLowerCase();
    if (/^(\+|~|-|\?)?(a|mx|ptr|exists)([:/]|$)/.test(lower)) n += 1;
    if (lower.startsWith('include:') || lower.startsWith('redirect=')) {
      n += 1;
      const target = m.split(/[:=]/)[1];
      if (target && !seen.has(target)) {
        seen.add(target);
        const nested = (await txtFromAnyResolver(target)).find((t) => /^v=spf1/i.test(t));
        if (nested) n += await countSpfLookups(nested, depth + 1, seen);
      }
    }
  }
  return n;
}

(async () => {
  const findings = [];
  const add = (severity, area, title, detail, fix) =>
    findings.push({ severity, area, title, detail, fix });

  if (!(await preflight(domain))) {
    console.error(`\nSCAN ABORTED — the resolver is not answering for ${domain}'s zone.`);
    console.error('This is a network or rate-limit problem, not a domain problem. Re-run shortly.\n');
    process.exit(2);
  }

  const result = { domain, checkedAt: new Date().toISOString(), records: {} };

  // ---------------------------------------------------------------- SPF
  const spfRecords = (await txt(domain)).filter((t) => /^v=spf1/i.test(t));
  result.records.spf = spfRecords;

  if (spfRecords.length === 0) {
    add('critical', 'SPF', 'No SPF record',
      'Receiving servers have no published list of who may send as this domain.',
      'Publish a TXT record at the root: v=spf1 include:<your-provider> ~all');
  } else if (spfRecords.length > 1) {
    add('critical', 'SPF', `${spfRecords.length} SPF records published`,
      'More than one SPF record is a permanent error under RFC 7208 — SPF fails entirely, not partially.',
      'Merge them into exactly one TXT record.');
  } else {
    const spf = spfRecords[0];
    const lookups = await countSpfLookups(spf);
    result.spfLookups = lookups;
    if (lookups > 10) {
      add('critical', 'SPF', `SPF exceeds the 10-lookup limit (${lookups})`,
        'Over 10 DNS lookups causes PERMERROR. SPF is treated as absent and mail authenticates on DKIM alone.',
        'Flatten or remove unused include: mechanisms until the count is 10 or below.');
    } else if (lookups >= 8) {
      add('warning', 'SPF', `SPF is near the lookup limit (${lookups}/10)`,
        'Adding one more sending tool will break authentication.',
        'Prune unused includes now, before you add another provider.');
    } else {
      add('pass', 'SPF', `SPF valid — ${lookups}/10 lookups used`, spf, null);
    }
    if (/[+]all/.test(spf)) {
      add('critical', 'SPF', 'SPF ends in +all',
        'This authorises the entire internet to send as your domain. It is worse than having no SPF.',
        'Change +all to ~all (softfail) or -all (hardfail).');
    } else if (!/[~-]all/.test(spf)) {
      add('warning', 'SPF', 'SPF has no all mechanism',
        'Without a terminating all, handling of unlisted senders is left to the receiver.',
        'Append ~all to the record.');
    }
  }

  // -------------------------------------------------------------- DMARC
  let dmarc = (await txt(`_dmarc.${domain}`)).filter((t) => /^v=DMARC1/i.test(t));
  let dmarcSource = domain;
  const parent = parentOf(domain);
  if (dmarc.length === 0 && parent) {
    const inherited = (await txt(`_dmarc.${parent}`)).filter((t) => /^v=DMARC1/i.test(t));
    if (inherited.length) { dmarc = inherited; dmarcSource = `${parent} (organisational-domain fallback)`; }
  }
  result.records.dmarc = dmarc;
  result.dmarcSource = dmarc.length ? dmarcSource : null;

  if (dmarc.length === 0) {
    add('critical', 'DMARC', 'No DMARC record',
      'Since Feb 2024 Google and Yahoo require DMARC for bulk senders. Without it, cold mail is filtered aggressively regardless of SPF and DKIM.',
      'Publish TXT at _dmarc: v=DMARC1; p=none; rua=mailto:you@yourdomain.com');
  } else {
    const rec = dmarc[0];
    const policy = (rec.match(/p=(\w+)/i) || [])[1] || 'none';
    const hasRua = /rua=/i.test(rec);
    add('pass', 'DMARC', `DMARC present (p=${policy}) via ${dmarcSource}`, rec, null);
    if (!hasRua) {
      add('warning', 'DMARC', 'DMARC has no rua= reporting address',
        'You receive no aggregate reports, so you cannot see who is authenticating as you or where alignment is failing.',
        'Add rua=mailto:dmarc@yourdomain.com to the record.');
    }
    if (policy.toLowerCase() === 'none') {
      add('info', 'DMARC', 'DMARC policy is p=none (monitor only)',
        'Correct while establishing a new sending domain. Nothing is enforced yet.',
        'Once reports are clean for 2-4 weeks, move to p=quarantine.');
    }
  }

  // ----------------------------------------------------------------- MX
  const mx = (await resolveWithRetry((n) => dns.resolveMx(n), domain)) || [];
  mx.sort((a, b) => a.priority - b.priority);
  result.records.mx = mx;

  if (mx.length === 0) {
    add('critical', 'MX', 'No MX record',
      'The domain cannot receive mail. Replies to your campaign — including positive ones — will bounce, and receivers treat reply-incapable senders as spam signals.',
      'Point MX at a real mailbox host before sending anything.');
  } else {
    const host = mx.map((m) => m.exchange).join(' ');
    const provider = (MX_PROVIDERS.find(([re]) => re.test(host)) || [, 'Unrecognised / self-hosted'])[1];
    result.mxProvider = provider;
    add('pass', 'MX', `Mailbox host: ${provider}`,
      mx.map((m) => `${m.priority} ${m.exchange}`).join(' · '), null);
    if (/Transactional ESP/.test(provider)) {
      add('warning', 'MX', 'MX points at a transactional ESP',
        'Transactional providers generally prohibit cold outreach in their acceptable-use policy, and enforcement is account-level.',
        'Send cold traffic through a mailbox you own (Google Workspace or Zoho), not a transactional API.');
    }
  }

  // --------------------------------------------------------------- DKIM
  const dkimFound = [];
  await inBatches(DKIM_SELECTORS, 8, async (sel) => {
    const r = await txt(`${sel}._domainkey.${domain}`, 2);
    const key = r.find((t) => /v=DKIM1|p=/i.test(t));
    if (key) dkimFound.push({ selector: sel, record: key });
  });
  dkimFound.sort((a, b) => DKIM_SELECTORS.indexOf(a.selector) - DKIM_SELECTORS.indexOf(b.selector));
  result.records.dkim = dkimFound;

  if (dkimFound.length === 0) {
    add('critical', 'DKIM', 'No DKIM key found on any known selector',
      `Probed ${DKIM_SELECTORS.length} selectors and found none. DKIM selectors cannot be enumerated from DNS — `
      + 'so this means either DKIM is not configured, or it is published under a private selector. '
      + 'Confirm with the mail provider before treating it as absent; re-run with --selector=<name> if you know it.',
      'Enable DKIM signing in your mail provider and publish the key it gives you.');
  } else {
    for (const d of dkimFound) {
      const bits = d.record.length > 400 ? '2048-bit' : '1024-bit';
      add('pass', 'DKIM', `DKIM key on selector "${d.selector}" (${bits})`,
        `${d.record.slice(0, 80)}...`, null);
      if (bits === '1024-bit') {
        add('info', 'DKIM', `Selector "${d.selector}" uses a 1024-bit key`,
          'Still accepted everywhere, but 2048-bit is the current standard.',
          'Rotate to 2048-bit at the next opportunity.');
      }
    }
    if (dkimFound.length > 2) {
      add('warning', 'DKIM', `${dkimFound.length} DKIM keys published`,
        'Multiple live keys usually means an old sending tool was never decommissioned. Stale keys are an impersonation surface.',
        'Remove selectors belonging to providers you no longer send through.');
    }
  }

  // ------------------------------------------------ MTA-STS / TLS-RPT / BIMI
  const mtaSts = await txt(`_mta-sts.${domain}`);
  const tlsRpt = await txt(`_smtp._tls.${domain}`);
  const bimi = await txt(`default._bimi.${domain}`);
  result.records.mtaSts = mtaSts; result.records.tlsRpt = tlsRpt; result.records.bimi = bimi;

  if (mtaSts.length) add('pass', 'TLS', 'MTA-STS policy published', mtaSts[0], null);
  else add('info', 'TLS', 'No MTA-STS policy',
    'Optional. Enforces TLS on inbound mail and is a mild positive reputation signal.',
    'Low priority — address after SPF, DKIM and DMARC are correct.');
  if (tlsRpt.length) add('pass', 'TLS', 'TLS-RPT reporting enabled', tlsRpt[0], null);
  if (bimi.length) add('pass', 'BIMI', 'BIMI record published', bimi[0], null);

  // ------------------------------------------------------- SANITY GATE
  // If literally nothing resolved, the scan failed — do not present that as
  // a finding about the domain. Verify the domain resolves at all.
  const nothingResolved =
    spfRecords.length === 0 && dmarc.length === 0 && mx.length === 0 && dkimFound.length === 0;
  if (nothingResolved) {
    const apex = await resolveWithRetry((n) => dns.resolve(n, 'NS'), domain.split('.').slice(-2).join('.'));
    if (!apex) {
      console.error(`\nSCAN INCONCLUSIVE — no DNS records of any type resolved for ${domain},`);
      console.error('and the parent zone did not answer either. This indicates a resolver or');
      console.error('network problem, not a misconfigured domain. Re-run before reporting.\n');
      process.exit(2);
    }
  }

  // --------------------------------------------------------------- SCORE
  const weight = { critical: 25, warning: 8, info: 0, pass: 0 };
  const penalty = findings.reduce((s, f) => s + (weight[f.severity] || 0), 0);
  const score = Math.max(0, 100 - penalty);
  const verdict =
    score >= 90 ? 'Ready to send' :
    score >= 70 ? 'Sendable, with fixes needed' :
    score >= 40 ? 'Not ready — authentication is incomplete' :
                  'Do not send — mail will be filtered or rejected';
  result.score = score; result.verdict = verdict; result.findings = findings;

  const order = { critical: 0, warning: 1, pass: 2, info: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  // -------------------------------------------------------------- OUTPUT
  if (asJSON) { console.log(JSON.stringify(result, null, 2)); return; }
  if (asHTML) { console.log(html(result)); return; }

  const C = { critical: '\x1b[31m', warning: '\x1b[33m', pass: '\x1b[32m', info: '\x1b[36m', r: '\x1b[0m', b: '\x1b[1m' };
  const label = { critical: 'CRITICAL', warning: 'WARNING ', pass: 'PASS    ', info: 'NOTE    ' };
  console.log(`\n${C.b}Cold Email Deliverability Audit${C.r}`);
  console.log(`Domain:  ${domain}`);
  console.log(`Checked: ${new Date().toUTCString()}`);
  console.log(`\n${C.b}Score: ${score}/100 — ${verdict}${C.r}\n`);
  console.log('─'.repeat(72));
  for (const f of findings) {
    console.log(`${C[f.severity]}${label[f.severity]}${C.r} [${f.area}] ${C.b}${f.title}${C.r}`);
    if (f.detail) console.log(`           ${f.detail}`);
    if (f.fix) console.log(`           ${C.b}Fix:${C.r} ${f.fix}`);
    console.log('');
  }
  console.log('─'.repeat(72));
  const crit = findings.filter((f) => f.severity === 'critical').length;
  const warn = findings.filter((f) => f.severity === 'warning').length;
  console.log(`${crit} critical · ${warn} warning · ${findings.filter(f=>f.severity==='pass').length} passing\n`);
  console.log('Note: DNS authentication is necessary but not sufficient. Inbox');
  console.log('placement also depends on sending history, content, list quality and');
  console.log('complaint rate — none of which are visible in DNS.\n');
})();

function esc(s = '') {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function html(r) {
  const label = { critical: 'Critical', warning: 'Warning', pass: 'Pass', info: 'Note' };
  const rows = r.findings.map((f) => `
      <div class="f ${f.severity}">
        <div class="head"><span class="sev">${label[f.severity]}</span><span class="area">${esc(f.area)}</span>
          <span class="title">${esc(f.title)}</span></div>
        ${f.detail ? `<p class="detail">${esc(f.detail)}</p>` : ''}
        ${f.fix ? `<p class="fix"><strong>Fix:</strong> ${esc(f.fix)}</p>` : ''}
      </div>`).join('');
  const band = r.score >= 90 ? 'good' : r.score >= 70 ? 'ok' : 'bad';
  return `<!doctype html><meta charset="utf-8"><title>Deliverability audit — ${esc(r.domain)}</title>
<style>
:root{--bg:#fff;--fg:#111;--mut:#666;--line:#e5e5e5;--crit:#c0392b;--warn:#b8860b;--pass:#1a7f37;--info:#31708f}
@media(prefers-color-scheme:dark){:root{--bg:#131313;--fg:#eee;--mut:#999;--line:#2c2c2c;--crit:#ff6b5e;--warn:#e8b93b;--pass:#4ac26b;--info:#5ab0d6}}
*{box-sizing:border-box}body{margin:0;padding:40px 24px;background:var(--bg);color:var(--fg);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
.wrap{max-width:760px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}
.meta{color:var(--mut);font-size:13px;margin-bottom:28px}
.score{border:1px solid var(--line);border-radius:10px;padding:20px 24px;margin-bottom:32px}
.score .n{font-size:40px;font-weight:700;line-height:1}
.score .n.good{color:var(--pass)}.score .n.ok{color:var(--warn)}.score .n.bad{color:var(--crit)}
.score .v{color:var(--mut);font-size:14px;margin-top:6px}
.f{border-left:3px solid var(--line);padding:12px 0 12px 16px;margin-bottom:14px}
.f.critical{border-color:var(--crit)}.f.warning{border-color:var(--warn)}
.f.pass{border-color:var(--pass)}.f.info{border-color:var(--info)}
.head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.sev{font-size:11px;text-transform:uppercase;letter-spacing:.07em;font-weight:700}
.critical .sev{color:var(--crit)}.warning .sev{color:var(--warn)}
.pass .sev{color:var(--pass)}.info .sev{color:var(--info)}
.area{font-size:11px;color:var(--mut);border:1px solid var(--line);border-radius:3px;padding:1px 6px}
.title{font-weight:600}
.detail{margin:6px 0 0;color:var(--mut);font-size:14px;word-break:break-word}
.fix{margin:6px 0 0;font-size:14px}
footer{margin-top:36px;padding-top:18px;border-top:1px solid var(--line);color:var(--mut);font-size:13px}
</style><div class="wrap">
<h1>Cold email deliverability audit</h1>
<div class="meta">${esc(r.domain)} · checked ${new Date(r.checkedAt).toUTCString()} · live DNS</div>
<div class="score"><div class="n ${band}">${r.score}<span style="font-size:18px;color:var(--mut)">/100</span></div>
<div class="v">${esc(r.verdict)}</div></div>
${rows}
<footer>DNS authentication is necessary but not sufficient. Inbox placement also depends on
sending history, content, list quality and complaint rate — none of which are visible in DNS.
</footer></div>`;
}
