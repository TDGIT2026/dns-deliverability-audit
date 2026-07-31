# DNS Deliverability Audit

A single file, zero dependency Node script that audits the DNS side of email deliverability for a domain and
scores it out of 100. Every finding is ranked and comes with the exact fix.

It answers one question: **if this domain sends mail today, what will reject it, and why?**

```bash
node audit-deliverability.cjs example.com
```

No install, no API key, no account. It reads public DNS and nothing else.

## What it checks

| Check | What it actually verifies |
|---|---|
| **SPF** | Record validity, syntax, and the **10 lookup limit counted through nested includes**, which is where most SPF records silently fail |
| **DKIM** | Scans 40+ known selectors, reports key size, and flags **stale keys left behind by decommissioned tools** |
| **DMARC** | Presence, policy, alignment mode, `rua` destination, and organisational domain fallback |
| **MX** | Resolves the mailbox host and identifies the provider |
| **MTA-STS / TLS** | Policy presence, reported as optional |
| **BIMI** | Record presence |

## Why the SPF lookup count matters

The SPF limit is 10 DNS lookups, and it is counted **recursively**. A record with four `include:` statements
can be well over the limit once each include's own includes are resolved. Past the limit the result is
`permerror`, and receivers are free to treat that as a fail. Most online checkers count only the top level
and report a passing record that is not passing.

## Why stale DKIM keys matter

DKIM selectors **cannot be enumerated from DNS**. There is no way to list them, you can only guess names and
query each one. So a key published for a tool you stopped using three years ago stays live and invisible.
Anyone who still holds that private key can sign mail as your domain and pass DKIM.

This tool brute forces a list of 40+ known provider selectors specifically to surface those.

If you know a custom selector name, pass it:

```bash
node audit-deliverability.cjs example.com --selector=mycustomselector
```

## Sample output

Run against `cloudflare.com`:

```
Cold Email Deliverability Audit
Domain:  cloudflare.com

Score: 92/100 — Ready to send

────────────────────────────────────────────────────────────────────────
WARNING  [DKIM] 3 DKIM keys published
           Multiple live keys usually means an old sending tool was never
           decommissioned. Stale keys are an impersonation surface.
           Fix: Remove selectors belonging to providers you no longer send through.

PASS     [SPF] SPF valid — 7/10 lookups used
PASS     [DMARC] DMARC present (p=reject) via cloudflare.com
PASS     [MX] Mailbox host: Unrecognised / self-hosted
PASS     [DKIM] DKIM key on selector "s1" (2048-bit)
PASS     [DKIM] DKIM key on selector "k1" (1024-bit)
PASS     [DKIM] DKIM key on selector "mandrill" (1024-bit)
PASS     [BIMI] BIMI record published

NOTE     [DKIM] Selector "k1" uses a 1024-bit key
NOTE     [DKIM] Selector "mandrill" uses a 1024-bit key
NOTE     [TLS] No MTA-STS policy
────────────────────────────────────────────────────────────────────────
0 critical · 1 warning · 7 passing
```

Even a domain scoring 92 has something worth fixing.

## What it deliberately does not claim

DNS authentication is necessary but not sufficient. Inbox placement also depends on sending history, content,
list quality and complaint rate, none of which are visible in DNS. A 100 out of 100 here means your mail is
authenticated correctly. It does not mean your mail lands in the primary inbox.

## Notes

- Requires Node 18 or newer. No dependencies.
- Failed DNS lookups are retried rather than scored as zero, because a transient resolver failure otherwise
  reads identically to a missing record. If lookups keep failing the run aborts as inconclusive instead of
  reporting a false negative.
- macOS negative caches failed lookups, so a transient failure can replay as "record missing" until the cache
  expires.

## License

MIT
