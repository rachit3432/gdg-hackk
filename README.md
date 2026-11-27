# AEGIS // PROTOCOL — Zero-Backend PII Sanitizer

**AEGIS // PROTOCOL** (formerly NEON//SCRUB) is a client-side, zero-network, browser-based PII detection and redaction tool, presented as a tactical security landing page with the live sanitizer embedded in it. All scanning, validation, redaction, and export generation run strictly inside your browser's memory.

## Quick Start

1. **Open directly**: Double-click `index.html` (`file://` works out of the box—no server, build step, or `npm install` required).
2. **Or serve statically**: Open from any static file server (e.g. `python -m http.server 8080`).
3. **Run tests**: Open `tests/tests.html` in your browser to execute the zero-dependency diagnostic suite.

## Supported Entities & Validators

| Type | Detection & Validation Rules |
| :--- | :--- |
| **EMAIL** | RFC-style pattern supporting plus-tags (`+billing`), subdomains, and sentence punctuation boundaries |
| **PHONE** | Indian mobiles (`+91` / `0091` / `0` / bare `6–9XXXXXXXXX` with optional grouping) & International E.164 (`+CC ...`, 8–15 digits); excludes dates, timestamps, bare `<6` 10-digit numbers, and embedded digits |
| **IP** | Strict IPv4 (`0–255` octets, excludes leading-zero octets, version strings like `v1.2.3.4`, and trailing sentence periods) + IPv6 (`2001:db8::1`, `::1`, full 8-group) |
| **PAN (IN)** | `[A-Z]{5}[0-9]{4}[A-Z]` (case-insensitive) with 4th-char holder-type check (`P, C, H, F, A, T, B, L, J, G`) |
| **AADHAAR** | 12 digits starting `2–9` (ungrouped or `4-4-4` space/hyphen) validated with the **Verhoeff checksum** |
| **CREDIT_CARD** | 13–19 digits (consistent space/hyphen or ungrouped) validated with the **Luhn algorithm**, plus IIN brand inference (`Visa`, `Mastercard`, `Amex`, `RuPay`, `Discover`) |

Overlap resolution priority: `CREDIT_CARD > AADHAAR > PAN > EMAIL > IP > PHONE` (longer match wins on tie).

## Redaction Modes

- **FULL MASK**: Replaces entities with `[REDACTED]` or typed blocks (`[REDACTED:EMAIL]`, etc.).
- **PARTIAL MASK**: Preserves minimal context and original separators (`XXXX-XXXX-XXXX-1234`, `XXXX-XXXX-9012`, `XXXXXX234F`, `+91-XXXXX-X3210`, `j***@d***.com`, `192.168.XXX.XXX`).
- **PSEUDONYM**: Consistent normalized placeholders (`USER_01`, `PHONE_01`, `IP_01`, `PAN_01`, `AADHAAR_01`, `CARD_01`) across the entire document with a live mapping inspector and optional JSON export.

## Architecture

```text
index.html          Strict CSP; landing page (nav, hero console, bento, sanitizer, defense matrix, CTA, footer)
css/styles.css      Tactical dark theme: 80/15/5 palette, 1px hairlines, clip-path chamfers, reduced-motion support
js/validators.js    Pure Luhn, Verhoeff, IPv4/IPv6, PAN holder, IIN brand helpers
js/detectors.js     Single-pass scanners, boundary rules, overlap resolver, time-sliced scanAsync
js/redactors.js     Full / Partial / Pseudonym engines, risk score, safe audit report
js/sample.js        52-line synthetic multi-domain sample with valid entities & decoys
js/ui.js            Pure DOM rendering (no innerHTML), mirrored backdrop diff, scroll sync
js/app.js           In-memory state, debounced pipeline, drag-drop upload, exports, WIPE
js/scene3d.js       Hero "scrub core": hand-rolled 3D canvas (point-cloud sphere, icosahedron, orbiting PII tokens redacted by the engine at the scan gate)
js/landing.js       Landing interactions: telemetry console, measured stats, before/after gate, use-case previews, defense matrix (live engine readouts), scroll reveals
tests/tests.html    In-browser test runner
tests/tests.js      Unit + integration test suite
```

## Privacy Guarantees

- **Zero network requests**: Strict `<meta http-equiv="Content-Security-Policy">` (`default-src 'none'; connect-src 'none'; ...`) blocks outbound network APIs, remote fonts, and remote assets.
- **No persistence**: Never touches `localStorage`, `sessionStorage`, `cookies`, or `IndexedDB`.
- **XSS-safe rendering**: Never assigns user input to `innerHTML`; builds DOM text nodes and `<mark>` elements directly.
- **WIPE button**: Immediately purges all raw text, findings, mappings, file metadata, and DOM previews from memory.
- **Audit Report safety**: `AUDIT REPORT (JSON)` exports counts, types, rejected-candidate counts, and scores only—never raw or masked PII.

## Ignore Semantics

- **Ignore safety**: an IGNORE choice is keyed by value and occurrence (`TYPE:normalized#n`), not by character offset, so editing the text can never move an ignore onto a different PII value.
- **Stable pseudonyms**: placeholder numbers are assigned by first appearance before ignores are applied, so ignoring one value never renumbers the others.

## Limitations

- **Unstructured names / addresses**: NEON//SCRUB targets structured identifiers (email, phone, IP, PAN, Aadhaar, payment cards) rather than free-form NLP named-entity recognition.
- **Client file cap**: Uploads are capped at 5 MB (`text/plain` / `text/csv`) to keep client-side DOM diffing responsive.
- **Cooperative chunking vs. Web Workers**: Strict `script-src 'self'` CSP forbids `blob:` Web Workers, so large files (~2 MB) are scanned via cooperative line-bounded time-slicing (`scanAsync`).
- **Bare 10-digit numbers**: Any standalone 10-digit number starting with `6–9` matches Indian mobile rules unless ignored manually via the Findings table's `IGNORE` checkbox.
