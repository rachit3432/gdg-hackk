(function (global) {
  'use strict';

  function assert(cond, msg) {
    if (!cond) {
      throw new Error(msg || 'Assertion failed');
    }
  }

  function assertEqual(actual, expected, msg) {
    if (actual !== expected) {
      throw new Error(
        (msg ? msg + ' — ' : '') +
          'Expected ' +
          JSON.stringify(expected) +
          ' but got ' +
          JSON.stringify(actual)
      );
    }
  }

  function createRunner() {
    const suites = [];
    let current = null;

    function suite(name, fn) {
      current = { name: name, cases: [] };
      suites.push(current);
      fn();
      current = null;
    }

    function test(name, fn) {
      current.cases.push({ name: name, fn: fn });
    }

    async function run() {
      const t0 = performance.now();
      let total = 0;
      let passed = 0;
      let failed = 0;
      const results = [];

      for (let i = 0; i < suites.length; i++) {
        const s = suites[i];
        const outCases = [];
        for (let j = 0; j < s.cases.length; j++) {
          const c = s.cases[j];
          total++;
          try {
            const ret = c.fn();
            if (ret && typeof ret.then === 'function') {
              await ret;
            }
            passed++;
            outCases.push({ name: c.name, ok: true });
          } catch (err) {
            failed++;
            outCases.push({
              name: c.name,
              ok: false,
              error: err && err.message ? err.message : String(err)
            });
          }
        }
        results.push({ name: s.name, cases: outCases });
      }

      return {
        total: total,
        passed: passed,
        failed: failed,
        durationMs: Math.round(performance.now() - t0),
        suites: results
      };
    }

    return { suite: suite, test: test, run: run };
  }

  function renderResults(res) {
    document.getElementById('totalCount').textContent = String(res.total);
    document.getElementById('passCount').textContent = String(res.passed);
    document.getElementById('failCount').textContent = String(res.failed);
    document.getElementById('durationMs').textContent = res.durationMs + ' ms';

    const badge = document.getElementById('overallBadge');
    if (res.failed === 0) {
      badge.textContent = 'ALL ' + res.total + ' TESTS PASSED';
      badge.className = 'test-badge';
    } else {
      badge.textContent = res.failed + ' FAILED // ' + res.passed + ' PASSED';
      badge.className = 'test-badge is-fail';
    }

    const container = document.getElementById('suiteList');
    const frag = document.createDocumentFragment();

    for (let i = 0; i < res.suites.length; i++) {
      const s = res.suites[i];
      const card = document.createElement('section');
      card.className = 'suite-card hud-frame';

      const heading = document.createElement('h2');
      heading.className = 'suite-title';
      heading.textContent = s.name;
      card.appendChild(heading);

      for (let j = 0; j < s.cases.length; j++) {
        const c = s.cases[j];
        const row = document.createElement('div');
        row.className = 'case-row';

        const nameSpan = document.createElement('span');
        nameSpan.textContent = c.name;

        const statusSpan = document.createElement('span');
        statusSpan.className = 'case-status ' + (c.ok ? 'case-pass' : 'case-fail');
        statusSpan.textContent = c.ok ? 'PASS' : 'FAIL';

        row.appendChild(nameSpan);
        row.appendChild(statusSpan);
        card.appendChild(row);

        if (!c.ok) {
          const errBox = document.createElement('pre');
          errBox.className = 'case-error';
          errBox.textContent = c.error;
          card.appendChild(errBox);
        }
      }

      frag.appendChild(card);
    }

    container.replaceChildren(frag);
  }

  document.addEventListener('DOMContentLoaded', function () {
    const V = global.Scrub.validators;
    const D = global.Scrub.detectors;
    const R = global.Scrub.redactors;
    const SAMPLE = global.Scrub.sample.TEXT;

    const r = createRunner();

    r.suite('1. Luhn & Card Brand Validators', function () {
      r.test('Accepts valid Visa, Mastercard, Amex, RuPay, Discover', function () {
        assert(V.luhnCheck('4111 1111 1111 1111'), 'Visa test card');
        assert(V.luhnCheck('5555-5555-5555-4444'), 'Mastercard test card');
        assert(V.luhnCheck('378282246310005'), 'Amex test card');
        assert(V.luhnCheck('6070950000000016'), 'RuPay test card');
        assert(V.luhnCheck('6011000990139424'), 'Discover test card');

        assertEqual(V.inferCardBrand('4111111111111111'), 'Visa');
        assertEqual(V.inferCardBrand('5555555555554444'), 'Mastercard');
        assertEqual(V.inferCardBrand('378282246310005'), 'Amex');
        assertEqual(V.inferCardBrand('6070950000000016'), 'RuPay');
        assertEqual(V.inferCardBrand('6011000990139424'), 'Discover');
      });

      r.test('Rejects Luhn-invalid numbers, order IDs, and all-zeros', function () {
        assert(!V.luhnCheck('4111 1111 1111 1112'), 'Mutated check digit');
        assert(!V.luhnCheck('1234567890123456'), 'Order ID 16 digits');
        assert(!V.luhnCheck('0000000000000000'), 'All zeros');
        assert(!V.luhnCheck('411111111111'), '12 digits too short');
      });
    });

    r.suite('2. Verhoeff & Aadhaar Validators', function () {
      r.test('Accepts canonical Verhoeff and generated Aadhaar numbers', function () {
        assert(V.verhoeffCheck('2363'), 'Canonical 2363');
        assert(V.isValidAadhaar('2345 6789 0124'), 'Generated Aadhaar 1');
        assert(V.isValidAadhaar('7845-1236-9013'), 'Generated Aadhaar 2');
        assert(V.isValidAadhaar('543219876545'), 'Generated Aadhaar 3');
      });

      r.test('Rejects Verhoeff failures, transpositions, and 0/1 prefixes', function () {
        assert(!V.isValidAadhaar('2345 6789 0120'), 'Single digit error');
        assert(!V.isValidAadhaar('2345 6789 0142'), 'Adjacent transposition error');
        const badStart = '12345678901' + V.verhoeffGenerateCheckDigit('12345678901');
        assert(!V.isValidAadhaar(badStart), 'Starts with 1 must be rejected for Aadhaar');
      });
    });

    r.suite('3. IPv4 & IPv6 Validators + Boundaries', function () {
      r.test('Validates IPv4 0-255 boundaries and rejects >255 / leading zeros', function () {
        assert(V.isValidIPv4('0.0.0.0'));
        assert(V.isValidIPv4('255.255.255.255'));
        assert(V.isValidIPv4('192.168.1.1'));
        assert(!V.isValidIPv4('256.0.0.1'));
        assert(!V.isValidIPv4('999.300.1.1'));
        assert(!V.isValidIPv4('01.2.3.4'));
      });

      r.test('Validates IPv6 and rejects timestamps / MACs / bare colons', function () {
        assert(V.isValidIPv6('2001:0db8:85a3::8a2e:0370:7334'));
        assert(V.isValidIPv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334'));
        assert(V.isValidIPv6('::1'));
        assert(!V.isValidIPv6('14:32:09'));
        assert(!V.isValidIPv6('00:1A:2B:3C:4D:5E'));
        assert(!V.isValidIPv6('::'));
      });

      r.test('Handles trailing period and excludes v1.2.3.4 and 5-octet strings', function () {
        const res = D.scan('Host 198.51.100.14. Ver v1.2.3.4 Bad 999.1.1.1 Extra 1.2.3.4.5');
        assertEqual(res.counts.IP, 1, 'Only 198.51.100.14 should match');
        assertEqual(res.findings[0].raw, '198.51.100.14');
        assertEqual(res.rejected.IP, 1, '999.1.1.1 tracked as rejected IP');
      });
    });

    r.suite('4. PAN Holder Validation & Case Handling', function () {
      r.test('Accepts all 10 holder types and rejects invalid 4th characters', function () {
        const validCodes = ['P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G'];
        for (let i = 0; i < validCodes.length; i++) {
          assert(V.isValidPanHolder('ABC' + validCodes[i] + 'E1234F'), 'Code ' + validCodes[i]);
        }
        assert(!V.isValidPanHolder('ABCXE1234F'), 'X is invalid holder type');
        assert(!V.isValidPanHolder('XYZQE4512K'), 'Q is invalid holder type');

        const scanRes = D.scan('Lower abcpe1234f and decoy XYZQE4512K');
        assertEqual(scanRes.counts.PAN, 1);
        assertEqual(scanRes.findings[0].raw, 'abcpe1234f');
        assertEqual(scanRes.rejected.PAN, 1);
      });
    });

    r.suite('5. Phone Detection & Non-Phone Decoys', function () {
      r.test('Matches Indian mobile variants and international E.164', function () {
        const text =
          'M1: +91-98765-43210 | M2: 98765 43210 | M3: 09876543210 | M4: 0091-91234-56789 | US: +1 (415) 555-0192 | UK: +44 20 7946 0958';
        const res = D.scan(text);
        assertEqual(res.counts.PHONE, 6, 'All 6 phones should match');
      });

      r.test('Ignores bare 10-digit <6, dates, timestamps, and longer digit chains', function () {
        const text =
          'Bare: 5551234567, 4012345678 | Date: 2024-01-15 | TS: 2026-11-27T09:14:22Z | Long: 987654321019 | Ref: 1234567890123456';
        const res = D.scan(text);
        assertEqual(res.total, 0, 'No PII should match decoys');

        // Also confirm PHONE detector alone ignores 12-digit chains even if Verhoeff-valid
        const phoneOnly = D.scan('ID 987654321012', { PHONE: true });
        assertEqual(phoneOnly.total, 0, 'Phone detector must not match inside 12-digit number');
      });
    });

    r.suite('6. Overlap Resolution Priority', function () {
      r.test('CREDIT_CARD > AADHAAR > PAN > EMAIL > IP > PHONE & longer match wins', function () {
        // Embedded digits inside email & longer +91 phone vs inner 10-digit phone
        const res = D.scan('Email: user.9876543210@sub.example.com and Tel: +91-98765-43210');
        assertEqual(res.total, 2);
        assertEqual(res.findings[0].type, 'EMAIL');
        assertEqual(res.findings[1].type, 'PHONE');
        assertEqual(res.findings[1].raw, '+91-98765-43210', 'Longer +91 match beats inner 98765-43210');

        // Verify no overlaps anywhere
        for (let i = 1; i < res.findings.length; i++) {
          assert(res.findings[i].start >= res.findings[i - 1].end, 'No overlapping spans');
        }
      });
    });

    r.suite('7. Partial Masking Formats', function () {
      r.test('Formats all 6 entity types preserving separators and minimal context', function () {
        assertEqual(R.maskPartial('CREDIT_CARD', '4111-1111-1111-1234'), 'XXXX-XXXX-XXXX-1234');
        assertEqual(R.maskPartial('CREDIT_CARD', '4111 1111 1111 1234'), 'XXXX XXXX XXXX 1234');
        assertEqual(R.maskPartial('AADHAAR', '2345-6789-9012'), 'XXXX-XXXX-9012');
        assertEqual(R.maskPartial('AADHAAR', '2345 6789 9012'), 'XXXX XXXX 9012');
        assertEqual(R.maskPartial('PAN', 'abcpe1234f'), 'XXXXXX234F');
        assertEqual(R.maskPartial('PHONE', '+91-98765-43210'), '+91-XXXXX-X3210');
        assertEqual(R.maskPartial('PHONE', '9876543210'), 'XXXXXX3210');
        assertEqual(R.maskPartial('EMAIL', 'john@domain.com'), 'j***@d***.com');
        assertEqual(R.maskPartial('EMAIL', 'Priya.Sharma+tag@sub.acme.org'), 'P***@s***.org');
        assertEqual(R.maskPartial('IP', '192.168.10.42'), '192.168.XXX.XXX');
        assertEqual(R.maskPartial('IP', '2001:0db8:85a3::1'), '2001:0db8:XXXX::XXXX');
      });
    });

    r.suite('8. Consistent Pseudonymization & Normalization', function () {
      r.test('Maps casing and separator variants to identical TYPE_NN placeholders', function () {
        const text = [
          'E1: John.Doe+tag@Example.com | E2: john.doe+tag@example.com',
          'C1: 4111 1111 1111 1111 | C2: 4111-1111-1111-1111',
          'A1: 2345 6789 0124 | A2: 2345-6789-0124',
          'P1: ABCPE1234F | P2: abcpe1234f',
          'M1: +91-98765-43210 | M2: +91 98765 43210',
          'I1: 2001:0DB8::1 | I2: 2001:0db8::1'
        ].join('\n');

        const scanRes = D.scan(text);
        const red = R.redact(text, scanRes.findings, R.MODES.PSEUDONYM);

        assert(red.output.indexOf('E1: USER_01 | E2: USER_01') !== -1, 'Emails match USER_01');
        assert(red.output.indexOf('C1: CARD_01 | C2: CARD_01') !== -1, 'Cards match CARD_01');
        assert(red.output.indexOf('A1: AADHAAR_01 | A2: AADHAAR_01') !== -1, 'Aadhaar matches AADHAAR_01');
        assert(red.output.indexOf('P1: PAN_01 | P2: PAN_01') !== -1, 'PAN matches PAN_01');
        assert(red.output.indexOf('M1: PHONE_01 | M2: PHONE_01') !== -1, 'Phone matches PHONE_01');
        assert(red.output.indexOf('I1: IP_01 | I2: IP_01') !== -1, 'IP matches IP_01');
        assertEqual(red.mapping.length, 6, 'Only 6 unique mappings for 12 occurrences');
      });
    });

    r.suite('9. Full Sample End-to-End, CRLF, Empty Input & Async', function () {
      r.test('Detects all 6 types on sample and leaves decoys untouched', function () {
        const scanRes = D.scan(SAMPLE);
        for (let i = 0; i < D.ENTITY_TYPES.length; i++) {
          const t = D.ENTITY_TYPES[i];
          assert(scanRes.counts[t] > 0, 'Sample must detect ' + t);
        }
        assert(scanRes.rejected.CREDIT_CARD >= 2, 'Sample rejects Luhn-invalid cards');
        assert(scanRes.rejected.AADHAAR >= 2, 'Sample rejects Verhoeff-invalid Aadhaars');
        assert(scanRes.rejected.IP >= 1, 'Sample rejects 999.300.1.1');
        assert(scanRes.rejected.PAN >= 1, 'Sample rejects XYZQE4512K');

        const redFull = R.redact(SAMPLE, scanRes.findings, R.MODES.FULL, { typedLabels: true });
        assert(redFull.output.includes('v1.2.3.4'), 'Version string preserved');
        assert(redFull.output.includes('999.300.1.1'), 'Invalid IP preserved');
        assert(redFull.output.includes('4111 1111 1111 1112'), 'Luhn-invalid card preserved');
        assert(redFull.output.includes('1234567890123456'), 'Order ID preserved');
        assert(redFull.output.includes('2345 6789 0120'), 'Verhoeff-invalid Aadhaar preserved');
        assert(redFull.output.includes('XYZQE4512K'), 'Invalid PAN decoy preserved');
        assert(redFull.output.includes('2026-11-27T09:14:22Z'), 'Timestamp preserved');
        assert(redFull.output.includes('[REDACTED:CREDIT_CARD]'), 'Typed card label applied');

        const redPseudo = R.redact(SAMPLE, scanRes.findings, R.MODES.PSEUDONYM);
        const priyaOccurrences = redPseudo.output.match(/USER_01/g) || [];
        assertEqual(priyaOccurrences.length, 3, 'Priya email repeated 3x with mixed casing -> USER_01');

        const stats = R.computeRiskStats(scanRes.findings, new Set(), scanRes.rejected, true);
        assertEqual(stats.outputExposure, 0, 'Output exposure drops to 0');
        const reportStr = JSON.stringify(
          R.buildAuditReport({
            mode: 'full',
            typedLabels: false,
            inputLength: SAMPLE.length,
            outputLength: redFull.output.length,
            lineCount: SAMPLE.split('\n').length,
            stats: stats
          })
        );
        assert(!reportStr.includes('Priya.Sharma'), 'Audit report contains zero PII');
        assert(!reportStr.includes('4111 1111'), 'Audit report contains zero cards');
      });

      r.test('Preserves CRLF line endings and non-PII text verbatim', function () {
        const crlf = 'id,email,phone\r\n101,alice@example.com,9876543210\r\n102,bob@example.org,+91-91234-56789\r\n';
        const scanRes = D.scan(crlf);
        const red = R.redact(crlf, scanRes.findings, R.MODES.FULL);
        assertEqual(
          red.output,
          'id,email,phone\r\n101,[REDACTED],[REDACTED]\r\n102,[REDACTED],[REDACTED]\r\n'
        );
      });

      r.test('Handles empty input gracefully', function () {
        const scanRes = D.scan('');
        assertEqual(scanRes.total, 0);
        const red = R.redact('', scanRes.findings, R.MODES.FULL);
        assertEqual(red.output, '');
        const stats = R.computeRiskStats(scanRes.findings, new Set(), scanRes.rejected, false);
        assertEqual(stats.inputRisk, 0);
        assertEqual(stats.outputExposure, 0);
      });

      r.test('Time-sliced scanAsync handles ~300 KB payload accurately', async function () {
        const chunk = 'Log: 2026-11-27 user@example.com 192.168.1.5 +91-98765-43210\n';
        const bigText = chunk.repeat(5000); // ~315 KB
        const asyncRes = await D.scanAsync(bigText, null, { chunkSize: 80000 });
        assertEqual(asyncRes.counts.EMAIL, 5000);
        assertEqual(asyncRes.counts.IP, 5000);
        assertEqual(asyncRes.counts.PHONE, 5000);
      });
    });

    r.suite('10. Regression: ignore safety, stable pseudonyms, mapping export', function () {
      r.test('Ignore keys are value-based: an edit can never un-redact a different value', function () {
        const before = 'a@x.com b@y.com';
        const f1 = D.scan(before).findings;
        const ignored = new Set([f1[0].key]); // ignore a@x.com
        const after = 'b@y.com a@x.com'; // b@y.com now sits at a@x.com's old offset
        const f2 = D.scan(after).findings;
        const out = R.redact(after, f2, R.MODES.FULL, { ignoredKeys: ignored }).output;
        assertEqual(out, '[REDACTED] a@x.com', 'Only the ignored value stays visible');
      });

      r.test('Keys are identical across CRLF and LF versions of the same text', function () {
        const lf = 'x a@x.com\ny 4111 1111 1111 1111\nz a@x.com';
        const crlf = lf.replace(/\n/g, '\r\n');
        const k1 = D.scan(lf).findings.map(function (f) { return f.key; }).join('|');
        const k2 = D.scan(crlf).findings.map(function (f) { return f.key; }).join('|');
        assertEqual(k1, k2);
        assert(k1.indexOf('EMAIL:a@x.com#2') !== -1, 'Second occurrence is numbered #2');
      });

      r.test('Ignoring one value never renumbers the other pseudonyms', function () {
        const text = 'a@x.com b@y.com c@z.com';
        const f = D.scan(text).findings;
        const all = R.redact(text, f, R.MODES.PSEUDONYM).output;
        const some = R.redact(text, f, R.MODES.PSEUDONYM, { ignoredKeys: new Set([f[0].key]) }).output;
        assertEqual(all, 'USER_01 USER_02 USER_03');
        assertEqual(some, 'a@x.com USER_02 USER_03');
      });

      r.test('Mapping list excludes ignored values; export keys are type-scoped', function () {
        const text = 'a@x.com b@y.com';
        const f = D.scan(text).findings;
        const red = R.redact(text, f, R.MODES.PSEUDONYM, { ignoredKeys: new Set([f[0].key]) });
        assertEqual(red.mapping.length, 1, 'Ignored value is not in the reversible mapping');
        const exp = R.buildMappingExport(red.mapping);
        assert(Object.prototype.hasOwnProperty.call(exp.normalizedToPlaceholder, 'EMAIL:b@y.com'), 'Forward map keyed by TYPE:value');
      });
    });

    r.run().then(renderResults);
  });
})(window);
