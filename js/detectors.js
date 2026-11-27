(function (global) {
  'use strict';

  const Scrub = (global.Scrub = global.Scrub || {});

  const ENTITY_TYPES = ['CREDIT_CARD', 'AADHAAR', 'PAN', 'EMAIL', 'IP', 'PHONE'];

  // Overlap resolution priority: higher number wins
  const ENTITY_PRIORITY = {
    CREDIT_CARD: 6,
    AADHAAR: 5,
    PAN: 4,
    EMAIL: 3,
    IP: 2,
    PHONE: 1
  };

  const ENTITY_META = {
    EMAIL: { label: 'EMAIL', colorVar: '--color-email' },
    PHONE: { label: 'PHONE', colorVar: '--color-phone' },
    IP: { label: 'IP ADDR', colorVar: '--color-ip' },
    PAN: { label: 'PAN (IN)', colorVar: '--color-pan' },
    AADHAAR: { label: 'AADHAAR', colorVar: '--color-aadhaar' },
    CREDIT_CARD: { label: 'CREDIT CARD', colorVar: '--color-card' }
  };

  function isAlphaNum(ch) {
    return ch !== undefined && /[A-Za-z0-9]/.test(ch);
  }

  function isDigit(ch) {
    return ch !== undefined && ch >= '0' && ch <= '9';
  }

  /** Inputs at or below this size are scanned synchronously (one tick); larger ones are time-sliced. */
  const SYNC_SCAN_LIMIT = 160000;

  /**
   * True when a digit run is not glued to letters/digits and not part of a longer
   * dotted, hyphenated or separator-joined number (dates, versions, longer IDs).
   * @param {string} text
   * @param {number} start
   * @param {number} end
   * @param {string} sep separator used inside the run ('' when ungrouped)
   */
  function isIsolatedDigitRun(text, start, end, sep) {
    const prev = start > 0 ? text[start - 1] : undefined;
    const next = end < text.length ? text[end] : undefined;
    if (isAlphaNum(prev) || isAlphaNum(next)) {
      return false;
    }
    const digitBefore = start >= 2 && isDigit(text[start - 2]);
    const digitAfter = end + 1 < text.length && isDigit(text[end + 1]);
    if (digitBefore && (prev === '.' || prev === '-' || (sep && prev === sep))) {
      return false;
    }
    if (digitAfter && (next === '.' || next === '-' || (sep && next === sep))) {
      return false;
    }
    return true;
  }

  function createEmptyRejected() {
    return {
      CREDIT_CARD: 0,
      AADHAAR: 0,
      PAN: 0,
      IP: 0
    };
  }

  function createEmptyCounts() {
    return {
      EMAIL: 0,
      PHONE: 0,
      IP: 0,
      PAN: 0,
      AADHAAR: 0,
      CREDIT_CARD: 0
    };
  }

  /**
   * Scan EMAIL entities with zero-backtracking pattern + boundary checks.
   */
  function scanEmails(text, candidates) {
    const V = Scrub.validators;
    const re = /[A-Za-z0-9]+(?:[._%+\-][A-Za-z0-9]+)*@(?:[A-Za-z0-9]+(?:\-[A-Za-z0-9]+)*\.)+[A-Za-z]{2,24}/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const raw = m[0];
      const start = m.index;
      const end = start + raw.length;
      const prev = start > 0 ? text[start - 1] : undefined;
      const next = end < text.length ? text[end] : undefined;

      if (prev && /[A-Za-z0-9_%+\-]/.test(prev)) {
        continue;
      }
      if (prev === '.' && start >= 2 && isAlphaNum(text[start - 2])) {
        continue;
      }
      if (next && /[A-Za-z0-9_%+\-@]/.test(next)) {
        continue;
      }
      if (next === '.' && end + 1 < text.length && isAlphaNum(text[end + 1])) {
        continue;
      }
      if (!V.isValidEmail(raw)) {
        continue;
      }
      candidates.push({
        type: 'EMAIL',
        start: start,
        end: end,
        raw: raw,
        meta: {}
      });
    }
  }

  /**
   * Scan CREDIT_CARD candidates (13-19 digits, optional consistent space/hyphen)
   * and validate with Luhn. Rejects are tracked for audit proof.
   */
  function scanCreditCards(text, candidates, rejected) {
    const V = Scrub.validators;
    const re = /([1-9]\d{12,18})|([1-9]\d{1,5}([ \t-])\d{2,6}(?:\3\d{2,6}){1,4})/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const raw = m[0];
      const sep = m[3] || '';
      const start = m.index;
      const end = start + raw.length;
      if (!isIsolatedDigitRun(text, start, end, sep)) {
        continue;
      }

      const digits = raw.replace(/[ \t-]/g, '');
      if (digits.length < 13 || digits.length > 19) {
        continue;
      }

      if (V.luhnCheck(digits)) {
        candidates.push({
          type: 'CREDIT_CARD',
          start: start,
          end: end,
          raw: raw,
          meta: {
            brand: V.inferCardBrand(digits)
          }
        });
      } else {
        rejected.CREDIT_CARD++;
      }
    }
  }

  /**
   * Scan Indian AADHAAR candidates (12 digits, starts 2-9, optional 4-4-4 grouping)
   * and validate with Verhoeff checksum.
   */
  function scanAadhaar(text, candidates, rejected) {
    const V = Scrub.validators;
    const re = /[2-9]\d{11}|[2-9]\d{3}([ \t-])\d{4}\1\d{4}/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const raw = m[0];
      const sep = m[1] || '';
      const start = m.index;
      const end = start + raw.length;
      if (!isIsolatedDigitRun(text, start, end, sep)) {
        continue;
      }

      if (V.isValidAadhaar(raw)) {
        candidates.push({
          type: 'AADHAAR',
          start: start,
          end: end,
          raw: raw,
          meta: {}
        });
      } else {
        rejected.AADHAAR++;
      }
    }
  }

  /**
   * Scan Indian PAN candidates ([A-Z]{5}[0-9]{4}[A-Z], case-insensitive)
   * and validate 4th-char holder type.
   */
  function scanPan(text, candidates, rejected) {
    const V = Scrub.validators;
    const re = /[A-Za-z]{5}[0-9]{4}[A-Za-z]/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const raw = m[0];
      const start = m.index;
      const end = start + raw.length;
      const prev = start > 0 ? text[start - 1] : undefined;
      const next = end < text.length ? text[end] : undefined;

      if (isAlphaNum(prev) || isAlphaNum(next)) {
        continue;
      }

      if (V.isValidPanHolder(raw)) {
        candidates.push({
          type: 'PAN',
          start: start,
          end: end,
          raw: raw,
          meta: {
            normalized: raw.toUpperCase(),
            holderCode: raw[3].toUpperCase()
          }
        });
      } else {
        rejected.PAN++;
      }
    }
  }

  /**
   * Scan IPv4 (strict 0-255 octets) and IPv6 addresses.
   * Excludes version strings like v1.2.3.4 and handles trailing sentence periods.
   */
  function scanIPs(text, candidates, rejected) {
    const V = Scrub.validators;

    // IPv4
    const re4 = /\d{1,3}(?:\.\d{1,3}){3}/g;
    let m;
    while ((m = re4.exec(text)) !== null) {
      const raw = m[0];
      const start = m.index;
      const end = start + raw.length;
      const prev = start > 0 ? text[start - 1] : undefined;
      const next = end < text.length ? text[end] : undefined;

      if (prev !== undefined && (isAlphaNum(prev) || prev === '.')) {
        continue;
      }
      if (isAlphaNum(next)) {
        continue;
      }
      if (next === '.' && end + 1 < text.length && isDigit(text[end + 1])) {
        continue;
      }

      if (V.isValidIPv4(raw)) {
        candidates.push({
          type: 'IP',
          start: start,
          end: end,
          raw: raw,
          meta: { version: 4 }
        });
      } else {
        rejected.IP++;
      }
    }

    // IPv6 linear-time scanner over hex + colon spans
    const re6 = /[0-9a-fA-F:]{3,45}/g;
    while ((m = re6.exec(text)) !== null) {
      let raw = m[0];
      let start = m.index;
      let end = start + raw.length;

      if (!raw.includes(':')) {
        continue;
      }
      // Trim single leading colon from prefixes like "ip:2001:db8::1"
      if (raw[0] === ':' && raw[1] !== ':') {
        raw = raw.slice(1);
        start += 1;
      }
      // Trim single trailing colon from suffixes like "fe80::1:"
      if (raw.length >= 3 && raw[raw.length - 1] === ':' && raw[raw.length - 2] !== ':') {
        raw = raw.slice(0, -1);
        end -= 1;
      }
      if (raw.length < 3 || !raw.includes(':')) {
        continue;
      }

      const prev = start > 0 ? text[start - 1] : undefined;
      const next = end < text.length ? text[end] : undefined;

      if (isAlphaNum(prev) || isAlphaNum(next) || next === ':') {
        continue;
      }
      if (next === '.' && end + 1 < text.length && isDigit(text[end + 1])) {
        continue;
      }

      if (V.isValidIPv6(raw)) {
        candidates.push({
          type: 'IP',
          start: start,
          end: end,
          raw: raw,
          meta: { version: 6 }
        });
      }
    }
  }

  /**
   * Scan Indian mobile numbers (+91 / 0091 / 0 / bare 6-9xxxxxxxxx)
   * and International E.164 numbers (+CC ... with 8-15 digits).
   */
  function scanPhones(text, candidates) {
    const V = Scrub.validators;

    const validatePhoneBounds = function (start, end, isIntl) {
      const prev = start > 0 ? text[start - 1] : undefined;
      const next = end < text.length ? text[end] : undefined;

      if (isAlphaNum(prev) || prev === '+') {
        return false;
      }
      if (!isIntl && prev === '-' && start >= 2 && isDigit(text[start - 2])) {
        return false;
      }
      if (!isIntl && prev === '.' && start >= 2 && isDigit(text[start - 2])) {
        return false;
      }
      if (isAlphaNum(next)) {
        return false;
      }
      if (next === '-' && end + 1 < text.length && isDigit(text[end + 1])) {
        return false;
      }
      if (next === '.' && end + 1 < text.length && isDigit(text[end + 1])) {
        return false;
      }
      return true;
    };

    // 1. Indian mobile patterns (explicit realistic groupings prevent false matches)
    const reIndian =
      /(?:\(\+91\)[ \t-]?|\+91[ \t-]?|0091[ \t-]?|0[ \t-]?)?(?:[6-9]\d{9}|[6-9]\d{4}[ \t-]\d{5}|[6-9]\d{3}[ \t-]\d{3}[ \t-]\d{3}|[6-9]\d{2}[ \t-]\d{3}[ \t-]\d{4}|[6-9]\d[ \t-]\d{4}[ \t-]\d{4}|[6-9]\d{2}[ \t-]\d{4}[ \t-]\d{3}|\([6-9]\d{4}\)[ \t-]?\d{5})/g;
    let m;
    while ((m = reIndian.exec(text)) !== null) {
      const raw = m[0];
      const start = m.index;
      const end = start + raw.length;
      if (!validatePhoneBounds(start, end, raw.includes('+'))) {
        continue;
      }
      const digits = V.digitsOnly(raw);
      if (digits.length < 10 || digits.length > 14) {
        continue;
      }
      candidates.push({
        type: 'PHONE',
        start: start,
        end: end,
        raw: raw,
        meta: { format: 'IN_MOBILE' }
      });
    }

    // 2. International E.164 patterns (+ prefix, 8-15 total digits)
    const reIntl =
      /\+[1-9]\d{7,14}|(?:\(\+[1-9]\d{0,3}\)|\+[1-9]\d{0,3})[ \t-]\d{5,12}|(?:\(\+[1-9]\d{0,3}\)|\+[1-9]\d{0,2})(?:[ \t-](?:\(\d{1,5}\)|\d{1,6})){2,5}/g;
    while ((m = reIntl.exec(text)) !== null) {
      const raw = m[0];
      const start = m.index;
      const end = start + raw.length;
      if (!validatePhoneBounds(start, end, true)) {
        continue;
      }
      const digits = V.digitsOnly(raw);
      if (digits.length < 8 || digits.length > 15) {
        continue;
      }
      candidates.push({
        type: 'PHONE',
        start: start,
        end: end,
        raw: raw,
        meta: { format: 'E164' }
      });
    }
  }

  /**
   * Resolve overlapping spans deterministically:
   * 1. Higher ENTITY_PRIORITY wins
   * 2. Longer span wins on equal priority
   * 3. Earlier start index wins on tie
   * Uses binary search insertion over accepted non-overlapping spans for O(N log N).
   */
  function resolveOverlaps(candidates) {
    if (candidates.length === 0) {
      return [];
    }

    const sorted = candidates.slice().sort(function (a, b) {
      const pDiff = ENTITY_PRIORITY[b.type] - ENTITY_PRIORITY[a.type];
      if (pDiff !== 0) {
        return pDiff;
      }
      const lenDiff = (b.end - b.start) - (a.end - a.start);
      if (lenDiff !== 0) {
        return lenDiff;
      }
      return a.start - b.start;
    });

    const accepted = [];

    for (let i = 0; i < sorted.length; i++) {
      const cand = sorted[i];
      let lo = 0;
      let hi = accepted.length;
      while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        if (accepted[mid].start < cand.start) {
          lo = mid + 1;
        } else {
          hi = mid;
        }
      }

      if (lo > 0 && accepted[lo - 1].end > cand.start) {
        continue;
      }
      if (lo < accepted.length && accepted[lo].start < cand.end) {
        continue;
      }
      accepted.splice(lo, 0, cand);
    }

    return accepted;
  }

  /**
   * Normalize a raw entity so formatting variants share one identity
   * (casing for EMAIL/IP/PAN, separators for numeric types).
   */
  function normalizeValue(type, raw) {
    switch (type) {
      case 'EMAIL':
      case 'IP':
        return raw.toLowerCase();
      case 'PAN':
        return raw.toUpperCase();
      case 'PHONE':
        return raw.replace(/[ \t()-]/g, '');
      case 'CREDIT_CARD':
      case 'AADHAAR':
        return raw.replace(/[ \t-]/g, '');
      default:
        return raw;
    }
  }

  /**
   * Attach 1-based line numbers, IDs, and a stable identity key to sorted findings.
   * The key is value-based (type:normalized#occurrence), never offset-based, so an
   * edit that shifts text can never move an "ignore" onto a different PII value.
   */
  function annotateLineNumbers(text, findings) {
    let line = 1;
    let cursor = 0;
    const seen = new Map();
    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      while (cursor < f.start) {
        if (text.charCodeAt(cursor) === 10) {
          line++;
        }
        cursor++;
      }
      f.line = line;
      f.id = 'f_' + i;
      const valueKey = f.type + ':' + normalizeValue(f.type, f.raw);
      const nth = (seen.get(valueKey) || 0) + 1;
      seen.set(valueKey, nth);
      f.valueKey = valueKey;
      f.key = valueKey + '#' + nth;
    }
    return findings;
  }

  /**
   * Compute line-offset chunks bounded cleanly on newlines for cooperative scanning.
   */
  function splitIntoLineChunks(text, targetChunkSize) {
    const chunks = [];
    let offset = 0;
    const len = text.length;
    while (offset < len) {
      let end = Math.min(offset + targetChunkSize, len);
      if (end < len) {
        const nextNl = text.indexOf('\n', end);
        end = nextNl === -1 ? len : nextNl + 1;
      }
      chunks.push({ offset: offset, text: text.slice(offset, end) });
      offset = end;
    }
    return chunks;
  }

  /**
   * Scan a single text segment for all enabled entity types.
   */
  function scanSegment(segmentText, enabledMap, offset, candidates, rejected) {
    const segCandidates = [];
    if (enabledMap.CREDIT_CARD) {
      scanCreditCards(segmentText, segCandidates, rejected);
    }
    if (enabledMap.AADHAAR) {
      scanAadhaar(segmentText, segCandidates, rejected);
    }
    if (enabledMap.PAN) {
      scanPan(segmentText, segCandidates, rejected);
    }
    if (enabledMap.EMAIL) {
      scanEmails(segmentText, segCandidates);
    }
    if (enabledMap.IP) {
      scanIPs(segmentText, segCandidates, rejected);
    }
    if (enabledMap.PHONE) {
      scanPhones(segmentText, segCandidates);
    }

    if (offset === 0) {
      for (let i = 0; i < segCandidates.length; i++) {
        candidates.push(segCandidates[i]);
      }
    } else {
      for (let i = 0; i < segCandidates.length; i++) {
        const c = segCandidates[i];
        c.start += offset;
        c.end += offset;
        candidates.push(c);
      }
    }
  }

  function normalizeEnabledMap(enabledTypes) {
    const map = {};
    for (let i = 0; i < ENTITY_TYPES.length; i++) {
      const t = ENTITY_TYPES[i];
      map[t] = enabledTypes ? Boolean(enabledTypes[t]) : true;
    }
    return map;
  }

  function buildResult(text, candidates, rejected) {
    const resolved = resolveOverlaps(candidates);
    annotateLineNumbers(text, resolved);
    const counts = createEmptyCounts();
    for (let i = 0; i < resolved.length; i++) {
      counts[resolved[i].type]++;
    }
    return {
      findings: resolved,
      counts: counts,
      rejected: rejected,
      total: resolved.length
    };
  }

  /**
   * Synchronous scan (ideal for small/medium text and unit tests).
   * @param {string} text
   * @param {Object<string, boolean>} [enabledTypes]
   */
  function scan(text, enabledTypes) {
    const source = typeof text === 'string' ? text : '';
    const rejected = createEmptyRejected();
    if (!source) {
      return {
        findings: [],
        counts: createEmptyCounts(),
        rejected: rejected,
        total: 0
      };
    }

    const enabledMap = normalizeEnabledMap(enabledTypes);
    const candidates = [];
    scanSegment(source, enabledMap, 0, candidates, rejected);
    return buildResult(source, candidates, rejected);
  }

  /**
   * Time-sliced async scan for large inputs (~2 MB+) so UI remains responsive
   * without violating strict CSP (script-src 'self' prohibits blob: Workers).
   * @param {string} text
   * @param {Object<string, boolean>} enabledTypes
   * @param {{ chunkSize?: number, onProgress?: Function, isCancelled?: Function }} [options]
   * @returns {Promise<Object>}
   */
  function scanAsync(text, enabledTypes, options) {
    const opts = options || {};
    const source = typeof text === 'string' ? text : '';
    const chunkSize = opts.chunkSize || SYNC_SCAN_LIMIT;

    if (source.length <= chunkSize) {
      if (opts.onProgress) {
        opts.onProgress(1);
      }
      return Promise.resolve(scan(source, enabledTypes));
    }

    const chunks = splitIntoLineChunks(source, chunkSize);
    const enabledMap = normalizeEnabledMap(enabledTypes);
    const candidates = [];
    const rejected = createEmptyRejected();

    return new Promise(function (resolve) {
      let idx = 0;
      function step() {
        if (opts.isCancelled && opts.isCancelled()) {
          resolve(null);
          return;
        }
        const sliceStart = performance.now();
        while (idx < chunks.length) {
          const chunk = chunks[idx];
          scanSegment(chunk.text, enabledMap, chunk.offset, candidates, rejected);
          idx++;
          if (opts.onProgress) {
            opts.onProgress(idx / chunks.length);
          }
          if (idx < chunks.length && performance.now() - sliceStart >= 12) {
            setTimeout(step, 0);
            return;
          }
        }
        resolve(buildResult(source, candidates, rejected));
      }
      setTimeout(step, 0);
    });
  }

  Scrub.detectors = {
    ENTITY_TYPES: ENTITY_TYPES,
    ENTITY_PRIORITY: ENTITY_PRIORITY,
    ENTITY_META: ENTITY_META,
    scan: scan,
    scanAsync: scanAsync,
    resolveOverlaps: resolveOverlaps,
    normalizeValue: normalizeValue,
    isIsolatedDigitRun: isIsolatedDigitRun,
    emptyCounts: createEmptyCounts,
    emptyRejected: createEmptyRejected,
    SYNC_SCAN_LIMIT: SYNC_SCAN_LIMIT
  };
})(typeof window !== 'undefined' ? window : globalThis);
