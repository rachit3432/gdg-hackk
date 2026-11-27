(function (global) {
  'use strict';

  const Scrub = (global.Scrub = global.Scrub || {});

  const MODES = {
    FULL: 'full',
    PARTIAL: 'partial',
    PSEUDONYM: 'pseudonym'
  };

  const PSEUDONYM_PREFIX = {
    EMAIL: 'USER',
    PHONE: 'PHONE',
    IP: 'IP',
    PAN: 'PAN',
    AADHAAR: 'AADHAAR',
    CREDIT_CARD: 'CARD'
  };

  const RISK_WEIGHTS = {
    CREDIT_CARD: 25,
    AADHAAR: 24,
    PAN: 20,
    PHONE: 12,
    EMAIL: 10,
    IP: 9
  };

  /**
   * Mask all ASCII digits except the last `keepLast` digits while preserving
   * original spaces, hyphens, and parentheses in place.
   */
  function maskDigitsKeepLast(str, keepLast) {
    let totalDigits = 0;
    for (let i = 0; i < str.length; i++) {
      if (str[i] >= '0' && str[i] <= '9') {
        totalDigits++;
      }
    }
    const maskCutoff = Math.max(0, totalDigits - keepLast);
    let seen = 0;
    let out = '';
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      if (ch >= '0' && ch <= '9') {
        out += seen < maskCutoff ? 'X' : ch;
        seen++;
      } else {
        out += ch;
      }
    }
    return out;
  }

  /**
   * Partial mask for EMAIL: j***@d***.com
   */
  function maskPartialEmail(raw) {
    const at = raw.indexOf('@');
    if (at <= 0) {
      return '[REDACTED:EMAIL]';
    }
    const local = raw.slice(0, at);
    const domain = raw.slice(at + 1);
    const dotParts = domain.split('.');
    if (dotParts.length < 2) {
      return local[0] + '***@' + domain[0] + '***';
    }
    const firstDomChar = dotParts[0][0] || 'x';
    const tld = dotParts[dotParts.length - 1];
    return local[0] + '***@' + firstDomChar + '***.' + tld;
  }

  /**
   * Partial mask for PHONE: +91-XXXXX-X3210 or XXXXXX3210
   */
  function maskPartialPhone(raw) {
    const intlMatch = raw.match(/^(\(\+[1-9]\d{0,3}\)|\+[1-9]\d{0,3})([ \t-].*)$/);
    if (intlMatch) {
      return intlMatch[1] + maskDigitsKeepLast(intlMatch[2], 4);
    }
    if (/^\+91[6-9]\d{9}$/.test(raw)) {
      return '+91' + maskDigitsKeepLast(raw.slice(3), 4);
    }
    if (raw[0] === '+') {
      return '+' + maskDigitsKeepLast(raw.slice(1), 4);
    }
    return maskDigitsKeepLast(raw, 4);
  }

  /**
   * Partial mask for IPv4 (192.168.XXX.XXX) and IPv6 (keep first 2 groups).
   */
  function maskPartialIP(raw) {
    if (!raw.includes(':')) {
      const parts = raw.split('.');
      if (parts.length === 4) {
        return parts[0] + '.' + parts[1] + '.XXX.XXX';
      }
      return 'XXX.XXX.XXX.XXX';
    }

    const dc = raw.split('::');
    if (dc.length === 1) {
      const groups = raw.split(':');
      return groups
        .map(function (g, idx) {
          return idx < 2 ? g : 'XXXX';
        })
        .join(':');
    }

    const left = dc[0] ? dc[0].split(':') : [];
    const right = dc[1] ? dc[1].split(':') : [];
    let kept = 0;
    const maskedLeft = left.map(function (g) {
      if (kept < 2) {
        kept++;
        return g;
      }
      return 'XXXX';
    });
    const maskedRight = right.map(function () {
      return 'XXXX';
    });
    return maskedLeft.join(':') + '::' + maskedRight.join(':');
  }

  /**
   * Partial mask preserving minimal verifiable context and original separators.
   */
  function maskPartial(type, raw) {
    switch (type) {
      case 'CREDIT_CARD':
      case 'AADHAAR':
        return maskDigitsKeepLast(raw, 4);
      case 'PAN':
        return 'XXXXXX' + raw.slice(6).toUpperCase();
      case 'PHONE':
        return maskPartialPhone(raw);
      case 'EMAIL':
        return maskPartialEmail(raw);
      case 'IP':
        return maskPartialIP(raw);
      default:
        return '[REDACTED]';
    }
  }

  /**
   * Full mask block, optionally typed.
   */
  function maskFull(type, typedLabels) {
    return typedLabels ? '[REDACTED:' + type + ']' : '[REDACTED]';
  }

  /**
   * Normalize entity values before keying in the pseudonym map.
   */
  function normalizeForPseudonym(type, raw) {
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
   * Redact text across active (non-ignored) findings in one of 3 modes,
   * preserving exact line endings (CRLF/LF) and all non-PII text.
   * Also builds the consistent pseudonym mapping table across active findings.
   *
   * @param {string} text
   * @param {Array<Object>} findings
   * @param {'full'|'partial'|'pseudonym'} mode
   * @param {{ typedLabels?: boolean, ignoredKeys?: Set<string> }} [options]
   */
  function redact(text, findings, mode, options) {
    const source = typeof text === 'string' ? text : '';
    const opts = options || {};
    const typedLabels = Boolean(opts.typedLabels);
    const ignoredKeys = opts.ignoredKeys || new Set();

    const counters = {
      EMAIL: 0,
      PHONE: 0,
      IP: 0,
      PAN: 0,
      AADHAAR: 0,
      CREDIT_CARD: 0
    };

    // Pre-pass: number placeholders by first appearance across ALL findings, so
    // ignoring or un-ignoring one value never renumbers the others.
    const entryByValue = new Map();
    const allEntries = [];
    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      const normalized = normalizeForPseudonym(f.type, f.raw);
      const vk = f.type + ':' + normalized;
      if (!entryByValue.has(vk)) {
        counters[f.type]++;
        const entry = {
          placeholder: PSEUDONYM_PREFIX[f.type] + '_' + String(counters[f.type]).padStart(2, '0'),
          type: f.type,
          normalized: normalized,
          maskedPreview: maskPartial(f.type, f.raw),
          rawExample: f.raw,
          brand: f.meta && f.meta.brand ? f.meta.brand : null,
          occurrences: 0
        };
        entryByValue.set(vk, entry);
        allEntries.push(entry);
      }
    }

    const mappingList = [];
    const replacements = [];
    const outParts = [];
    let cursor = 0;
    let outLen = 0;

    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      const ignored = ignoredKeys.has(f.key);

      if (f.start > cursor) {
        const plain = source.slice(cursor, f.start);
        outParts.push(plain);
        outLen += plain.length;
      }

      const maskedPreview = maskPartial(f.type, f.raw);

      if (ignored) {
        const outStart = outLen;
        outParts.push(f.raw);
        outLen += f.raw.length;
        replacements.push({
          id: f.id,
          key: f.key,
          type: f.type,
          line: f.line,
          start: f.start,
          end: f.end,
          outStart: outStart,
          outEnd: outLen,
          raw: f.raw,
          replacement: f.raw,
          maskedPreview: maskedPreview,
          pseudonym: null,
          brand: f.meta && f.meta.brand ? f.meta.brand : null,
          ignored: true
        });
        cursor = f.end;
        continue;
      }

      // Deterministic pseudonym (numbered in the pre-pass) for mapping store & pseudonym mode
      const mapEntry = entryByValue.get(f.type + ':' + normalizeForPseudonym(f.type, f.raw));
      mapEntry.occurrences++;

      let repText;
      if (mode === MODES.PARTIAL) {
        repText = maskedPreview;
      } else if (mode === MODES.PSEUDONYM) {
        repText = mapEntry.placeholder;
      } else {
        repText = maskFull(f.type, typedLabels);
      }

      const outStart = outLen;
      outParts.push(repText);
      outLen += repText.length;

      replacements.push({
        id: f.id,
        key: f.key,
        type: f.type,
        line: f.line,
        start: f.start,
        end: f.end,
        outStart: outStart,
        outEnd: outLen,
        raw: f.raw,
        replacement: repText,
        maskedPreview: maskedPreview,
        pseudonym: mapEntry.placeholder,
        brand: f.meta && f.meta.brand ? f.meta.brand : null,
        ignored: false
      });

      cursor = f.end;
    }

    if (cursor < source.length) {
      outParts.push(source.slice(cursor));
    }

    // Only values that were actually replaced belong in the reversible mapping.
    for (let i = 0; i < allEntries.length; i++) {
      if (allEntries[i].occurrences > 0) {
        mappingList.push(allEntries[i]);
      }
    }

    return {
      output: outParts.join(''),
      replacements: replacements,
      mapping: mappingList
    };
  }

  /**
   * Compute pre-sanitization input risk score and post-sanitization exposure score.
   * Output exposure drops to 0 when all detected findings are active (not ignored).
   */
  function computeRiskStats(findings, ignoredKeys, rejected, hasInput) {
    const activeCounts = {
      EMAIL: 0,
      PHONE: 0,
      IP: 0,
      PAN: 0,
      AADHAAR: 0,
      CREDIT_CARD: 0
    };
    const totalCounts = {
      EMAIL: 0,
      PHONE: 0,
      IP: 0,
      PAN: 0,
      AADHAAR: 0,
      CREDIT_CARD: 0
    };

    let rawWeight = 0;
    let residualWeight = 0;
    let activeTotal = 0;
    let ignoredTotal = 0;

    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      const w = RISK_WEIGHTS[f.type] || 10;
      totalCounts[f.type]++;
      rawWeight += w;

      if (ignoredKeys && ignoredKeys.has(f.key)) {
        ignoredTotal++;
        residualWeight += w;
      } else {
        activeTotal++;
        activeCounts[f.type]++;
      }
    }

    const inputRisk = hasInput ? Math.min(100, rawWeight) : 0;
    // Output exposure drops to 0 when no active PII remains unredacted
    const outputExposure = hasInput ? Math.min(100, residualWeight) : 0;

    return {
      inputRisk: inputRisk,
      outputExposure: outputExposure,
      activeTotal: activeTotal,
      ignoredTotal: ignoredTotal,
      totalFound: findings.length,
      activeCounts: activeCounts,
      totalCounts: totalCounts,
      rejected: rejected
    };
  }

  /**
   * Build privacy-safe JSON audit report containing counts, types, and metadata ONLY.
   * Never includes any raw PII or masked PII values.
   */
  function buildAuditReport(params) {
    const stats = params.stats;
    return {
      tool: 'NEON//SCRUB',
      schemaVersion: '1.0',
      generatedAt: new Date().toISOString(),
      networkActivity: 'NONE (LOCAL CLIENT-ONLY)',
      mode: params.mode,
      typedLabels: Boolean(params.typedLabels),
      inputStats: {
        characters: params.inputLength,
        lines: params.lineCount
      },
      outputStats: {
        characters: params.outputLength
      },
      entitiesRedacted: stats.activeTotal,
      entitiesIgnored: stats.ignoredTotal,
      countsByType: Object.assign({}, stats.activeCounts),
      rejectedCandidates: Object.assign({}, stats.rejected),
      riskScoreBefore: stats.inputRisk,
      exposureScoreAfter: stats.outputExposure
    };
  }

  /**
   * Build reversible JSON mapping export for Pseudonym mode.
   */
  function buildMappingExport(mappingList) {
    const forward = {};
    const reverse = {};
    for (let i = 0; i < mappingList.length; i++) {
      const entry = mappingList[i];
      forward[entry.type + ':' + entry.normalized] = entry.placeholder;
      reverse[entry.placeholder] = {
        type: entry.type,
        value: entry.rawExample,
        normalized: entry.normalized,
        occurrences: entry.occurrences
      };
    }
    return {
      warning: 'SENSITIVE: This mapping file reverses PII pseudonymization. Store securely and do not distribute.',
      generatedAt: new Date().toISOString(),
      placeholders: reverse,
      normalizedToPlaceholder: forward
    };
  }

  Scrub.redactors = {
    MODES: MODES,
    PSEUDONYM_PREFIX: PSEUDONYM_PREFIX,
    maskFull: maskFull,
    maskPartial: maskPartial,
    normalizeForPseudonym: normalizeForPseudonym,
    redact: redact,
    computeRiskStats: computeRiskStats,
    buildAuditReport: buildAuditReport,
    buildMappingExport: buildMappingExport
  };
})(typeof window !== 'undefined' ? window : globalThis);
