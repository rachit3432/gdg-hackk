(function (global) {
  'use strict';

  const Scrub = (global.Scrub = global.Scrub || {});

  const VALID_PAN_HOLDERS = new Set(['P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G']);

  // Verhoeff dihedral D5 multiplication table
  const VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
  ];

  // Verhoeff permutation table
  const VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
  ];

  // Verhoeff inverse table
  const VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

  /**
   * Strip whitespace, parentheses, and hyphens from numeric identifiers.
   * @param {string} value
   * @returns {string}
   */
  function stripSeparators(value) {
    return String(value || '').replace(/[ \t()-]/g, '');
  }

  /**
   * Extract only ASCII digits from a string.
   * @param {string} value
   * @returns {string}
   */
  function digitsOnly(value) {
    return String(value || '').replace(/[^0-9]/g, '');
  }

  /**
   * Validate a 13-19 digit card number using the Luhn checksum.
   * Rejects non-digit/separator characters and all-zero or 0-prefixed numbers.
   * @param {string} value
   * @returns {boolean}
   */
  function luhnCheck(value) {
    if (typeof value !== 'string' || !/^[0-9 \t-]+$/.test(value)) {
      return false;
    }
    const digits = value.replace(/[ \t-]/g, '');
    if (digits.length < 13 || digits.length > 19 || digits[0] === '0') {
      return false;
    }
    let sum = 0;
    let alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits.charCodeAt(i) - 48;
      if (alt) {
        d *= 2;
        if (d > 9) {
          d -= 9;
        }
      }
      sum += d;
      alt = !alt;
    }
    return sum % 10 === 0;
  }

  /**
   * Infer card network brand from IIN prefix.
   * Checks RuPay ranges before Discover to resolve shared 60/65 prefixes cleanly.
   * @param {string} value
   * @returns {'Visa'|'Mastercard'|'Amex'|'RuPay'|'Discover'|'Unknown'}
   */
  function inferCardBrand(value) {
    const digits = String(value || '').replace(/[ \t-]/g, '');
    if (!digits) {
      return 'Unknown';
    }
    if (/^3[47]/.test(digits) && digits.length === 15) {
      return 'Amex';
    }
    if (/^(?:606[1-9]|607|608|652[12]|652[89]|6530|508|81|82|353|356)/.test(digits) && digits.length >= 16) {
      return 'RuPay';
    }
    if (/^4/.test(digits) && (digits.length === 13 || digits.length === 16 || digits.length === 19)) {
      return 'Visa';
    }
    if (/^(?:5[1-5]|222[1-9]|22[3-9]\d|2[3-6]\d\d|27[01]\d|2720)/.test(digits) && digits.length === 16) {
      return 'Mastercard';
    }
    if (
      /^(?:6011|64[4-9]|65|622(?:12[6-9]|1[3-9]\d|[2-8]\d\d|9[01]\d|92[0-5]))/.test(digits) &&
      digits.length >= 16 &&
      digits.length <= 19
    ) {
      return 'Discover';
    }
    return 'Unknown';
  }

  /**
   * Run the pure Verhoeff checksum over a digit string (any length >= 1).
   * @param {string} digits
   * @returns {boolean}
   */
  function verhoeffCheck(digits) {
    if (typeof digits !== 'string' || !/^\d+$/.test(digits)) {
      return false;
    }
    let c = 0;
    for (let i = 0; i < digits.length; i++) {
      const digit = digits.charCodeAt(digits.length - 1 - i) - 48;
      c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
    }
    return c === 0;
  }

  /**
   * Generate a Verhoeff check digit for a base digit string.
   * @param {string} baseDigits
   * @returns {string}
   */
  function verhoeffGenerateCheckDigit(baseDigits) {
    if (typeof baseDigits !== 'string' || !/^\d+$/.test(baseDigits)) {
      throw new Error('verhoeffGenerateCheckDigit requires an ASCII digit string');
    }
    let c = 0;
    for (let i = 0; i < baseDigits.length; i++) {
      const digit = baseDigits.charCodeAt(baseDigits.length - 1 - i) - 48;
      c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][digit]];
    }
    return String(VERHOEFF_INV[c]);
  }

  /**
   * Validate an Aadhaar candidate: 12 digits, starts 2-9, valid Verhoeff checksum.
   * @param {string} value
   * @returns {boolean}
   */
  function isValidAadhaar(value) {
    if (typeof value !== 'string' || !/^[0-9 \t-]+$/.test(value)) {
      return false;
    }
    const digits = value.replace(/[ \t-]/g, '');
    if (digits.length !== 12 || digits[0] < '2' || digits[0] > '9') {
      return false;
    }
    return verhoeffCheck(digits);
  }

  /**
   * Validate IPv4 strictly: 4 octets in 0..255 with no multi-digit leading zeros.
   * @param {string} value
   * @returns {boolean}
   */
  function isValidIPv4(value) {
    if (typeof value !== 'string') {
      return false;
    }
    const parts = value.split('.');
    if (parts.length !== 4) {
      return false;
    }
    for (let i = 0; i < 4; i++) {
      const part = parts[i];
      if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) {
        return false;
      }
      if (Number(part) > 255) {
        return false;
      }
    }
    return true;
  }

  /**
   * Validate IPv6 (full 8-hextet, :: compressed, or IPv4-embedded suffix).
   * Requires at least one hex group so bare "::" in prose/code is not flagged.
   * @param {string} value
   * @returns {boolean}
   */
  function isValidIPv6(value) {
    if (typeof value !== 'string' || value.length < 3 || value.includes(':::')) {
      return false;
    }
    const doubleColonParts = value.split('::');
    if (doubleColonParts.length > 2) {
      return false;
    }

    const isHexGroup = function (g) {
      return /^[0-9a-fA-F]{1,4}$/.test(g);
    };

    if (doubleColonParts.length === 1) {
      const groups = value.split(':');
      if (groups.length === 8) {
        return groups.every(isHexGroup);
      }
      if (groups.length === 7 && groups[6].includes('.')) {
        return groups.slice(0, 6).every(isHexGroup) && isValidIPv4(groups[6]);
      }
      return false;
    }

    const leftRaw = doubleColonParts[0];
    const rightRaw = doubleColonParts[1];
    const left = leftRaw ? leftRaw.split(':') : [];
    const right = rightRaw ? rightRaw.split(':') : [];

    if (left.length + right.length === 0) {
      return false;
    }

    let ipv4Tail = false;
    if (right.length > 0 && right[right.length - 1].includes('.')) {
      const last = right[right.length - 1];
      if (!isValidIPv4(last)) {
        return false;
      }
      ipv4Tail = true;
    }

    const rightHex = ipv4Tail ? right.slice(0, -1) : right;
    if (!left.every(isHexGroup) || !rightHex.every(isHexGroup)) {
      return false;
    }

    const groupWeight = left.length + rightHex.length + (ipv4Tail ? 2 : 0);
    return groupWeight <= 7;
  }

  /**
   * Validate Indian PAN format and 4th-character holder type.
   * @param {string} value
   * @returns {boolean}
   */
  function isValidPanHolder(value) {
    if (typeof value !== 'string' || value.length !== 10) {
      return false;
    }
    const upper = value.toUpperCase();
    if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(upper)) {
      return false;
    }
    return VALID_PAN_HOLDERS.has(upper[3]);
  }

  /**
   * Validate basic RFC-ish email structure and length bounds.
   * @param {string} value
   * @returns {boolean}
   */
  function isValidEmail(value) {
    if (typeof value !== 'string' || value.length > 254) {
      return false;
    }
    const atIndex = value.indexOf('@');
    if (atIndex <= 0 || atIndex !== value.lastIndexOf('@')) {
      return false;
    }
    const local = value.slice(0, atIndex);
    const domain = value.slice(atIndex + 1);
    if (local.length > 64 || domain.length < 3 || domain.length > 253) {
      return false;
    }
    if (local.includes('..') || domain.includes('..')) {
      return false;
    }
    return /\.[A-Za-z]{2,24}$/.test(domain);
  }

  Scrub.validators = {
    VALID_PAN_HOLDERS: VALID_PAN_HOLDERS,
    stripSeparators: stripSeparators,
    digitsOnly: digitsOnly,
    luhnCheck: luhnCheck,
    inferCardBrand: inferCardBrand,
    verhoeffCheck: verhoeffCheck,
    verhoeffGenerateCheckDigit: verhoeffGenerateCheckDigit,
    isValidAadhaar: isValidAadhaar,
    isValidIPv4: isValidIPv4,
    isValidIPv6: isValidIPv6,
    isValidPanHolder: isValidPanHolder,
    isValidEmail: isValidEmail
  };
})(typeof window !== 'undefined' ? window : globalThis);
