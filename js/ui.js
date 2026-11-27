(function (global) {
  'use strict';

  const Scrub = (global.Scrub = global.Scrub || {});

  const MAX_RENDERED_HIGHLIGHTS = 4000;
  const TABLE_PAGE_SIZE = 300;
  const LINE_HEIGHT_PX = 21;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  /**
   * Cache DOM references once at startup.
   */
  function getElements() {
    return {
      bootLine: document.getElementById('bootLine'),
      btnWipe: document.getElementById('btnWipe'),
      btnSample: document.getElementById('btnSample'),
      fileInput: document.getElementById('fileInput'),
      fileLabel: document.querySelector('.file-label'),
      fileMetaTag: document.getElementById('fileMetaTag'),

      modeControl: document.getElementById('modeControl'),
      modeIndicator: document.getElementById('modeIndicator'),
      modeButtons: Array.prototype.slice.call(document.querySelectorAll('.seg-btn')),
      typedLabelWrap: document.getElementById('typedLabelWrap'),
      chkTypedLabels: document.getElementById('chkTypedLabels'),

      btnCopy: document.getElementById('btnCopy'),
      btnDownloadOutput: document.getElementById('btnDownloadOutput'),
      btnDownloadReport: document.getElementById('btnDownloadReport'),

      scanBarWrap: document.getElementById('scanBarWrap'),
      scanBarLabel: document.getElementById('scanBarLabel'),
      alertBanner: document.getElementById('alertBanner'),
      alertText: document.getElementById('alertText'),
      btnDismissAlert: document.getElementById('btnDismissAlert'),

      filterPills: document.getElementById('filterPills'),
      dropZone: document.getElementById('dropZone'),

      originalInput: document.getElementById('originalInput'),
      originalBackdrop: document.getElementById('originalBackdrop'),
      originalLines: document.getElementById('originalLines'),
      originalMeta: document.getElementById('originalMeta'),

      sanitizedScroll: document.getElementById('sanitizedScroll'),
      sanitizedOutput: document.getElementById('sanitizedOutput'),
      sanitizedLines: document.getElementById('sanitizedLines'),
      sanitizedMeta: document.getElementById('sanitizedMeta'),
      sanitizedStamp: document.getElementById('sanitizedStamp'),

      dockTabs: Array.prototype.slice.call(document.querySelectorAll('.dock-tab')),
      dockPanels: Array.prototype.slice.call(document.querySelectorAll('.dock-panel')),
      tabFindingsCount: document.getElementById('tabFindingsCount'),
      tabMappingCount: document.getElementById('tabMappingCount'),
      summaryTotal: document.getElementById('summaryTotal'),
      summaryRejected: document.getElementById('summaryRejected'),
      summaryExposure: document.getElementById('summaryExposure'),

      inputRiskVal: document.getElementById('inputRiskVal'),
      inputRiskBar: document.getElementById('inputRiskBar'),
      outputExposureVal: document.getElementById('outputExposureVal'),
      outputExposureBar: document.getElementById('outputExposureBar'),
      exposureNote: document.getElementById('exposureNote'),
      distList: document.getElementById('distList'),
      rejectedList: document.getElementById('rejectedList'),

      findingsTbody: document.getElementById('findingsTbody'),
      findingsEmpty: document.getElementById('findingsEmpty'),

      chkRevealRaw: document.getElementById('chkRevealRaw'),
      mappingModeNote: document.getElementById('mappingModeNote'),
      btnDownloadMapping: document.getElementById('btnDownloadMapping'),
      mappingTbody: document.getElementById('mappingTbody'),
      mappingEmpty: document.getElementById('mappingEmpty'),

      liveAnnouncer: document.getElementById('liveAnnouncer')
    };
  }

  /** Gutter text "1\n2\n...n" for a given line count. */
  function buildLineNumbers(count) {
    const nums = new Array(Math.max(1, count));
    for (let i = 0; i < nums.length; i++) {
      nums[i] = String(i + 1);
    }
    return nums.join('\n');
  }

  // Gutters are only rebuilt when the line count actually changes.
  const gutterCache = { orig: -1, san: -1 };

  function countLines(text) {
    if (!text) {
      return 0;
    }
    let count = 1;
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10) {
        count++;
      }
    }
    return count;
  }

  /**
   * Create entity filter toggle buttons with color chips and live counts.
   */
  function renderFilterPills(dom, enabledTypes, counts, onToggle) {
    const D = Scrub.detectors;
    // Update existing pills in place so keyboard focus survives a toggle.
    const existing = dom.filterPills.querySelectorAll('.entity-pill');
    if (existing.length === D.ENTITY_TYPES.length) {
      for (let i = 0; i < existing.length; i++) {
        const btn = existing[i];
        const type = btn.getAttribute('data-entity');
        const isOn = Boolean(enabledTypes[type]);
        btn.classList.toggle('is-off', !isOn);
        btn.setAttribute('aria-pressed', isOn ? 'true' : 'false');
        btn.querySelector('.entity-pill-count').textContent = String((counts && counts[type]) || 0);
      }
      return;
    }
    const frag = document.createDocumentFragment();
    for (let i = 0; i < D.ENTITY_TYPES.length; i++) {
      const type = D.ENTITY_TYPES[i];
      const meta = D.ENTITY_META[type];
      const isOn = Boolean(enabledTypes[type]);
      const btn = el('button', 'entity-pill' + (isOn ? '' : ' is-off'));
      btn.type = 'button';
      btn.setAttribute('data-entity', type);
      btn.setAttribute('aria-pressed', isOn ? 'true' : 'false');
      btn.title = 'Toggle ' + meta.label + ' detection';

      const dot = el('span', 'entity-pill-dot');
      dot.setAttribute('aria-hidden', 'true');
      const label = el('span', 'entity-pill-label', meta.label);
      const count = el('span', 'entity-pill-count', String((counts && counts[type]) || 0));

      btn.appendChild(dot);
      btn.appendChild(label);
      btn.appendChild(count);

      btn.addEventListener('click', function () {
        onToggle(type);
      });

      frag.appendChild(btn);
    }
    dom.filterPills.replaceChildren(frag);
  }

  /**
   * Render Original highlight backdrop and Sanitized output pane using pure DOM nodes.
   * Returns lookup maps for fast cross-highlighting.
   */
  function renderDiff(dom, text, outputText, findings, replacements, ignoredKeys) {
    const origById = new Map();
    const sanById = new Map();

    // 1. Original mirrored backdrop
    const origFrag = document.createDocumentFragment();
    if (text) {
      let cursor = 0;
      const limit = Math.min(findings.length, MAX_RENDERED_HIGHLIGHTS);
      for (let i = 0; i < limit; i++) {
        const f = findings[i];
        if (f.start > cursor) {
          origFrag.appendChild(document.createTextNode(text.slice(cursor, f.start)));
        }
        const isIgnored = ignoredKeys.has(f.key);
        const markClass =
          'hl hl-' + f.type + (isIgnored ? ' hl-ignored' : '');
        const mark = el('mark', markClass, f.raw);
        mark.setAttribute('data-fid', f.id);
        origFrag.appendChild(mark);
        origById.set(f.id, mark);
        cursor = f.end;
      }
      if (cursor < text.length) {
        origFrag.appendChild(document.createTextNode(text.slice(cursor)));
      }
      if (text.endsWith('\n')) {
        origFrag.appendChild(document.createTextNode(' '));
      }
    }
    dom.originalBackdrop.replaceChildren(origFrag);

    // 2. Sanitized read-only diff pane
    const sanFrag = document.createDocumentFragment();
    if (outputText) {
      let cursor = 0;
      const limit = Math.min(replacements.length, MAX_RENDERED_HIGHLIGHTS);
      for (let i = 0; i < limit; i++) {
        const rep = replacements[i];
        if (rep.outStart > cursor) {
          sanFrag.appendChild(document.createTextNode(outputText.slice(cursor, rep.outStart)));
        }
        const markClass =
          'hl hl-sanitized hl-' + rep.type + (rep.ignored ? ' hl-ignored' : '');
        const mark = el('mark', markClass, rep.replacement);
        mark.setAttribute('data-fid', rep.id);
        mark.title = rep.ignored
          ? 'Ignored (un-redacted) — click to locate in original'
          : rep.type + ' — click to locate in original';
        sanFrag.appendChild(mark);
        sanById.set(rep.id, mark);
        cursor = rep.outEnd;
      }
      if (cursor < outputText.length) {
        sanFrag.appendChild(document.createTextNode(outputText.slice(cursor)));
      }
      if (outputText.endsWith('\n')) {
        sanFrag.appendChild(document.createTextNode(' '));
      }
    } else {
      const placeholder = el(
        'span',
        'pane-placeholder',
        ''
      );
      sanFrag.appendChild(placeholder);
    }
    dom.sanitizedOutput.replaceChildren(sanFrag);

    // 3. Line numbers (identical vertical line alignment because white-space: pre)
    const lineCount = countLines(text);
    const sanCount = countLines(outputText);
    if (lineCount !== gutterCache.orig) {
      gutterCache.orig = lineCount;
      dom.originalLines.textContent = buildLineNumbers(lineCount);
    }
    if (sanCount !== gutterCache.san) {
      gutterCache.san = sanCount;
      dom.sanitizedLines.textContent = buildLineNumbers(sanCount);
    }

    dom.originalMeta.textContent = lineCount + ' lines // ' + text.length + ' chars';

    return {
      origById: origById,
      sanById: sanById
    };
  }

  /**
   * Render Exposure Meters, Entity Distribution bars, and Validator Rejection Log.
   */
  function renderStats(dom, stats, hasInput, prevExposure) {
    const D = Scrub.detectors;
    const totalRejected =
      stats.rejected.CREDIT_CARD +
      stats.rejected.AADHAAR +
      stats.rejected.PAN +
      stats.rejected.IP;

    dom.summaryTotal.textContent = String(stats.activeTotal);
    dom.summaryRejected.textContent = String(totalRejected);
    dom.summaryExposure.textContent = hasInput ? stats.outputExposure + '%' : '0%';
    dom.sanitizedMeta.textContent =
      stats.activeTotal +
      ' scrubbed' +
      (stats.ignoredTotal > 0 ? ' // ' + stats.ignoredTotal + ' ignored' : '');

    // Exposure meters
    dom.inputRiskVal.textContent = stats.inputRisk + ' / 100';
    dom.inputRiskBar.style.width = stats.inputRisk + '%';

    if (!hasInput) {
      dom.outputExposureVal.textContent = '0 / 100 // IDLE';
      dom.outputExposureBar.style.width = '0%';
      dom.sanitizedStamp.textContent = 'IDLE';
      dom.sanitizedStamp.className = 'stamp-badge';
    } else if (stats.outputExposure === 0) {
      dom.outputExposureVal.textContent = '0 / 100 // SAFE';
      dom.outputExposureBar.style.width = '0%';
      dom.sanitizedStamp.textContent = 'SANITIZED // 0% EXPOSURE';
      dom.sanitizedStamp.className = 'stamp-badge is-sanitized';
      if (prevExposure !== 0 || stats.activeTotal > 0) {
        dom.sanitizedStamp.classList.add('is-flash');
      }
    } else {
      dom.outputExposureVal.textContent = stats.outputExposure + ' / 100 // IGNORED PII';
      dom.outputExposureBar.style.width = Math.max(4, stats.outputExposure) + '%';
      dom.sanitizedStamp.textContent = 'PARTIAL (' + stats.ignoredTotal + ' IGNORED)';
      dom.sanitizedStamp.className = 'stamp-badge is-partial-exposure';
    }

    // Distribution bars
    const distFrag = document.createDocumentFragment();
    const maxCount = Math.max(1, stats.totalFound);
    for (let i = 0; i < D.ENTITY_TYPES.length; i++) {
      const type = D.ENTITY_TYPES[i];
      const meta = D.ENTITY_META[type];
      const count = stats.activeCounts[type] || 0;
      const pct = Math.round((count / maxCount) * 100);

      const row = el('div', 'dist-row');
      const label = el('span', 'dist-label', meta.label);
      label.style.color = 'var(' + meta.colorVar + ')';

      const barBg = el('div', 'dist-bar-bg');
      const barFill = el('div', 'dist-bar-fill');
      barFill.style.width = (count > 0 ? Math.max(4, pct) : 0) + '%';
      barFill.style.background = 'var(' + meta.colorVar + ')';
      barBg.appendChild(barFill);

      const countNode = el('span', 'dist-count', String(count));
      row.appendChild(label);
      row.appendChild(barBg);
      row.appendChild(countNode);
      distFrag.appendChild(row);
    }
    dom.distList.replaceChildren(distFrag);

    // Rejected-candidate validation proof
    const rejItems = [
      {
        label: 'Card-like numbers rejected by Luhn',
        count: stats.rejected.CREDIT_CARD
      },
      {
        label: 'Aadhaar-like numbers rejected by Verhoeff',
        count: stats.rejected.AADHAAR
      },
      {
        label: 'IPv4-like tokens rejected (out of 0-255)',
        count: stats.rejected.IP
      },
      {
        label: 'PAN-like IDs rejected (invalid holder type)',
        count: stats.rejected.PAN
      }
    ];

    const rejFrag = document.createDocumentFragment();
    for (let i = 0; i < rejItems.length; i++) {
      const item = rejItems[i];
      const li = el('li', 'rejected-item');
      li.appendChild(el('span', 'rejected-text', item.label));
      li.appendChild(el('span', 'rejected-count', String(item.count)));
      rejFrag.appendChild(li);
    }
    dom.rejectedList.replaceChildren(rejFrag);
  }

  /**
   * Render Findings Table with per-row IGNORE checkboxes.
   */
  function renderFindingsTable(dom, replacements, onToggleIgnore, onHoverRow, onSelectRow) {
    dom.tabFindingsCount.textContent = String(replacements.length);
    const rowById = new Map();

    if (replacements.length === 0) {
      dom.findingsTbody.replaceChildren();
      dom.findingsEmpty.hidden = false;
      return rowById;
    }

    dom.findingsEmpty.hidden = true;
    const frag = document.createDocumentFragment();
    const renderLimit = Math.min(replacements.length, TABLE_PAGE_SIZE);

    for (let i = 0; i < renderLimit; i++) {
      const rep = replacements[i];
      const tr = el('tr', rep.ignored ? 'is-ignored-row' : '');
      tr.setAttribute('data-fid', rep.id);

      tr.appendChild(el('td', 'mono-code', String(rep.line)));

      const tdType = el('td');
      const badge = el('span', 'type-badge', rep.type);
      badge.setAttribute('data-entity', rep.type);
      tdType.appendChild(badge);
      tr.appendChild(tdType);

      tr.appendChild(el('td', 'mono-code', rep.maskedPreview));
      tr.appendChild(el('td', '', rep.brand ? rep.brand : '—'));
      tr.appendChild(el('td', 'mono-code', rep.ignored ? '[UNREDACTED]' : rep.replacement));

      const tdIgnore = el('td');
      const chk = el('input', 'ignore-chk');
      chk.type = 'checkbox';
      chk.checked = Boolean(rep.ignored);
      chk.setAttribute('aria-label', 'Ignore ' + rep.type + ' on line ' + rep.line);
      chk.addEventListener('click', function (ev) {
        ev.stopPropagation();
      });
      chk.addEventListener('change', function () {
        onToggleIgnore(rep.key);
      });
      tdIgnore.appendChild(chk);
      tr.appendChild(tdIgnore);

      tr.addEventListener('mouseenter', function () {
        onHoverRow(rep.id);
      });
      tr.addEventListener('mouseleave', function () {
        onHoverRow(null);
      });
      tr.addEventListener('click', function () {
        onSelectRow(rep);
      });
      // Rows are keyboard-operable: Enter/Space locates the entity in both panes.
      tr.tabIndex = 0;
      tr.setAttribute('aria-label', rep.type + ' on line ' + rep.line + ', output ' + (rep.ignored ? 'unredacted' : rep.replacement));
      tr.addEventListener('keydown', function (ev) {
        if (ev.target === tr && (ev.key === 'Enter' || ev.key === ' ')) {
          ev.preventDefault();
          onSelectRow(rep);
        }
      });

      rowById.set(rep.id, tr);
      frag.appendChild(tr);
    }

    if (replacements.length > renderLimit) {
      const noticeRow = el('tr');
      const td = el(
        'td',
        '',
        'Showing first ' + renderLimit + ' of ' + replacements.length + ' findings for table responsiveness.'
      );
      td.colSpan = 6;
      noticeRow.appendChild(td);
      frag.appendChild(noticeRow);
    }

    dom.findingsTbody.replaceChildren(frag);
    return rowById;
  }

  /**
   * Render Pseudonym Mapping table (shows masked preview by default, raw only on reveal toggle).
   */
  function renderMappingTable(dom, mappingList, revealRaw, mode) {
    dom.tabMappingCount.textContent = String(mappingList.length);
    dom.btnDownloadMapping.disabled = mappingList.length === 0;

    dom.mappingModeNote.textContent =
      mode === 'pseudonym'
        ? 'Active in PSEUDONYM mode — consistent placeholders applied.'
        : 'Previewing consistent pseudonyms (switch to PSEUDONYM mode to apply to output).';

    if (mappingList.length === 0) {
      dom.mappingTbody.replaceChildren();
      dom.mappingEmpty.hidden = false;
      return;
    }

    dom.mappingEmpty.hidden = true;
    const frag = document.createDocumentFragment();
    const limit = Math.min(mappingList.length, TABLE_PAGE_SIZE);

    for (let i = 0; i < limit; i++) {
      const entry = mappingList[i];
      const tr = el('tr');

      tr.appendChild(el('td', 'mono-code', entry.placeholder));

      const tdType = el('td');
      const badge = el('span', 'type-badge', entry.type);
      badge.setAttribute('data-entity', entry.type);
      tdType.appendChild(badge);
      tr.appendChild(tdType);

      tr.appendChild(el('td', 'mono-code', entry.maskedPreview));
      tr.appendChild(
        el('td', 'mono-code', revealRaw ? entry.rawExample : '[HIDDEN — TOGGLE REVEAL]')
      );
      tr.appendChild(el('td', 'mono-code', String(entry.occurrences)));

      frag.appendChild(tr);
    }

    if (mappingList.length > limit) {
      const noticeRow = el('tr');
      const td = el(
        'td',
        '',
        'Showing first ' + limit + ' of ' + mappingList.length + ' unique mappings (all exported in JSON).'
      );
      td.colSpan = 5;
      noticeRow.appendChild(td);
      frag.appendChild(noticeRow);
    }

    dom.mappingTbody.replaceChildren(frag);
  }

  /**
   * Synchronize backdrop and line numbers via GPU-friendly translate3d.
   */
  function syncEditorTransform(dom) {
    const top = dom.originalInput.scrollTop;
    const left = dom.originalInput.scrollLeft;
    dom.originalBackdrop.style.transform = 'translate3d(' + (-left) + 'px, ' + (-top) + 'px, 0)';
    dom.originalLines.style.transform = 'translate3d(0, ' + (-top) + 'px, 0)';
  }

  function syncSanitizedLinesTransform(dom) {
    const top = dom.sanitizedScroll.scrollTop;
    dom.sanitizedLines.style.transform = 'translate3d(0, ' + (-top) + 'px, 0)';
  }

  function scrollBothToLine(dom, lineNumber) {
    const lh = parseFloat(global.getComputedStyle(dom.originalInput).lineHeight) || LINE_HEIGHT_PX;
    const targetTop = Math.max(0, (lineNumber - 3) * lh);
    dom.originalInput.scrollTop = targetTop;
    dom.sanitizedScroll.scrollTop = targetTop;
    syncEditorTransform(dom);
    syncSanitizedLinesTransform(dom);
  }

  function updateModeIndicator(dom, mode) {
    const idxMap = { full: 0, partial: 1, pseudonym: 2 };
    const idx = idxMap[mode] || 0;
    dom.modeIndicator.style.transform = 'translateX(' + idx * 100 + '%)';

    for (let i = 0; i < dom.modeButtons.length; i++) {
      const btn = dom.modeButtons[i];
      const active = btn.getAttribute('data-mode') === mode;
      btn.classList.toggle('is-active', active);
      btn.setAttribute('aria-checked', active ? 'true' : 'false');
      btn.tabIndex = active ? 0 : -1; // roving tabindex: one Tab stop for the radio group
    }

    const isFull = mode === 'full';
    dom.chkTypedLabels.disabled = !isFull;
    dom.typedLabelWrap.classList.toggle('is-disabled', !isFull);
  }

  function showAlert(dom, message) {
    dom.alertText.textContent = message;
    dom.alertBanner.hidden = false;
  }

  function hideAlert(dom) {
    dom.alertBanner.hidden = true;
    dom.alertText.textContent = '';
  }

  function setScanning(dom, active, label) {
    dom.scanBarWrap.classList.toggle('is-scanning', Boolean(active));
    if (label) {
      dom.scanBarLabel.textContent = label;
    }
  }

  function announce(dom, msg) {
    if (dom.liveAnnouncer.textContent !== msg) {
      dom.liveAnnouncer.textContent = msg;
    }
  }

  function runBootSequence(dom) {
    const prefersReduced =
      typeof global.matchMedia === 'function' &&
      global.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReduced) {
      dom.bootLine.textContent = '> network: DISABLED // engine: READY';
      return;
    }
    dom.bootLine.textContent = '> initializing sanitizer...';
    setTimeout(function () {
      dom.bootLine.textContent = '> network: DISABLED // CSP: STRICT';
    }, 260);
    setTimeout(function () {
      dom.bootLine.textContent = '> ready — client-side vault armed';
    }, 560);
  }

  Scrub.ui = {
    getElements: getElements,
    renderFilterPills: renderFilterPills,
    renderDiff: renderDiff,
    renderStats: renderStats,
    renderFindingsTable: renderFindingsTable,
    renderMappingTable: renderMappingTable,
    syncEditorTransform: syncEditorTransform,
    syncSanitizedLinesTransform: syncSanitizedLinesTransform,
    scrollBothToLine: scrollBothToLine,
    updateModeIndicator: updateModeIndicator,
    showAlert: showAlert,
    hideAlert: hideAlert,
    setScanning: setScanning,
    announce: announce,
    runBootSequence: runBootSequence
  };
})(typeof window !== 'undefined' ? window : globalThis);
