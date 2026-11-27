(function (global) {
  'use strict';

  const Scrub = (global.Scrub = global.Scrub || {});

  const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB client safety cap
  const SCAN_DEBOUNCE_MS = 150;

  function createInitialEnabled() {
    return {
      EMAIL: true,
      PHONE: true,
      IP: true,
      PAN: true,
      AADHAAR: true,
      CREDIT_CARD: true
    };
  }

  function init() {
    const D = Scrub.detectors;
    const R = Scrub.redactors;
    const UI = Scrub.ui;
    const dom = UI.getElements();

    // Pure in-memory state (never persisted to localStorage, sessionStorage, cookies, or IndexedDB)
    const state = {
      text: '',
      rawUploadedText: null,
      editedSinceUpload: false,
      lineEnding: '\n',
      sourceFilename: null,
      mode: R.MODES.FULL,
      typedLabels: false,
      revealRaw: false,
      enabledTypes: createInitialEnabled(),
      ignoredKeys: new Set(),
      findings: [],
      counts: {
        EMAIL: 0,
        PHONE: 0,
        IP: 0,
        PAN: 0,
        AADHAAR: 0,
        CREDIT_CARD: 0
      },
      rejected: {
        CREDIT_CARD: 0,
        AADHAAR: 0,
        PAN: 0,
        IP: 0
      },
      outputText: '',
      replacements: [],
      mapping: [],
      stats: null,
      prevExposure: null,
      activeFid: null,
      origById: new Map(),
      sanById: new Map(),
      rowById: new Map(),
      origMarks: [],
      scanToken: 0,
      debounceTimer: null,
      scrollLock: false,
      hoverRaf: null
    };

    UI.runBootSequence(dom);
    UI.updateModeIndicator(dom, state.mode);

    /**
     * Highlight matching entity across Original backdrop, Sanitized pane, and Findings row.
     */
    function setActiveHighlight(fid) {
      if (state.activeFid === fid) {
        return;
      }
      if (state.activeFid) {
        const prevOrig = state.origById.get(state.activeFid);
        const prevSan = state.sanById.get(state.activeFid);
        const prevRow = state.rowById.get(state.activeFid);
        if (prevOrig) prevOrig.classList.remove('is-active');
        if (prevSan) prevSan.classList.remove('is-active');
        if (prevRow) prevRow.classList.remove('is-active');
      }
      state.activeFid = fid || null;
      if (state.activeFid) {
        const nextOrig = state.origById.get(state.activeFid);
        const nextSan = state.sanById.get(state.activeFid);
        const nextRow = state.rowById.get(state.activeFid);
        if (nextOrig) nextOrig.classList.add('is-active');
        if (nextSan) nextSan.classList.add('is-active');
        if (nextRow) nextRow.classList.add('is-active');
      }
    }

    /**
     * Prune ignored keys that are no longer present after text/filter changes.
     */
    function pruneIgnoredKeys(findings) {
      const validKeys = new Set();
      for (let i = 0; i < findings.length; i++) {
        validKeys.add(findings[i].key);
      }
      state.ignoredKeys.forEach(function (k) {
        if (!validKeys.has(k)) {
          state.ignoredKeys.delete(k);
        }
      });
    }

    /**
     * Recompute redaction, diff, stats, findings table, and mapping table from current findings.
     */
    function applyRedactionAndRender() {
      const hasInput = state.text.length > 0;
      const redacted = R.redact(state.text, state.findings, state.mode, {
        typedLabels: state.typedLabels,
        ignoredKeys: state.ignoredKeys
      });

      state.outputText = redacted.output;
      state.replacements = redacted.replacements;
      state.mapping = redacted.mapping;

      const stats = R.computeRiskStats(
        state.findings,
        state.ignoredKeys,
        state.rejected,
        hasInput
      );
      state.stats = stats;

      const refs = UI.renderDiff(
        dom,
        state.text,
        state.outputText,
        state.findings,
        state.replacements,
        state.ignoredKeys
      );
      state.origById = refs.origById;
      state.sanById = refs.sanById;
      state.origMarks = refs.origMarks;
      state.activeFid = null;

      UI.renderFilterPills(dom, state.enabledTypes, stats.activeCounts, handleToggleEntityType);
      UI.renderStats(dom, stats, hasInput, state.prevExposure);
      state.prevExposure = stats.outputExposure;

      state.rowById = UI.renderFindingsTable(
        dom,
        state.replacements,
        handleToggleIgnore,
        setActiveHighlight,
        handleSelectFindingRow
      );

      UI.renderMappingTable(dom, state.mapping, state.revealRaw, state.mode);

      const exportDisabled = !hasInput;
      dom.btnCopy.disabled = exportDisabled;
      dom.btnDownloadOutput.disabled = exportDisabled;
      dom.btnDownloadReport.disabled = exportDisabled;

      UI.syncEditorTransform(dom);
      UI.syncSanitizedLinesTransform(dom);

      if (hasInput) {
        UI.announce(
          dom,
          'Detected ' +
            stats.activeTotal +
            ' PII entities. Exposure score: ' +
            stats.outputExposure +
            ' percent.'
        );
      }
    }

    /**
     * Run detection pipeline (sync for small inputs, cooperative chunked async for large inputs).
     */
    function runDetectionNow() {
      const currentToken = ++state.scanToken;
      if (!state.text) {
        state.findings = [];
        state.counts = {
          EMAIL: 0,
          PHONE: 0,
          IP: 0,
          PAN: 0,
          AADHAAR: 0,
          CREDIT_CARD: 0
        };
        state.rejected = { CREDIT_CARD: 0, AADHAAR: 0, PAN: 0, IP: 0 };
        state.ignoredKeys.clear();
        UI.setScanning(dom, false);
        applyRedactionAndRender();
        return;
      }

      if (state.text.length <= 160000) {
        const result = D.scan(state.text, state.enabledTypes);
        state.findings = result.findings;
        state.counts = result.counts;
        state.rejected = result.rejected;
        pruneIgnoredKeys(state.findings);
        UI.setScanning(dom, false);
        applyRedactionAndRender();
        return;
      }

      UI.setScanning(dom, true, 'SCANNING PAYLOAD...');
      const startTime = performance.now();

      D.scanAsync(state.text, state.enabledTypes, {
        isCancelled: function () {
          return currentToken !== state.scanToken;
        },
        onProgress: function (ratio) {
          const pct = Math.min(100, Math.round(ratio * 100));
          UI.setScanning(dom, true, 'SCANNING... ' + pct + '%');
        }
      }).then(function (result) {
        if (!result || currentToken !== state.scanToken) {
          return;
        }
        state.findings = result.findings;
        state.counts = result.counts;
        state.rejected = result.rejected;
        pruneIgnoredKeys(state.findings);

        const elapsed = performance.now() - startTime;
        const hideDelay = elapsed < 120 ? 180 : 40;
        setTimeout(function () {
          if (currentToken === state.scanToken) {
            UI.setScanning(dom, false);
          }
        }, hideDelay);

        applyRedactionAndRender();
      });
    }

    function scheduleDetection() {
      if (state.debounceTimer !== null) {
        clearTimeout(state.debounceTimer);
      }
      UI.setScanning(dom, true, 'ANALYZING...');
      state.debounceTimer = setTimeout(function () {
        state.debounceTimer = null;
        runDetectionNow();
      }, SCAN_DEBOUNCE_MS);
    }

    function handleToggleEntityType(type) {
      state.enabledTypes[type] = !state.enabledTypes[type];
      runDetectionNow();
    }

    function handleToggleIgnore(key) {
      if (state.ignoredKeys.has(key)) {
        state.ignoredKeys.delete(key);
      } else {
        state.ignoredKeys.add(key);
      }
      applyRedactionAndRender();
      // Preserve keyboard focus on the toggled row's IGNORE checkbox
      const matchingRep = state.replacements.find(function (r) {
        return r.key === key;
      });
      if (matchingRep) {
        const row = state.rowById.get(matchingRep.id);
        const chk = row && row.querySelector('.ignore-chk');
        if (chk) {
          chk.focus();
        }
      }
    }

    function handleSelectFindingRow(rep) {
      UI.scrollBothToLine(dom, rep.line);
      setActiveHighlight(rep.id);
    }

    function setMode(mode) {
      if (state.mode === mode) {
        return;
      }
      state.mode = mode;
      UI.updateModeIndicator(dom, mode);
      applyRedactionAndRender();
    }

    /**
     * Compute sanitized output string preserving original CRLF line endings when applicable.
     */
    function getExportOutputText() {
      const raw = state.rawUploadedText;
      if (raw !== null && !state.editedSinceUpload) {
        const nCRLF = (raw.match(/\r\n/g) || []).length;
        const nLF = (raw.match(/\n/g) || []).length;
        const nCR = (raw.match(/\r/g) || []).length;
        // Uniform endings: the on-screen output is exact; just restore CRLF if needed.
        if (nCR === 0) {
          return state.outputText;
        }
        if (nCRLF === nLF && nCRLF === nCR) {
          return state.outputText.replace(/\n/g, '\r\n');
        }
        // Mixed or lone-CR endings: redact the original bytes directly. Ignore keys are
        // value-based (type:normalized#occurrence), so they carry over exactly and the
        // download matches the preview.
        const rawScan = D.scan(raw, state.enabledTypes);
        return R.redact(raw, rawScan.findings, state.mode, {
          typedLabels: state.typedLabels,
          ignoredKeys: state.ignoredKeys
        }).output;
      }

      if (state.lineEnding === '\r\n') {
        return state.outputText.replace(/\r?\n/g, '\r\n');
      }
      return state.outputText;
    }

    function buildSanitizedFilename() {
      const name = state.sourceFilename;
      if (!name) {
        return 'sanitized.txt';
      }
      const dotIdx = name.lastIndexOf('.');
      if (dotIdx > 0 && dotIdx < name.length - 1) {
        return name.slice(0, dotIdx) + '.sanitized' + name.slice(dotIdx);
      }
      return name + '.sanitized.txt';
    }

    function triggerBlobDownload(content, mimeType, filename) {
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () {
        URL.revokeObjectURL(url);
      }, 1500);
    }

    function handleLoadedFile(file) {
      UI.hideAlert(dom);
      if (!file) {
        return;
      }
      const lower = (file.name || '').toLowerCase();
      const validExt = lower.endsWith('.txt') || lower.endsWith('.csv');
      if (!validExt) {
        UI.showAlert(
          dom,
          'Unsupported file "' + file.name + '". Only .txt and .csv files are accepted.'
        );
        return;
      }
      if (file.size > MAX_FILE_BYTES) {
        const mb = (file.size / (1024 * 1024)).toFixed(2);
        UI.showAlert(
          dom,
          'File "' + file.name + '" is ' + mb + ' MB (max 5.00 MB allowed in client memory).'
        );
        return;
      }

      const reader = new FileReader();
      reader.onload = function () {
        const raw = typeof reader.result === 'string' ? reader.result : '';
        if (raw.includes('\u0000')) {
          UI.showAlert(dom, 'File "' + file.name + '" appears to contain binary null bytes.');
          return;
        }
        state.rawUploadedText = raw;
        state.editedSinceUpload = false;
        state.lineEnding = raw.includes('\r\n') ? '\r\n' : '\n';
        state.sourceFilename = file.name;
        const normalizedForEditor = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

        state.text = normalizedForEditor;
        state.ignoredKeys.clear();
        state.prevExposure = null;
        dom.originalInput.value = normalizedForEditor;
        dom.fileMetaTag.textContent =
          file.name + ' (' + (state.lineEnding === '\r\n' ? 'CRLF' : 'LF') + ')';
        runDetectionNow();
      };
      reader.onerror = function () {
        UI.showAlert(dom, 'Failed to read "' + file.name + '" from local disk.');
      };
      reader.readAsText(file);
    }

    function wipeAll() {
      if (state.debounceTimer !== null) {
        clearTimeout(state.debounceTimer);
        state.debounceTimer = null;
      }
      state.scanToken++;
      state.text = '';
      state.rawUploadedText = null;
      state.editedSinceUpload = false;
      state.lineEnding = '\n';
      state.sourceFilename = null;
      state.ignoredKeys.clear();
      state.findings = [];
      state.counts = { EMAIL: 0, PHONE: 0, IP: 0, PAN: 0, AADHAAR: 0, CREDIT_CARD: 0 };
      state.rejected = { CREDIT_CARD: 0, AADHAAR: 0, PAN: 0, IP: 0 };
      state.outputText = '';
      state.replacements = [];
      state.mapping = [];
      state.prevExposure = null;
      state.activeFid = null;
      state.revealRaw = false;

      dom.originalInput.value = '';
      dom.fileInput.value = '';
      dom.chkRevealRaw.checked = false;
      dom.fileMetaTag.textContent = 'NO FILE // PASTE MODE';
      UI.hideAlert(dom);
      UI.setScanning(dom, false);
      applyRedactionAndRender();
      UI.announce(dom, 'All text, mappings, and state wiped from memory.');
    }

    // === EVENT WIRING ===

    dom.btnSample.addEventListener('click', function () {
      UI.hideAlert(dom);
      state.rawUploadedText = null;
      state.editedSinceUpload = false;
      state.lineEnding = '\n';
      state.sourceFilename = null;
      state.ignoredKeys.clear();
      state.prevExposure = null;
      state.text = Scrub.sample.TEXT;
      dom.originalInput.value = state.text;
      dom.fileMetaTag.textContent = 'SAMPLE PAYLOAD // ' + state.text.split('\n').length + ' LINES';
      runDetectionNow();
    });

    dom.btnWipe.addEventListener('click', wipeAll);
    dom.btnDismissAlert.addEventListener('click', function () {
      UI.hideAlert(dom);
    });

    dom.fileInput.addEventListener('change', function () {
      const file = dom.fileInput.files && dom.fileInput.files[0];
      handleLoadedFile(file);
      dom.fileInput.value = '';
    });

    dom.fileLabel.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' || ev.key === ' ') {
        ev.preventDefault();
        dom.fileInput.click();
      }
    });

    // Drag and drop on workspace
    let dragCounter = 0;
    dom.dropZone.addEventListener('dragenter', function (ev) {
      ev.preventDefault();
      dragCounter++;
      dom.dropZone.classList.add('is-dragover');
    });
    dom.dropZone.addEventListener('dragover', function (ev) {
      ev.preventDefault();
    });
    dom.dropZone.addEventListener('dragleave', function () {
      dragCounter = Math.max(0, dragCounter - 1);
      if (dragCounter === 0) {
        dom.dropZone.classList.remove('is-dragover');
      }
    });
    dom.dropZone.addEventListener('drop', function (ev) {
      ev.preventDefault();
      dragCounter = 0;
      dom.dropZone.classList.remove('is-dragover');
      const file = ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0];
      if (file) {
        handleLoadedFile(file);
      }
    });

    // Live textarea edits (debounced ~150 ms)
    dom.originalInput.addEventListener('input', function () {
      state.text = dom.originalInput.value;
      if (state.rawUploadedText !== null) {
        state.editedSinceUpload = true;
      } else {
        dom.fileMetaTag.textContent = state.text ? 'PASTED INPUT' : 'NO FILE // PASTE MODE';
      }
      UI.syncEditorTransform(dom);
      scheduleDetection();
    });

    // Synchronized scrolling between Original and Sanitized panes
    dom.originalInput.addEventListener('scroll', function () {
      UI.syncEditorTransform(dom);
      if (state.scrollLock) {
        return;
      }
      state.scrollLock = true;
      dom.sanitizedScroll.scrollTop = dom.originalInput.scrollTop;
      dom.sanitizedScroll.scrollLeft = dom.originalInput.scrollLeft;
      UI.syncSanitizedLinesTransform(dom);
      requestAnimationFrame(function () {
        state.scrollLock = false;
      });
    });

    dom.sanitizedScroll.addEventListener('scroll', function () {
      UI.syncSanitizedLinesTransform(dom);
      if (state.scrollLock) {
        return;
      }
      state.scrollLock = true;
      dom.originalInput.scrollTop = dom.sanitizedScroll.scrollTop;
      dom.originalInput.scrollLeft = dom.sanitizedScroll.scrollLeft;
      UI.syncEditorTransform(dom);
      requestAnimationFrame(function () {
        state.scrollLock = false;
      });
    });

    // Cross-highlighting: click & hover inside Original textarea
    dom.originalInput.addEventListener('click', function () {
      const pos = dom.originalInput.selectionStart;
      for (let i = 0; i < state.findings.length; i++) {
        const f = state.findings[i];
        if (pos >= f.start && pos <= f.end) {
          setActiveHighlight(f.id);
          return;
        }
        if (f.start > pos) {
          break;
        }
      }
      setActiveHighlight(null);
    });

    dom.originalInput.addEventListener('mousemove', function (ev) {
      if (state.origMarks.length === 0 || state.hoverRaf !== null) {
        return;
      }
      const cx = ev.clientX;
      const cy = ev.clientY;
      state.hoverRaf = requestAnimationFrame(function () {
        state.hoverRaf = null;
        let hitFid = null;
        for (let i = 0; i < state.origMarks.length; i++) {
          const mark = state.origMarks[i];
          const box = mark.getBoundingClientRect();
          if (cy < box.top || cy > box.bottom) {
            continue;
          }
          if (cx >= box.left && cx <= box.right) {
            hitFid = mark.getAttribute('data-fid');
            break;
          }
        }
        setActiveHighlight(hitFid);
      });
    });

    dom.originalInput.addEventListener('mouseleave', function () {
      setActiveHighlight(null);
    });

    // Cross-highlighting: hover & click inside Sanitized pane
    dom.sanitizedOutput.addEventListener('mouseover', function (ev) {
      const mark = ev.target.closest('mark[data-fid]');
      setActiveHighlight(mark ? mark.getAttribute('data-fid') : null);
    });

    dom.sanitizedOutput.addEventListener('mouseleave', function () {
      setActiveHighlight(null);
    });

    dom.sanitizedOutput.addEventListener('click', function (ev) {
      const mark = ev.target.closest('mark[data-fid]');
      if (!mark) {
        setActiveHighlight(null);
        return;
      }
      const fid = mark.getAttribute('data-fid');
      setActiveHighlight(fid);
      const origMark = state.origById.get(fid);
      if (origMark) {
        const f = state.findings.find(function (item) {
          return item.id === fid;
        });
        if (f) {
          UI.scrollBothToLine(dom, f.line);
        }
      }
    });

    // Mode segmented control + keyboard arrows
    for (let i = 0; i < dom.modeButtons.length; i++) {
      (function (btn, index) {
        btn.addEventListener('click', function () {
          setMode(btn.getAttribute('data-mode'));
        });
        btn.addEventListener('keydown', function (ev) {
          if (ev.key === 'ArrowRight' || ev.key === 'ArrowDown') {
            ev.preventDefault();
            const nextBtn = dom.modeButtons[(index + 1) % dom.modeButtons.length];
            nextBtn.focus();
            setMode(nextBtn.getAttribute('data-mode'));
          } else if (ev.key === 'ArrowLeft' || ev.key === 'ArrowUp') {
            ev.preventDefault();
            const prevBtn =
              dom.modeButtons[(index - 1 + dom.modeButtons.length) % dom.modeButtons.length];
            prevBtn.focus();
            setMode(prevBtn.getAttribute('data-mode'));
          }
        });
      })(dom.modeButtons[i], i);
    }

    dom.chkTypedLabels.addEventListener('change', function () {
      state.typedLabels = dom.chkTypedLabels.checked;
      applyRedactionAndRender();
    });

    dom.chkRevealRaw.addEventListener('change', function () {
      state.revealRaw = dom.chkRevealRaw.checked;
      UI.renderMappingTable(dom, state.mapping, state.revealRaw, state.mode);
    });

    // Dock tabs + arrow key navigation
    function activateTab(tabName) {
      const panelIdMap = {
        stats: 'panelStats',
        findings: 'panelFindings',
        mapping: 'panelMapping'
      };
      for (let i = 0; i < dom.dockTabs.length; i++) {
        const t = dom.dockTabs[i];
        const active = t.getAttribute('data-tab') === tabName;
        t.classList.toggle('is-active', active);
        t.setAttribute('aria-selected', active ? 'true' : 'false');
      }
      for (let i = 0; i < dom.dockPanels.length; i++) {
        const p = dom.dockPanels[i];
        const show = p.id === panelIdMap[tabName];
        p.classList.toggle('is-active', show);
        p.hidden = !show;
      }
    }

    for (let i = 0; i < dom.dockTabs.length; i++) {
      (function (tab, index) {
        tab.addEventListener('click', function () {
          activateTab(tab.getAttribute('data-tab'));
        });
        tab.addEventListener('keydown', function (ev) {
          if (ev.key === 'ArrowRight') {
            ev.preventDefault();
            const next = dom.dockTabs[(index + 1) % dom.dockTabs.length];
            next.focus();
            activateTab(next.getAttribute('data-tab'));
          } else if (ev.key === 'ArrowLeft') {
            ev.preventDefault();
            const prev = dom.dockTabs[(index - 1 + dom.dockTabs.length) % dom.dockTabs.length];
            prev.focus();
            activateTab(prev.getAttribute('data-tab'));
          }
        });
      })(dom.dockTabs[i], i);
    }

    // Export buttons
    dom.btnCopy.addEventListener('click', function () {
      const payload = getExportOutputText();
      if (!payload) {
        return;
      }
      const onCopied = function () {
        const origLabel = dom.btnCopy.textContent;
        dom.btnCopy.textContent = 'COPIED!';
        UI.announce(dom, 'Sanitized output copied to clipboard.');
        setTimeout(function () {
          dom.btnCopy.textContent = origLabel;
        }, 1200);
      };

      if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        navigator.clipboard.writeText(payload).then(onCopied, function () {
          fallbackCopy(payload, onCopied);
        });
      } else {
        fallbackCopy(payload, onCopied);
      }
    });

    function fallbackCopy(text, cb) {
      const tmp = document.createElement('textarea');
      tmp.value = text;
      tmp.setAttribute('readonly', '');
      tmp.style.position = 'fixed';
      tmp.style.left = '-9999px';
      document.body.appendChild(tmp);
      tmp.select();
      try {
        document.execCommand('copy');
        cb();
      } catch (err) {
        UI.showAlert(dom, 'Clipboard copy was blocked by browser permissions.');
      }
      document.body.removeChild(tmp);
    }

    dom.btnDownloadOutput.addEventListener('click', function () {
      const payload = getExportOutputText();
      if (!payload) {
        return;
      }
      const filename = buildSanitizedFilename();
      const mime = filename.toLowerCase().endsWith('.csv')
        ? 'text/csv;charset=utf-8'
        : 'text/plain;charset=utf-8';
      triggerBlobDownload(payload, mime, filename);
      UI.announce(dom, 'Downloaded sanitized file ' + filename);
    });

    dom.btnDownloadReport.addEventListener('click', function () {
      if (!state.stats) {
        return;
      }
      const report = R.buildAuditReport({
        mode: state.mode,
        typedLabels: state.typedLabels,
        inputLength: state.text.length,
        outputLength: state.outputText.length,
        lineCount: state.text ? state.text.split('\n').length : 0,
        stats: state.stats
      });
      const base = state.sourceFilename
        ? state.sourceFilename.replace(/\.[^.]+$/, '')
        : 'neon-scrub';
      triggerBlobDownload(
        JSON.stringify(report, null, 2),
        'application/json;charset=utf-8',
        base + '.audit-report.json'
      );
      UI.announce(dom, 'Downloaded privacy-safe audit report JSON.');
    });

    dom.btnDownloadMapping.addEventListener('click', function () {
      if (state.mapping.length === 0) {
        return;
      }
      const mappingObj = R.buildMappingExport(state.mapping);
      const base = state.sourceFilename
        ? state.sourceFilename.replace(/\.[^.]+$/, '')
        : 'neon-scrub';
      triggerBlobDownload(
        JSON.stringify(mappingObj, null, 2),
        'application/json;charset=utf-8',
        base + '.mapping-SENSITIVE.json'
      );
      UI.announce(dom, 'Downloaded reversible mapping JSON. Store securely.');
    });

    // Initial render
    applyRedactionAndRender();
  }

  document.addEventListener('DOMContentLoaded', init);
})(typeof window !== 'undefined' ? window : globalThis);
