/* AEGIS // PROTOCOL — landing page interactions.
   Pure DOM (no innerHTML), no network, pauses work when the tab is hidden. */
(function (global) {
  'use strict';

  const Scrub = global.Scrub || {};
  const doc = global.document;
  const reduceMotion =
    typeof global.matchMedia === 'function' &&
    global.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function $(id) {
    return doc.getElementById(id);
  }

  function el(tag, className, text) {
    const n = doc.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function pad2(n) {
    return n < 10 ? '0' + n : String(n);
  }

  function clockString(d) {
    return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  }

  function fmtInt(n) {
    return n.toLocaleString('en-US');
  }

  function pick(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }

  /* Visible-only interval: skips ticks while the tab is hidden. */
  function every(ms, fn) {
    return global.setInterval(function () {
      if (!doc.hidden) fn();
    }, ms);
  }

  /* ---------- Roving tablist helper (arrow keys, Home/End) ---------- */
  function wireTablist(tabs, onSelect) {
    tabs.forEach(function (tab, i) {
      tab.addEventListener('click', function () {
        select(i, false);
      });
      tab.addEventListener('keydown', function (ev) {
        let next = null;
        if (ev.key === 'ArrowRight' || ev.key === 'ArrowDown') next = (i + 1) % tabs.length;
        else if (ev.key === 'ArrowLeft' || ev.key === 'ArrowUp') next = (i - 1 + tabs.length) % tabs.length;
        else if (ev.key === 'Home') next = 0;
        else if (ev.key === 'End') next = tabs.length - 1;
        if (next !== null) {
          ev.preventDefault();
          select(next, true);
        }
      });
    });
    function select(i, focus) {
      tabs.forEach(function (t, j) {
        const on = i === j;
        t.classList.toggle('is-active', on);
        t.setAttribute('aria-selected', on ? 'true' : 'false');
        t.tabIndex = on ? 0 : -1;
      });
      if (focus) tabs[i].focus();
      onSelect(i);
    }
  }

  /* ---------- Nav ---------- */
  function initNav() {
    const toggle = $('navToggle');
    const links = $('navLinks');
    if (!toggle || !links) return;
    function setOpen(open) {
      links.classList.toggle('is-open', open);
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      toggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    }
    toggle.addEventListener('click', function () {
      setOpen(!links.classList.contains('is-open'));
    });
    links.addEventListener('click', function (ev) {
      if (ev.target.closest('a')) setOpen(false);
    });
    doc.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') setOpen(false);
    });
  }

  /* ---------- Console: live traffic ---------- */
  // Documentation-reserved ranges (RFC 5737) so no real host is ever named.
  const NETS = ['203.0.113.', '198.51.100.', '192.0.2.'];
  const EVENTS = [
    { v: 'ALLOW', w: 5, msgs: ['mesh handshake, identity attested', 'mTLS verified, device posture 98', 'service token valid, scope=read'] },
    { v: 'ROTATE', w: 2, msgs: ['session keys rotated, ML-KEM-768', 'tunnel rekeyed, epoch +1'] },
    { v: 'SCRUB', w: 2, msgs: ['egress payload: 2 emails, 1 PAN masked', 'log line: card ****1111 redacted', 'ticket body: Aadhaar pseudonymized'] },
    { v: 'BLOCK', w: 1, msgs: ['DNS beacon to known C2 domain', 'SQL injection signature on /api/v2/auth', 'credential stuffing, 41 attempts/min'] }
  ];
  const WEIGHTED = [];
  EVENTS.forEach(function (e) {
    for (let i = 0; i < e.w; i++) WEIGHTED.push(e);
  });

  let blocked = 14737;

  function makeLogLine(date) {
    const e = pick(WEIGHTED);
    const li = el('li');
    li.appendChild(el('span', 't', clockString(date)));
    const vClass = e.v === 'BLOCK' ? 'v-block' : e.v === 'ROTATE' || e.v === 'SCRUB' ? 'v-rotate' : 'v-allow';
    li.appendChild(el('span', 'v ' + vClass, e.v));
    li.appendChild(el('span', 'ip', pick(NETS) + (1 + Math.floor(Math.random() * 253))));
    li.appendChild(el('span', 'msg', pick(e.msgs)));
    if (e.v === 'BLOCK') {
      blocked++;
      const b = $('consoleBlocked');
      if (b) b.textContent = fmtInt(blocked);
    }
    return li;
  }

  function initTraffic() {
    const feed = $('logFeed');
    if (!feed) return;
    const MAX = 13;
    const now = Date.now();
    for (let i = MAX; i > 0; i--) {
      feed.appendChild(makeLogLine(new Date(now - i * 1900)));
    }
    if (reduceMotion) return;
    every(1600, function () {
      feed.appendChild(makeLogLine(new Date()));
      while (feed.children.length > MAX) feed.removeChild(feed.firstChild);
    });
  }

  /* ---------- Console: packet inspector (runs the real engine) ---------- */
  const PACKET =
    '{\n' +
    '  "customer": "rahul.verma@acme-corp.example",\n' +
    '  "phone": "+91 98765 43210",\n' +
    '  "pan": "ABCPE1234F",\n' +
    '  "card": "4111 1111 1111 1111",\n' +
    '  "order_ref": "4111 1111 1111 1112",\n' +
    '  "client_ip": "203.0.113.42"\n' +
    '}';

  function renderMarked(pre, text, spans, cls) {
    const frag = doc.createDocumentFragment();
    let cursor = 0;
    spans.forEach(function (s) {
      if (s.start > cursor) frag.appendChild(doc.createTextNode(text.slice(cursor, s.start)));
      frag.appendChild(el('mark', cls, text.slice(s.start, s.end)));
      cursor = s.end;
    });
    if (cursor < text.length) frag.appendChild(doc.createTextNode(text.slice(cursor)));
    pre.replaceChildren(frag);
  }

  function initPacket() {
    const rawPre = $('packetRaw');
    const cleanPre = $('packetClean');
    if (!rawPre || !cleanPre || !Scrub.detectors || !Scrub.redactors) return;
    const t0 = performance.now();
    const scan = Scrub.detectors.scan(PACKET);
    const red = Scrub.redactors.redact(PACKET, scan.findings, 'partial');
    const ms = performance.now() - t0;

    renderMarked(rawPre, PACKET, scan.findings, '');
    renderMarked(
      cleanPre,
      red.output,
      red.replacements.map(function (r) {
        return { start: r.outStart, end: r.outEnd };
      }),
      'clean'
    );
    const rej = scan.rejected;
    const rejected = rej.CREDIT_CARD + rej.AADHAAR + rej.PAN + rej.IP;
    $('packetCount').textContent = scan.total + ' MASKED · ' + rejected + ' LOOK-ALIKE LEFT INTACT';
    $('packetMs').textContent = ms < 1 ? ms.toFixed(2) + ' ms' : ms.toFixed(1) + ' ms';
  }

  /* ---------- Console: neural shield radar ---------- */
  function initShield() {
    const g = $('radarNodes');
    const legend = $('shieldLegend');
    if (!g || !legend) return;
    const NS = 'http://www.w3.org/2000/svg';
    const nodes = [];
    for (let i = 0; i < 14; i++) {
      const a = Math.random() * Math.PI * 2;
      const r = 22 + Math.random() * 82;
      nodes.push({ x: 120 + Math.cos(a) * r, y: 120 + Math.sin(a) * r, threat: i < 3 });
    }
    function draw() {
      const frag = doc.createDocumentFragment();
      let threats = 0;
      nodes.forEach(function (n) {
        const c = doc.createElementNS(NS, 'circle');
        c.setAttribute('cx', n.x.toFixed(1));
        c.setAttribute('cy', n.y.toFixed(1));
        c.setAttribute('r', n.threat ? '3.2' : '2.2');
        c.setAttribute('class', 'radar-node' + (n.threat ? ' is-threat' : ''));
        frag.appendChild(c);
        if (n.threat) {
          threats++;
          const ring = doc.createElementNS(NS, 'circle');
          ring.setAttribute('cx', n.x.toFixed(1));
          ring.setAttribute('cy', n.y.toFixed(1));
          ring.setAttribute('r', '8');
          ring.setAttribute('class', 'radar-node-ring');
          frag.appendChild(ring);
        }
      });
      g.replaceChildren(frag);

      const rows = [
        ['Nodes tracked', String(nodes.length)],
        ['Quarantined', String(threats)],
        ['Baseline drift', (0.6 + Math.random() * 0.8).toFixed(2) + ' σ'],
        ['Model', 'shield-v4 · int8']
      ];
      const lf = doc.createDocumentFragment();
      rows.forEach(function (r) {
        const li = el('li');
        li.appendChild(doc.createTextNode(r[0] + ' '));
        li.appendChild(el('b', '', r[1]));
        lf.appendChild(li);
      });
      legend.replaceChildren(lf);
    }
    draw();
    if (reduceMotion) return;
    every(3200, function () {
      // drift nodes slightly and occasionally flip one threat
      nodes.forEach(function (n) {
        n.x = Math.max(16, Math.min(224, n.x + (Math.random() - 0.5) * 6));
        n.y = Math.max(16, Math.min(224, n.y + (Math.random() - 0.5) * 6));
      });
      const i = Math.floor(Math.random() * nodes.length);
      nodes[i].threat = !nodes[i].threat && nodes.filter(function (n) { return n.threat; }).length < 4;
      draw();
    });
  }

  function initConsole() {
    const tabs = Array.prototype.slice.call(doc.querySelectorAll('.console-tab'));
    const panels = ['cpTraffic', 'cpPacket', 'cpShield'].map($);
    wireTablist(tabs, function (i) {
      panels.forEach(function (p, j) {
        p.hidden = i !== j;
        p.classList.toggle('is-active', i === j);
      });
    });
    initTraffic();
    initPacket();
    initShield();
    const clock = $('consoleClock');
    if (clock) {
      clock.textContent = clockString(new Date());
      every(1000, function () {
        clock.textContent = clockString(new Date());
      });
    }
  }

  /* ---------- Capability micro-metrics ---------- */
  function initTickers() {
    if (reduceMotion) return;
    const nodes = Array.prototype.slice.call(doc.querySelectorAll('[data-tick]'));
    every(2600, function () {
      const n = pick(nodes);
      const v = Number(n.getAttribute('data-tick')) + 1 + Math.floor(Math.random() * 3);
      n.setAttribute('data-tick', String(v));
      n.textContent = fmtInt(v);
    });
  }

  /* ---------- Defense matrix (latencies measured live) ---------- */
  function measure(fn, iterations) {
    fn(); // warm up
    const t0 = performance.now();
    for (let i = 0; i < iterations; i++) fn();
    return (performance.now() - t0) / iterations;
  }

  function fmtMs(ms) {
    if (ms < 0.01) return '<0.01 ms';
    if (ms < 10) return ms.toFixed(2) + ' ms';
    return ms.toFixed(1) + ' ms';
  }

  let stageData = null;

  function buildStages() {
    const D = Scrub.detectors;
    const R = Scrub.redactors;
    const V = Scrub.validators;
    const text = (Scrub.sample && Scrub.sample.TEXT) || PACKET;
    let scan = D.scan(text);
    const detectMs = measure(function () {
      scan = D.scan(text);
    }, 20);

    const raws = scan.findings.map(function (f) {
      return f;
    });
    const isolateMs = measure(function () {
      for (let i = 0; i < raws.length; i++) {
        const f = raws[i];
        if (f.type === 'CREDIT_CARD') V.luhnCheck(f.raw.replace(/[ \t-]/g, ''));
        else if (f.type === 'AADHAAR') V.isValidAadhaar(f.raw);
        else if (f.type === 'IP') V.isValidIPv4(f.raw) || V.isValidIPv6(f.raw);
        else if (f.type === 'PAN') V.isValidPanHolder(f.raw);
      }
    }, 200);

    let red = R.redact(text, scan.findings, 'pseudonym');
    const neutralizeMs = measure(function () {
      red = R.redact(text, scan.findings, 'pseudonym');
    }, 50);

    const rej = scan.rejected;
    const rejected = rej.CREDIT_CARD + rej.AADHAAR + rej.PAN + rej.IP;
    stageData = { text: text, scan: scan, red: red };

    return [
      {
        tag: 'STAGE 01 // SENSE',
        title: 'Detect',
        latency: fmtMs(detectMs),
        statLabel: 'Candidates matched',
        stat: String(scan.total + rejected),
        steps: [
          'Six linear-time scanners sweep the text in one pass',
          'Boundary rules drop matches glued to letters, dates or versions',
          'Overlaps resolve by priority: card, Aadhaar, PAN, email, IP, phone'
        ]
      },
      {
        tag: 'STAGE 02 // VERIFY',
        title: 'Isolate',
        latency: fmtMs(isolateMs),
        statLabel: 'Look-alikes rejected',
        stat: String(rejected),
        steps: [
          'Card numbers must pass Luhn; Aadhaar must pass Verhoeff',
          'IPv4 octets are range-checked; PAN holder letter must be valid',
          'Rejected look-alikes are counted for the audit, never redacted'
        ]
      },
      {
        tag: 'STAGE 03 // CONTAIN',
        title: 'Neutralize',
        latency: fmtMs(neutralizeMs),
        statLabel: 'Placeholders issued',
        stat: String(red.mapping.length),
        steps: [
          'Full mask, partial mask, or consistent pseudonyms per document',
          'Same value, same placeholder: a@x.com and A@X.com become USER_01',
          'Line endings and non-PII bytes are preserved exactly'
        ]
      }
    ];
  }

  /* Render text with entity spans as <mark class="hl hl-TYPE"> (pure DOM). */
  function renderHL(container, text, spans, extraClass) {
    const frag = doc.createDocumentFragment();
    let cursor = 0;
    spans.forEach(function (s) {
      if (s.start > cursor) frag.appendChild(doc.createTextNode(text.slice(cursor, s.start)));
      frag.appendChild(el('mark', 'hl hl-' + s.type + (extraClass ? ' ' + extraClass : ''), text.slice(s.start, s.end)));
      cursor = s.end;
    });
    if (cursor < text.length) frag.appendChild(doc.createTextNode(text.slice(cursor)));
    container.replaceChildren(frag);
  }

  function rvRow(i, children, cls) {
    const row = el('div', 'rv-row' + (cls ? ' ' + cls : ''));
    row.style.setProperty('--i', String(i));
    children.forEach(function (c) {
      row.appendChild(c);
    });
    return row;
  }

  function typeBadge(type) {
    const b = el('span', 'type-badge', type === 'CREDIT_CARD' ? 'CARD' : type);
    b.setAttribute('data-entity', type);
    return b;
  }

  /* Stage 01: real lines from the sample with the scanner's matches highlighted. */
  function visualDetect() {
    const D = Scrub.detectors;
    const lines = stageData.text.split('\n');
    const picked = [];
    const seenTypes = {};
    for (let n = 0; n < lines.length && picked.length < 7; n++) {
      const res = D.scan(lines[n]);
      if (!res.total) continue;
      const fresh = res.findings.some(function (f) { return !seenTypes[f.type]; });
      if (!fresh && picked.length >= 4) continue;
      res.findings.forEach(function (f) { seenTypes[f.type] = true; });
      picked.push({ n: n + 1, text: lines[n], findings: res.findings });
    }
    const rows = picked.map(function (p, i) {
      const code = el('span', 'rv-text');
      renderHL(code, p.text, p.findings);
      return rvRow(i, [el('span', 'rv-ln', String(p.n).padStart(2, '0')), code], 'rv-detect');
    });
    return { title: 'SCAN FEED // SAMPLE PAYLOAD', meta: picked.length + ' of ' + lines.length + ' lines', rows: rows, scan: true };
  }

  /* Stage 02: look-alikes vs real identifiers, judged by the real validators. */
  function visualIsolate() {
    const V = Scrub.validators;
    const cands = [
      { v: '4111 1111 1111 1111', type: 'CREDIT_CARD', check: 'Luhn', ok: V.luhnCheck('4111111111111111') },
      { v: '4111 1111 1111 1112', type: 'CREDIT_CARD', check: 'Luhn', ok: V.luhnCheck('4111111111111112') },
      { v: '2345 6789 0124', type: 'AADHAAR', check: 'Verhoeff', ok: V.isValidAadhaar('2345 6789 0124') },
      { v: '2345 6789 0120', type: 'AADHAAR', check: 'Verhoeff', ok: V.isValidAadhaar('2345 6789 0120') },
      { v: '192.168.10.42', type: 'IP', check: 'Octet range', ok: V.isValidIPv4('192.168.10.42') },
      { v: '999.300.1.1', type: 'IP', check: 'Octet range', ok: V.isValidIPv4('999.300.1.1') },
      { v: 'ABCPE1234F', type: 'PAN', check: 'Holder type', ok: V.isValidPanHolder('ABCPE1234F') },
      { v: 'XYZQE4512K', type: 'PAN', check: 'Holder type', ok: V.isValidPanHolder('XYZQE4512K') }
    ];
    let pass = 0;
    const rows = cands.map(function (c, i) {
      if (c.ok) pass++;
      const verdict = el('span', 'rv-verdict ' + (c.ok ? 'is-pii' : 'is-decoy'), c.ok ? 'PII → REDACT' : 'DECOY → KEEP');
      return rvRow(i, [typeBadge(c.type), el('span', 'rv-val', c.v), el('span', 'rv-check', c.check), verdict], 'rv-isolate' + (c.ok ? '' : ' is-dim'));
    });
    return { title: 'CHECKSUM GATE', meta: pass + ' real · ' + (cands.length - pass) + ' look-alikes', rows: rows };
  }

  /* Stage 03: raw value → consistent placeholder, from the real redaction pass. */
  function visualNeutralize() {
    const reps = stageData.red.replacements;
    const seen = {};
    const pickedReps = [];
    reps.forEach(function (r) {
      if (!seen[r.type] && pickedReps.length < 6) {
        seen[r.type] = true;
        pickedReps.push(r);
      }
    });
    // show one repeat to prove consistency: same value → same placeholder
    const repeat = reps.find(function (r) {
      return pickedReps.some(function (p) { return p.pseudonym === r.pseudonym && p.raw !== r.raw; });
    });
    if (repeat) pickedReps.push(repeat);
    const rows = pickedReps.map(function (r, i) {
      return rvRow(i, [typeBadge(r.type), el('span', 'rv-raw', r.raw), el('span', 'rv-arrow', '→'), el('span', 'rv-out', r.pseudonym)], 'rv-neutralize' + (r === repeat ? ' is-repeat' : ''));
    });
    return { title: 'PSEUDONYM PASS', meta: stageData.red.mapping.length + ' placeholders · consistent', rows: rows };
  }

  function renderVisual(i) {
    const v = [visualDetect, visualIsolate, visualNeutralize][i]();
    $('rvTitle').textContent = v.title;
    $('rvMeta').textContent = v.meta;
    const body = $('rvBody');
    body.classList.toggle('is-scanning', Boolean(v.scan));
    const f = doc.createDocumentFragment();
    v.rows.forEach(function (r) { f.appendChild(r); });
    body.replaceChildren(f);
  }

  /* ---------- Live ops stats (measured) ---------- */
  function countUp(node, to, decimals) {
    if (reduceMotion) {
      node.textContent = to.toFixed(decimals);
      return;
    }
    const t0 = performance.now();
    const dur = 1100;
    function step(now) {
      const k = Math.min(1, (now - t0) / dur);
      const e = 1 - Math.pow(1 - k, 3);
      node.textContent = decimals ? (to * e).toFixed(decimals) : fmtInt(Math.round(to * e));
      if (k < 1) global.requestAnimationFrame(step);
    }
    global.requestAnimationFrame(step);
  }

  function initStats() {
    const D = Scrub.detectors;
    if (!D || !Scrub.sample) return;
    const text = Scrub.sample.TEXT;
    const big = new Array(48).fill(text).join('\n');
    D.scan(big); // warm
    const t0 = performance.now();
    D.scan(big);
    const ms = Math.max(0.1, performance.now() - t0);
    const mbps = (big.length / 1048576) / (ms / 1000);
    const res = D.scan(text);
    const rej = res.rejected.CREDIT_CARD + res.rejected.AADHAAR + res.rejected.PAN + res.rejected.IP;

    const targets = [
      [$('statThroughput'), mbps, 1],
      [$('statEntities'), res.total, 0],
      [$('statRejected'), rej, 0]
    ];
    const band = doc.querySelector('.stat-band');
    let done = false;
    function run() {
      if (done) return;
      done = true;
      targets.forEach(function (t) {
        if (t[0]) countUp(t[0], t[1], t[2]);
      });
    }
    if ('IntersectionObserver' in global && band) {
      const io = new IntersectionObserver(function (entries) {
        if (entries[0].isIntersecting) {
          run();
          io.disconnect();
        }
      }, { threshold: 0.4 });
      io.observe(band);
    } else {
      run();
    }
  }

  /* ---------- Before / after gate ---------- */
  function initCompare() {
    const body = $('compareBody');
    if (!body || !Scrub.detectors || !Scrub.sample) return;
    const D = Scrub.detectors;
    const R = Scrub.redactors;
    const lines = Scrub.sample.TEXT.split('\n');
    const text = lines.slice(0, 11).join('\n');
    const scan = D.scan(text);
    const rawPre = $('compareRaw');
    const cleanPre = $('compareClean');
    const range = $('compareRange');
    const chips = Array.prototype.slice.call(doc.querySelectorAll('.mode-chip'));

    renderHL(rawPre, text, scan.findings);

    function renderClean(mode) {
      const red = R.redact(text, scan.findings, mode, { typedLabels: true });
      renderHL(
        cleanPre,
        red.output,
        red.replacements.map(function (r) {
          return { start: r.outStart, end: r.outEnd, type: r.type };
        }),
        'hl-sanitized'
      );
    }

    const rawMarks = function () {
      return Array.prototype.slice.call(rawPre.querySelectorAll('mark'));
    };

    function update() {
      const pct = Number(range.value);
      body.style.setProperty('--pos', pct + '%');
      const rect = body.getBoundingClientRect();
      const gateX = rect.left + (rect.width * pct) / 100;
      let exposed = 0;
      const marks = rawMarks();
      marks.forEach(function (m) {
        const r = m.getBoundingClientRect();
        if ((r.left + r.right) / 2 < gateX) exposed++;
      });
      $('compareRawCount').textContent = String(exposed);
      $('compareCleanCount').textContent = String(marks.length - exposed);
    }

    chips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        chips.forEach(function (c) {
          const on = c === chip;
          c.classList.toggle('is-active', on);
          c.setAttribute('aria-checked', on ? 'true' : 'false');
        });
        renderClean(chip.getAttribute('data-mode'));
      });
    });

    range.addEventListener('input', update);
    global.addEventListener('resize', update);
    renderClean('pseudonym');
    update();

    // one-time sweep the first time the card scrolls into view
    if (!reduceMotion && 'IntersectionObserver' in global) {
      const io = new IntersectionObserver(function (entries) {
        if (!entries[0].isIntersecting) return;
        io.disconnect();
        const t0 = performance.now();
        const from = 92;
        const to = 38;
        range.value = String(from);
        function step(now) {
          const k = Math.min(1, (now - t0) / 1400);
          const e = 1 - Math.pow(1 - k, 3);
          range.value = String(Math.round(from + (to - from) * e));
          update();
          if (k < 1) global.requestAnimationFrame(step);
        }
        global.requestAnimationFrame(step);
      }, { threshold: 0.5 });
      io.observe(body);
    }
  }

  /* ---------- Use-case cards: live previews + 3D tilt ---------- */
  function initUses() {
    const cards = Array.prototype.slice.call(doc.querySelectorAll('.use'));
    if (!cards.length || !Scrub.detectors) return;
    const modes = ['pseudonym', 'partial', 'full', 'pseudonym'];
    cards.forEach(function (card, idx) {
      const text = card.getAttribute('data-sample') || '';
      const scan = Scrub.detectors.scan(text);
      const red = Scrub.redactors.redact(text, scan.findings, modes[idx % modes.length], { typedLabels: true });
      renderHL(card.querySelector('.use-raw'), text, scan.findings);
      renderHL(
        card.querySelector('.use-clean'),
        red.output,
        red.replacements.map(function (r) {
          return { start: r.outStart, end: r.outEnd, type: r.type };
        }),
        'hl-sanitized'
      );
    });

    const finePointer = typeof global.matchMedia === 'function' && global.matchMedia('(hover: hover) and (pointer: fine)').matches;
    if (reduceMotion || !finePointer) return;
    cards.forEach(function (card) {
      card.addEventListener('pointermove', function (ev) {
        const r = card.getBoundingClientRect();
        const nx = (ev.clientX - r.left) / r.width - 0.5;
        const ny = (ev.clientY - r.top) / r.height - 0.5;
        card.style.setProperty('--ry', (nx * 10).toFixed(2) + 'deg');
        card.style.setProperty('--rx', (-ny * 10).toFixed(2) + 'deg');
        card.style.setProperty('--mx', ((nx + 0.5) * 100).toFixed(1) + '%');
        card.style.setProperty('--my', ((ny + 0.5) * 100).toFixed(1) + '%');
      });
      card.addEventListener('pointerleave', function () {
        card.style.setProperty('--ry', '0deg');
        card.style.setProperty('--rx', '0deg');
      });
    });
  }

  /* ---------- Scroll reveal ---------- */
  function initReveal() {
    const items = Array.prototype.slice.call(doc.querySelectorAll('.reveal'));
    if (reduceMotion || !('IntersectionObserver' in global)) {
      items.forEach(function (n) { n.classList.add('is-in'); });
      return;
    }
    const io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          e.target.classList.add('is-in');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });
    items.forEach(function (n) { io.observe(n); });
  }

  function initMatrix() {
    const panel = $('stagePanel');
    if (!panel || !Scrub.detectors) return;
    const stages = buildStages();
    const tabs = Array.prototype.slice.call(doc.querySelectorAll('.stage'));

    function show(i) {
      const s = stages[i];
      $('stageTag').textContent = s.tag;
      $('stageTitle').textContent = s.title;
      $('stageLatency').textContent = s.latency;
      $('stageStatLabel').textContent = s.statLabel;
      $('stageStat').textContent = s.stat;
      const ol = $('stageSteps');
      const f = doc.createDocumentFragment();
      s.steps.forEach(function (t) {
        f.appendChild(el('li', '', t));
      });
      ol.replaceChildren(f);
      renderVisual(i, s);
      panel.setAttribute('aria-label', 'Stage ' + (i + 1) + ': ' + s.title);
    }

    let swapTimer = null;
    wireTablist(tabs, function (i) {
      if (reduceMotion) {
        show(i);
        return;
      }
      panel.classList.add('is-swapping');
      global.clearTimeout(swapTimer);
      swapTimer = global.setTimeout(function () {
        show(i);
        panel.classList.remove('is-swapping');
      }, 180);
    });
    show(0);
  }

  /* ---------- CTA + live system facts ---------- */
  function initCtas() {
    const audit = $('ctaAudit');
    const sample = $('btnSample');
    if (audit && sample) {
      audit.addEventListener('click', function () {
        // let the anchor scroll, then load the sample so the audit is ready
        global.setTimeout(function () {
          sample.click();
        }, reduceMotion ? 0 : 450);
      });
    }
  }

  function countOutbound() {
    if (!global.performance || typeof performance.getEntriesByType !== 'function') return 0;
    const here = global.location.origin;
    return performance.getEntriesByType('resource').filter(function (e) {
      return /^https?:/i.test(e.name) && e.name.indexOf(here) !== 0;
    }).length;
  }

  function initSystem() {
    const start = Date.now();
    const up = $('uptime');
    const reqA = $('factRequests');
    const reqB = $('footRequests');
    function tick() {
      const s = Math.floor((Date.now() - start) / 1000);
      if (up) up.textContent = pad2(Math.floor(s / 3600)) + ':' + pad2(Math.floor((s % 3600) / 60)) + ':' + pad2(s % 60);
      const n = String(countOutbound());
      if (reqA) reqA.textContent = n;
      if (reqB) reqB.textContent = n;
    }
    tick();
    every(1000, tick);
  }

  // Hide reveal targets only when JS is running, so the page never ships blank.
  if (!reduceMotion) doc.documentElement.classList.add('js-reveal');

  function init() {
    initNav();
    initConsole();
    initTickers();
    initMatrix();
    initStats();
    initCompare();
    initUses();
    initCtas();
    initSystem();
    initReveal();
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', init);
  else init();
})(typeof window !== 'undefined' ? window : globalThis);
