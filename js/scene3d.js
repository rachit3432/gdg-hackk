/* AEGIS // PROTOCOL — "Scrub Core" hero scene.
 *
 * Hand-rolled 3D on a 2D canvas (no WebGL library: the CSP forbids CDNs).
 * A point-cloud sphere with a counter-rotating icosahedron core. Real PII
 * tokens orbit it on separate latitude bands; each one is redacted by the
 * actual engine the moment it crosses the scan gate at the front.
 *
 * Performance notes:
 *  - Geometry is precomputed into typed arrays; the per-frame loop allocates nothing.
 *  - One combined rotation matrix per frame (two Y rotations fold into one angle).
 *  - Opacity varies through ctx.globalAlpha, so no colour strings are built per point.
 *  - Label widths are cached; the loop stops when off-screen, hidden, or paused.
 */
(function (global) {
  'use strict';

  const doc = global.document;
  const Scrub = (global.Scrub = global.Scrub || {});

  const TAU = Math.PI * 2;
  const CAM = 3.2; // camera distance in sphere radii
  const SPHERE_POINTS = 520;
  const RING_SEGMENTS = 64;
  const ORBIT_TILT = 0.12;
  const BASE_TILT_X = -0.22;

  const RGB = {
    point: '127,227,238',
    core: '233,162,59',
    raw: '242,73,107',
    clean: '127,227,238',
    ring: '42,48,58'
  };

  // Raw values come from the noisy sample; masks are produced by the engine at runtime.
  const TOKENS = [
    { type: 'EMAIL', raw: 'priya.sharma+billing@acmecorp.example', mode: 'pseudonym' },
    { type: 'PHONE', raw: '+91 98765 43210', mode: 'partial' },
    { type: 'CREDIT_CARD', raw: '4111 1111 1111 1111', mode: 'partial' },
    { type: 'PAN', raw: 'ABCPE1234F', mode: 'partial' },
    { type: 'AADHAAR', raw: '2345 6789 0124', mode: 'partial' },
    { type: 'IP', raw: '203.0.113.77', mode: 'partial' },
    { type: 'EMAIL', raw: 'dr.mehta+clinic@medportal.example.in', mode: 'pseudonym' },
    { type: 'CREDIT_CARD', raw: '5555 5555 5555 4444', mode: 'pseudonym' },
    { type: 'IP', raw: '2001:db8:85a3::8a2e:370:7334', mode: 'pseudonym' },
    { type: 'PHONE', raw: '+44 20 7946 0958', mode: 'partial' }
  ];

  const PREFIX = { EMAIL: 'USER', PHONE: 'PHONE', IP: 'IP', PAN: 'PAN', AADHAAR: 'AADHAAR', CREDIT_CARD: 'CARD' };

  /** Engine output for an orbiting token (partial mask or a pseudonym). */
  function maskFor(tok, idx) {
    if (tok.mode === 'pseudonym') {
      return PREFIX[tok.type] + '_0' + ((idx % 3) + 1);
    }
    return Scrub.redactors ? Scrub.redactors.maskPartial(tok.type, tok.raw) : '[REDACTED]';
  }

  /** Evenly distributed unit-sphere points, packed as [x0,y0,z0,x1,...]. */
  function fibonacciSphere(n) {
    const out = new Float32Array(n * 3);
    const golden = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < n; i++) {
      const y = 1 - (i / (n - 1)) * 2;
      const r = Math.sqrt(1 - y * y);
      const t = golden * i;
      out[i * 3] = Math.cos(t) * r;
      out[i * 3 + 1] = y;
      out[i * 3 + 2] = Math.sin(t) * r;
    }
    return out;
  }

  /** Unit icosahedron: 12 vertices and the 30 edges between nearest neighbours. */
  function icosahedron() {
    const p = (1 + Math.sqrt(5)) / 2;
    const raw = [
      [-1, p, 0], [1, p, 0], [-1, -p, 0], [1, -p, 0],
      [0, -1, p], [0, 1, p], [0, -1, -p], [0, 1, -p],
      [p, 0, -1], [p, 0, 1], [-p, 0, -1], [-p, 0, 1]
    ];
    const v = new Float32Array(36);
    raw.forEach(function (q, i) {
      const l = Math.hypot(q[0], q[1], q[2]);
      v[i * 3] = q[0] / l;
      v[i * 3 + 1] = q[1] / l;
      v[i * 3 + 2] = q[2] / l;
    });
    const edges = [];
    for (let i = 0; i < 12; i++) {
      for (let j = i + 1; j < 12; j++) {
        const d = Math.hypot(v[i * 3] - v[j * 3], v[i * 3 + 1] - v[j * 3 + 1], v[i * 3 + 2] - v[j * 3 + 2]);
        if (d < 1.1) edges.push(i, j);
      }
    }
    return { v: v, edges: new Uint8Array(edges) };
  }

  /**
   * Rotation matrix for Rx(ax) · Ry(ay), written into m (row-major 3x3).
   * @param {Float32Array} m
   */
  function setRotation(m, ax, ay) {
    const cx = Math.cos(ax), sx = Math.sin(ax), cy = Math.cos(ay), sy = Math.sin(ay);
    m[0] = cy;        m[1] = 0;   m[2] = sy;
    m[3] = sx * sy;   m[4] = cx;  m[5] = -sx * cy;
    m[6] = -cx * sy;  m[7] = sx;  m[8] = cx * cy;
  }

  function init() {
    const canvas = doc.getElementById('scrubCore');
    if (!canvas || !canvas.getContext) return;
    const ctx = canvas.getContext('2d');
    const counterEl = doc.getElementById('coreCount');
    const rateEl = doc.getElementById('coreRate');
    const reduceMotion =
      typeof global.matchMedia === 'function' &&
      global.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const sphere = fibonacciSphere(SPHERE_POINTS);
    const ico = icosahedron();
    const icoProj = new Float32Array(12 * 3);
    const ringCos = new Float32Array(RING_SEGMENTS + 1);
    const ringSin = new Float32Array(RING_SEGMENTS + 1);
    for (let i = 0; i <= RING_SEGMENTS; i++) {
      ringCos[i] = Math.cos((i / RING_SEGMENTS) * TAU);
      ringSin[i] = Math.sin((i / RING_SEGMENTS) * TAU);
    }
    const cosT = Math.cos(ORBIT_TILT), sinT = Math.sin(ORBIT_TILT);

    const orbits = TOKENS.map(function (tok, i) {
      return {
        raw: tok.raw,
        clean: maskFor(tok, i),
        theta: (((i * 7) % TOKENS.length) / TOKENS.length) * TAU,
        y: -0.84 + i * (1.68 / (TOKENS.length - 1)),
        radius: 1.24 + (i % 3) * 0.09,
        speed: 0.16 + (i % 4) * 0.025,
        masked: false,
        flash: 0,
        sx: 0, sy: 0, ss: 1, sz: 0 // projected screen position, scale, view depth
      };
    });
    const drawOrder = orbits.slice();

    const mView = new Float32Array(9); // tilt only (rings, tokens, gate)
    const mSphere = new Float32Array(9); // tilt + spin
    const mCore = new Float32Array(9); // counter-spin core
    const widthCache = new Map();

    let W = 0, H = 0, R = 0, cx = 0, cy = 0;
    let spin = 0.4;
    let tiltX = BASE_TILT_X, tiltY = 0, targetX = BASE_TILT_X, targetY = 0;
    let redactions = 0;
    let visible = true;
    let last = 0;
    let rafId = null;
    const flips = [];

    function resize() {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(global.devicePixelRatio || 1, 2);
      W = rect.width;
      H = rect.height;
      canvas.width = Math.round(W * dpr);
      canvas.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      R = Math.min(W, H) * 0.27;
      cx = W / 2;
      cy = H / 2;
      widthCache.clear();
    }

    /** Apply orbit tilt (about Z) then the view matrix; project into o.sx/sy/ss/sz. */
    function projectOrbit(o, px, py, pz) {
      const x = px * cosT - py * sinT;
      const y = px * sinT + py * cosT;
      const vx = mView[0] * x + mView[1] * y + mView[2] * pz;
      const vy = mView[3] * x + mView[4] * y + mView[5] * pz;
      const vz = mView[6] * x + mView[7] * y + mView[8] * pz;
      const s = CAM / (CAM - vz);
      o.sx = cx + vx * R * s;
      o.sy = cy - vy * R * s;
      o.ss = s;
      o.sz = vz;
    }

    const scratch = { sx: 0, sy: 0, ss: 1, sz: 0 };

    function drawRing(y, radius, alpha, dashed) {
      ctx.beginPath();
      for (let i = 0; i <= RING_SEGMENTS; i++) {
        projectOrbit(scratch, -ringCos[i] * radius, y, ringSin[i] * radius);
        if (i === 0) ctx.moveTo(scratch.sx, scratch.sy);
        else ctx.lineTo(scratch.sx, scratch.sy);
      }
      ctx.setLineDash(dashed ? [2, 5] : []);
      ctx.strokeStyle = 'rgba(' + RGB.ring + ',' + alpha + ')';
      ctx.stroke();
    }

    function drawGate() {
      const top = { sx: 0, sy: 0, ss: 1, sz: 0 };
      const bot = { sx: 0, sy: 0, ss: 1, sz: 0 };
      projectOrbit(top, 0, 1.55, 0.9);
      projectOrbit(bot, 0, -1.55, 0.9);
      ctx.setLineDash([]);
      const g = ctx.createLinearGradient(top.sx, top.sy, bot.sx, bot.sy);
      g.addColorStop(0, 'rgba(' + RGB.clean + ',0)');
      g.addColorStop(0.5, 'rgba(' + RGB.clean + ',0.55)');
      g.addColorStop(1, 'rgba(' + RGB.clean + ',0)');
      ctx.strokeStyle = g;
      ctx.beginPath();
      ctx.moveTo(top.sx, top.sy);
      ctx.lineTo(bot.sx, bot.sy);
      ctx.stroke();
      ctx.globalAlpha = 0.05;
      ctx.fillStyle = 'rgb(' + RGB.clean + ')';
      ctx.fillRect(top.sx - 14, top.sy, 28, bot.sy - top.sy);
      ctx.globalAlpha = 1;
    }

    function labelWidth(label, size) {
      const key = size + '|' + label;
      let w = widthCache.get(key);
      if (w === undefined) {
        w = ctx.measureText(label).width;
        widthCache.set(key, w);
      }
      return w;
    }

    function drawToken(o) {
      const depth = (o.sz + 1.6) / 3.2; // 0 = back, 1 = front
      const alpha = 0.18 + depth * 0.82;
      const size = Math.round(9.5 + depth * 3);
      const label = o.masked ? o.clean : o.raw;
      const rgb = o.masked ? RGB.clean : RGB.raw;

      ctx.font = '500 ' + size + 'px "JetBrains Mono", "Cascadia Mono", Consolas, monospace';
      const tw = labelWidth(label, size);
      const flip = o.sx + 12 + tw > W - 6;
      const x = Math.max(6, Math.min(W - tw - 6, flip ? o.sx - 10 - tw : o.sx + 8));
      const y = o.sy + size * 0.35;

      ctx.globalAlpha = alpha;
      ctx.fillStyle = 'rgb(' + rgb + ')';
      ctx.fillRect(o.sx - 2, o.sy - 2, 4, 4);
      ctx.globalAlpha = alpha * 0.5;
      ctx.fillRect(flip ? o.sx - 7 : o.sx + 3, o.sy, 4, 1);

      ctx.globalAlpha = 0.55 * alpha;
      ctx.fillStyle = '#090a0d';
      ctx.fillRect(x - 4, y - size, tw + 8, size + 6);
      if (o.flash > 0) {
        ctx.globalAlpha = o.flash * 0.9;
        ctx.strokeStyle = 'rgb(' + RGB.clean + ')';
        ctx.strokeRect(x - 4.5, y - size - 0.5, tw + 9, size + 7);
      }
      ctx.globalAlpha = alpha;
      ctx.fillStyle = 'rgb(' + rgb + ')';
      ctx.fillText(label, x, y);
      ctx.globalAlpha = 1;
    }

    function drawSphere() {
      ctx.fillStyle = 'rgb(' + RGB.point + ')';
      const m = mSphere;
      for (let i = 0; i < SPHERE_POINTS * 3; i += 3) {
        const x = sphere[i], y = sphere[i + 1], z = sphere[i + 2];
        const vz = m[6] * x + m[7] * y + m[8] * z;
        const s = CAM / (CAM - vz);
        const depth = (vz + 1) * 0.5;
        const size = 0.6 + depth * 1.4;
        ctx.globalAlpha = 0.08 + depth * 0.6;
        ctx.fillRect(
          cx + (m[0] * x + m[1] * y + m[2] * z) * R * s - size * 0.5,
          cy - (m[3] * x + m[4] * y + m[5] * z) * R * s - size * 0.5,
          size,
          size
        );
      }
      ctx.globalAlpha = 1;
    }

    function drawCore() {
      const k = 0.46;
      const m = mCore;
      for (let i = 0; i < 36; i += 3) {
        const x = ico.v[i] * k, y = ico.v[i + 1] * k, z = ico.v[i + 2] * k;
        const vz = m[6] * x + m[7] * y + m[8] * z;
        const s = CAM / (CAM - vz);
        icoProj[i] = cx + (m[0] * x + m[1] * y + m[2] * z) * R * s;
        icoProj[i + 1] = cy - (m[3] * x + m[4] * y + m[5] * z) * R * s;
        icoProj[i + 2] = vz;
      }
      ctx.strokeStyle = 'rgb(' + RGB.core + ')';
      for (let e = 0; e < ico.edges.length; e += 2) {
        const a = ico.edges[e] * 3, b = ico.edges[e + 1] * 3;
        ctx.globalAlpha = 0.12 + Math.max(0, (icoProj[a + 2] + icoProj[b + 2]) * 0.5 + 0.5) * 0.45;
        ctx.beginPath();
        ctx.moveTo(icoProj[a], icoProj[a + 1]);
        ctx.lineTo(icoProj[b], icoProj[b + 1]);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
    }

    function isPaused() {
      return Boolean(Scrub.motion && Scrub.motion.paused);
    }

    function frame(now) {
      rafId = null;
      if (!visible || doc.hidden) return;
      const animate = !reduceMotion && !isPaused();
      const dt = last ? Math.min(0.05, (now - last) / 1000) : 0.016;
      last = now;

      if (animate) {
        spin += dt * 0.18;
        tiltX += (targetX - tiltX) * 0.06;
        tiltY += (targetY - tiltY) * 0.06;
      }
      setRotation(mView, tiltX, tiltY);
      setRotation(mSphere, tiltX, tiltY + spin);
      setRotation(mCore, tiltX + 0.5, tiltY - spin * 1.6);

      ctx.clearRect(0, 0, W, H);
      ctx.lineWidth = 1;
      drawRing(-0.66, 1.24, 0.9, true);
      drawRing(0.0, 1.42, 0.7, false);
      drawRing(0.66, 1.33, 0.9, true);

      for (let i = 0; i < orbits.length; i++) {
        const o = orbits[i];
        if (animate) o.theta = (o.theta + dt * o.speed) % TAU;
        const shouldMask = o.theta > Math.PI / 2 && o.theta < Math.PI * 1.5;
        if (shouldMask && !o.masked) {
          o.masked = true;
          o.flash = 1;
          redactions++;
          flips.push(now);
        } else if (!shouldMask && o.masked) {
          o.masked = false;
        }
        o.flash = Math.max(0, o.flash - dt * 1.6);
        projectOrbit(o, -Math.cos(o.theta) * o.radius, o.y, Math.sin(o.theta) * o.radius);
      }
      drawOrder.sort(function (a, b) { return a.sz - b.sz; });

      ctx.setLineDash([]);
      for (let i = 0; i < drawOrder.length && drawOrder[i].sz < 0; i++) drawToken(drawOrder[i]);
      drawSphere();
      drawCore();
      drawGate();
      for (let i = 0; i < drawOrder.length; i++) if (drawOrder[i].sz >= 0) drawToken(drawOrder[i]);

      while (flips.length && now - flips[0] > 10000) flips.shift();
      if (counterEl) counterEl.textContent = redactions.toLocaleString('en-US');
      if (rateEl) rateEl.textContent = (flips.length / 10).toFixed(1) + '/s';

      if (animate) rafId = global.requestAnimationFrame(frame);
    }

    function kick() {
      if (rafId === null && visible && !doc.hidden) {
        last = 0;
        rafId = global.requestAnimationFrame(frame);
      }
    }

    resize();
    let resizeTimer = null;
    global.addEventListener('resize', function () {
      global.clearTimeout(resizeTimer);
      resizeTimer = global.setTimeout(function () {
        resize();
        kick();
      }, 120);
    });

    const stage = canvas.parentElement;
    stage.addEventListener('pointermove', function (ev) {
      const r = stage.getBoundingClientRect();
      targetY = ((ev.clientX - r.left) / r.width - 0.5) * 0.7;
      targetX = BASE_TILT_X + ((ev.clientY - r.top) / r.height - 0.5) * 0.5;
    });
    stage.addEventListener('pointerleave', function () {
      targetX = BASE_TILT_X;
      targetY = 0;
    });

    if ('IntersectionObserver' in global) {
      new IntersectionObserver(function (entries) {
        visible = entries[0].isIntersecting;
        kick();
      }).observe(canvas);
    }
    doc.addEventListener('visibilitychange', kick);
    doc.addEventListener('scrub:motion', kick);
    kick();
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', init);
  else init();
})(typeof window !== 'undefined' ? window : globalThis);
