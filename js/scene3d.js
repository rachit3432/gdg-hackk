/* AEGIS // PROTOCOL — "Scrub Core" hero scene.
   Hand-rolled 3D on a 2D canvas (no WebGL library: the CSP forbids CDNs).
   A point-cloud sphere with a counter-rotating icosahedron core. Real PII
   tokens orbit it; each one is redacted by the actual engine the moment it
   crosses the scan gate at the front of the sphere. */
(function (global) {
  'use strict';

  const doc = global.document;
  const Scrub = global.Scrub || {};

  const TAU = Math.PI * 2;
  const COLORS = {
    point: [127, 227, 238],
    core: [233, 162, 59],
    raw: [242, 73, 107],
    clean: [127, 227, 238],
    ring: [42, 48, 58]
  };

  // Raw values come from the noisy sample; masks are produced by the engine.
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

  function maskFor(tok, idx) {
    if (tok.mode === 'pseudonym') {
      return PREFIX[tok.type] + '_0' + ((idx % 3) + 1);
    }
    if (Scrub.redactors && Scrub.redactors.maskPartial) {
      return Scrub.redactors.maskPartial(tok.type, tok.raw);
    }
    return '[REDACTED]';
  }

  function rgba(c, a) {
    return 'rgba(' + c[0] + ',' + c[1] + ',' + c[2] + ',' + a.toFixed(3) + ')';
  }

  function fibonacciSphere(n) {
    const pts = [];
    const golden = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < n; i++) {
      const y = 1 - (i / (n - 1)) * 2;
      const r = Math.sqrt(1 - y * y);
      const t = golden * i;
      pts.push([Math.cos(t) * r, y, Math.sin(t) * r]);
    }
    return pts;
  }

  function icosahedron() {
    const p = (1 + Math.sqrt(5)) / 2;
    const v = [
      [-1, p, 0], [1, p, 0], [-1, -p, 0], [1, -p, 0],
      [0, -1, p], [0, 1, p], [0, -1, -p], [0, 1, -p],
      [p, 0, -1], [p, 0, 1], [-p, 0, -1], [-p, 0, 1]
    ].map(function (q) {
      const l = Math.hypot(q[0], q[1], q[2]);
      return [q[0] / l, q[1] / l, q[2] / l];
    });
    const edges = [];
    for (let i = 0; i < v.length; i++) {
      for (let j = i + 1; j < v.length; j++) {
        const d = Math.hypot(v[i][0] - v[j][0], v[i][1] - v[j][1], v[i][2] - v[j][2]);
        if (d < 1.1) edges.push([i, j]);
      }
    }
    return { v: v, edges: edges };
  }

  function rotY(p, a) {
    const c = Math.cos(a), s = Math.sin(a);
    return [p[0] * c + p[2] * s, p[1], -p[0] * s + p[2] * c];
  }
  function rotX(p, a) {
    const c = Math.cos(a), s = Math.sin(a);
    return [p[0], p[1] * c - p[2] * s, p[1] * s + p[2] * c];
  }
  function rotZ(p, a) {
    const c = Math.cos(a), s = Math.sin(a);
    return [p[0] * c - p[1] * s, p[0] * s + p[1] * c, p[2]];
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

    const sphere = fibonacciSphere(520);
    const ico = icosahedron();
    const orbits = TOKENS.map(function (tok, i) {
      return {
        raw: tok.raw,
        clean: maskFor(tok, i),
        theta: ((i * 7) % TOKENS.length / TOKENS.length) * TAU,
        y: -0.84 + i * (1.68 / (TOKENS.length - 1)),
        radius: 1.24 + (i % 3) * 0.09,
        speed: 0.16 + (i % 4) * 0.025,
        masked: false,
        flash: 0
      };
    });

    let W = 0, H = 0, R = 0, cx = 0, cy = 0, dpr = 1;
    let rotYAngle = 0.4;
    let tiltX = -0.22, tiltY = 0;
    let targetX = -0.22, targetY = 0;
    let redactions = 0;
    let visible = true;
    let last = 0;
    let rafId = null;
    const flips = [];

    function resize() {
      const rect = canvas.getBoundingClientRect();
      dpr = Math.min(global.devicePixelRatio || 1, 2);
      W = rect.width;
      H = rect.height;
      canvas.width = Math.round(W * dpr);
      canvas.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      R = Math.min(W, H) * 0.27;
      cx = W / 2;
      cy = H / 2;
    }

    const CAM = 3.2;
    function project(p) {
      const s = CAM / (CAM - p[2]);
      return [cx + p[0] * R * s, cy - p[1] * R * s, s, p[2]];
    }

    function viewTransform(p) {
      return rotX(rotY(p, tiltY), tiltX);
    }

    const ORBIT_TILT = 0.12;
    function drawRing(y, radius, color, alpha, dash) {
      ctx.beginPath();
      for (let i = 0; i <= 96; i++) {
        const t = (i / 96) * TAU;
        let p = [-Math.cos(t) * radius, y, Math.sin(t) * radius];
        p = viewTransform(rotZ(p, ORBIT_TILT));
        const q = project(p);
        if (i === 0) ctx.moveTo(q[0], q[1]);
        else ctx.lineTo(q[0], q[1]);
      }
      ctx.setLineDash(dash || []);
      ctx.strokeStyle = rgba(color, alpha);
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.setLineDash([]);
    }

    function drawGate() {
      // vertical scan plane at x = 0, facing the viewer
      const top = project(viewTransform([0, 1.55, 0.9]));
      const bot = project(viewTransform([0, -1.55, 0.9]));
      const g = ctx.createLinearGradient(top[0], top[1], bot[0], bot[1]);
      g.addColorStop(0, rgba(COLORS.clean, 0));
      g.addColorStop(0.5, rgba(COLORS.clean, 0.55));
      g.addColorStop(1, rgba(COLORS.clean, 0));
      ctx.strokeStyle = g;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(top[0], top[1]);
      ctx.lineTo(bot[0], bot[1]);
      ctx.stroke();
      const glow = ctx.createLinearGradient(top[0] - 26, 0, top[0] + 26, 0);
      glow.addColorStop(0, rgba(COLORS.clean, 0));
      glow.addColorStop(0.5, rgba(COLORS.clean, 0.05));
      glow.addColorStop(1, rgba(COLORS.clean, 0));
      ctx.fillStyle = glow;
      ctx.fillRect(top[0] - 26, top[1], 52, bot[1] - top[1]);
    }

    function tokenPos(o) {
      const p = [-Math.cos(o.theta) * o.radius, o.y, Math.sin(o.theta) * o.radius];
      return viewTransform(rotZ(p, ORBIT_TILT));
    }

    function drawToken(o) {
      const p = tokenPos(o);
      const q = project(p);
      const depth = (p[2] + 1.6) / 3.2; // 0 back .. 1 front
      const alpha = 0.18 + depth * 0.82;
      const size = Math.round(9.5 + depth * 3);
      const label = o.masked ? o.clean : o.raw;
      const col = o.masked ? COLORS.clean : COLORS.raw;

      ctx.font = '500 ' + size + 'px "JetBrains Mono", "Cascadia Mono", Consolas, monospace';
      const tw = ctx.measureText(label).width;
      // flip the label to the left of its anchor near the right edge
      const flip = q[0] + 12 + tw > W - 6;
      const x = Math.max(6, Math.min(W - tw - 6, flip ? q[0] - 10 - tw : q[0] + 8));
      const y = q[1] + size * 0.35;

      // anchor
      ctx.fillStyle = rgba(col, alpha);
      ctx.fillRect(q[0] - 2, q[1] - 2, 4, 4);
      // leader tick
      ctx.fillStyle = rgba(col, alpha * 0.5);
      ctx.fillRect(flip ? q[0] - 7 : q[0] + 3, q[1], 4, 1);

      // plate
      ctx.fillStyle = 'rgba(9,10,13,' + (0.55 * alpha).toFixed(3) + ')';
      ctx.fillRect(x - 4, y - size, tw + 8, size + 6);
      if (o.flash > 0) {
        ctx.strokeStyle = rgba(COLORS.clean, o.flash * 0.9);
        ctx.strokeRect(x - 4.5, y - size - 0.5, tw + 9, size + 7);
      }
      ctx.fillStyle = rgba(col, alpha);
      ctx.fillText(label, x, y);
    }

    function frame(now) {
      rafId = null;
      if (!visible || doc.hidden) return;
      const dt = last ? Math.min(0.05, (now - last) / 1000) : 0.016;
      last = now;

      if (!reduceMotion) {
        rotYAngle += dt * 0.18;
        tiltX += (targetX - tiltX) * 0.06;
        tiltY += (targetY - tiltY) * 0.06;
      }

      ctx.clearRect(0, 0, W, H);

      // orbit rings (behind)
      drawRing(-0.66, 1.24, COLORS.ring, 0.9, [2, 5]);
      drawRing(0.0, 1.42, COLORS.ring, 0.7);
      drawRing(0.66, 1.33, COLORS.ring, 0.9, [2, 5]);

      // advance tokens + gate crossings
      orbits.forEach(function (o) {
        if (!reduceMotion) o.theta = (o.theta + dt * o.speed) % TAU;
        const t = o.theta;
        const shouldMask = t > Math.PI / 2 && t < Math.PI * 1.5;
        if (shouldMask && !o.masked) {
          o.masked = true;
          o.flash = 1;
          redactions++;
          flips.push(now);
        } else if (!shouldMask && o.masked) {
          o.masked = false;
        }
        o.flash = Math.max(0, o.flash - dt * 1.6);
      });

      // back tokens
      const withDepth = orbits.map(function (o) {
        return { o: o, z: tokenPos(o)[2] };
      });
      withDepth.sort(function (a, b) { return a.z - b.z; });
      withDepth.forEach(function (d) {
        if (d.z < 0) drawToken(d.o);
      });

      // sphere point cloud
      for (let i = 0; i < sphere.length; i++) {
        const p = viewTransform(rotY(sphere[i], rotYAngle));
        const q = project(p);
        const depth = (p[2] + 1) / 2;
        const a = 0.08 + depth * 0.6;
        const s = 0.6 + depth * 1.4;
        ctx.fillStyle = rgba(COLORS.point, a);
        ctx.fillRect(q[0] - s / 2, q[1] - s / 2, s, s);
      }

      // icosahedron core (counter-rotating)
      const coreScale = 0.46;
      const pv = ico.v.map(function (v) {
        let p = [v[0] * coreScale, v[1] * coreScale, v[2] * coreScale];
        p = rotX(rotY(p, -rotYAngle * 1.6), 0.5);
        return project(viewTransform(p));
      });
      ctx.lineWidth = 1;
      ico.edges.forEach(function (e) {
        const a = pv[e[0]], b = pv[e[1]];
        const depth = ((a[3] + b[3]) / 2 + 0.5);
        ctx.strokeStyle = rgba(COLORS.core, 0.12 + Math.max(0, depth) * 0.45);
        ctx.beginPath();
        ctx.moveTo(a[0], a[1]);
        ctx.lineTo(b[0], b[1]);
        ctx.stroke();
      });

      drawGate();

      // front tokens
      withDepth.forEach(function (d) {
        if (d.z >= 0) drawToken(d.o);
      });

      // HUD numbers
      while (flips.length && now - flips[0] > 10000) flips.shift();
      if (counterEl) counterEl.textContent = redactions.toLocaleString('en-US');
      if (rateEl) rateEl.textContent = (flips.length / 10).toFixed(1) + '/s';

      if (!reduceMotion) rafId = global.requestAnimationFrame(frame);
    }

    function kick() {
      if (rafId === null && visible && !doc.hidden) {
        last = 0;
        rafId = global.requestAnimationFrame(frame);
      }
    }

    resize();
    global.addEventListener('resize', function () {
      resize();
      if (reduceMotion) kick();
    });

    const stage = canvas.parentElement;
    stage.addEventListener('pointermove', function (ev) {
      const r = stage.getBoundingClientRect();
      const nx = (ev.clientX - r.left) / r.width - 0.5;
      const ny = (ev.clientY - r.top) / r.height - 0.5;
      targetY = nx * 0.7;
      targetX = -0.22 + ny * 0.5;
    });
    stage.addEventListener('pointerleave', function () {
      targetX = -0.22;
      targetY = 0;
    });

    if ('IntersectionObserver' in global) {
      new IntersectionObserver(function (entries) {
        visible = entries[0].isIntersecting;
        kick();
      }).observe(canvas);
    }
    doc.addEventListener('visibilitychange', kick);

    if (reduceMotion) {
      // one static, fully composed frame with half the tokens already scrubbed
      orbits.forEach(function (o, i) {
        o.masked = i % 2 === 0;
      });
    }
    kick();
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', init);
  else init();
})(typeof window !== 'undefined' ? window : globalThis);
