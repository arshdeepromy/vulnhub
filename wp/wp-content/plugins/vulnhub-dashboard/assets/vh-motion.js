/* vh-motion.js — VulnHub motion layer. No dependencies, no build step.
   Enqueue after app.css. Everything is progressive: remove this file and the
   portal is still fully usable, just static.
   What it does:
     1. Page transitions       — fades/slides .vh-main in on load and on in-app link clicks
     2. Count-ups              — animates .vh-tile__value / .vh-card__value numbers from 0
     3. Widget-specific canvases — one motion per data-vh-widget (scan, radar, rain, heat, ping, ticker, mesh, funnel, countdown, pipeline, horizon, lanes)
                                 + OS badges: swaps .vh-os text (RH/WIN/…) for a glowing glyph badge
     4. Empty-state orbits     — draws dashed orbits behind .vh-chart-empty / .vh-empty
     5. Attack-path particles  — animates particles along .vh-flow__line paths in the flow widget
     6. Hover spotlight        — a soft accent glow that follows the cursor on cards
   Respects prefers-reduced-motion (does nothing except the instant fade). */
(function () {
  'use strict';
  var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var body = document.body; if (!body || !body.classList.contains('vh-app')) return;
  var accent = readAccent();
  var glows = [];

  function readAccent() {
    return (getComputedStyle(body).getPropertyValue('--vh-accent-rgb') || '94,224,255').trim();
  }

  /*
   * The accent differs per theme (cyan in dark, blue in light) and the toggle
   * swaps it by stamping data-theme on <html> -- no reload. Everything that
   * draws per frame re-reads `accent` on its own, but a canvas or a gradient
   * built once at setup kept whichever theme happened to be showing at load,
   * so toggling to light left cyan glows on a white card. Re-read the token
   * when the attribute changes and repaint what does not repaint itself.
   */
  new MutationObserver(function () {
    var next = readAccent();
    if (next === accent) return;
    accent = next;
    glows.forEach(function (paint) { paint(); });
  }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  var speed = parseFloat(body.getAttribute('data-vh-motion') || '1');
  var dpr = Math.min(2, window.devicePixelRatio || 1);

  /* 1. page transitions */
  var main = document.querySelector('.vh-main');
  document.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('a[href]'); if (!a || !main || reduced) return;
    var u = a.getAttribute('href'); if (!u || u.charAt(0) === '#' || a.target || a.hasAttribute('download') || a.hasAttribute('data-vh-drill') || a.origin !== location.origin) return;
    e.preventDefault(); main.style.transition = 'opacity .18s ease, transform .18s ease'; main.style.opacity = '0'; main.style.transform = 'translateY(-6px)';
    setTimeout(function () { location.href = u; }, 170);
  });

  /* 2. count-ups */
  function countUp(el) {
    var raw = el.textContent.trim(), m = raw.match(/^([^0-9]*)([0-9][0-9,]*)(.*)$/); if (!m) return;
    var to = parseInt(m[2].replace(/,/g, ''), 10); if (!isFinite(to) || to === 0) return;
    var pre = m[1], post = m[3], hasComma = m[2].indexOf(',') > -1, s = performance.now(), d = 1100 / speed;
    function step(n) { var k = Math.min(1, (n - s) / d), e = 1 - Math.pow(1 - k, 3), v = Math.round(to * e); el.textContent = pre + (hasComma ? v.toLocaleString() : v) + post; if (k < 1) requestAnimationFrame(step); }
    requestAnimationFrame(step);
  }
  if (!reduced) document.querySelectorAll('.vh-tile__value, .vh-card__value, .vh-flow__card-n, .vh-flow__n').forEach(countUp);

  /* 2b. reveal on scroll — widgets and list cards flow up into view.
     Only elements BELOW the fold at load are hidden then revealed, so
     above-the-fold content and no-JS/reduced-motion users never see a gap.
     A rAF-throttled scroll sweep reads positions directly (so fast scrolls
     and jump-to-anchor never skip a card), reveals in top-to-bottom order
     with a small stagger, and removes its own listeners once all are shown. */
  (function reveal() {
    if (reduced) return;
    var scope = document.querySelector('.vh-main') || document;
    var all = [].slice.call(scope.querySelectorAll('.vh-w, .vh-vendor, .vh-prodlist--full > .vh-prodrow'));
    if (!all.length) return;

    var vh0 = window.innerHeight || document.documentElement.clientHeight;
    var pending = [];
    all.forEach(function (el) {
      var r = el.getBoundingClientRect();
      if (r.top < vh0 - 40 && r.bottom > 0) return; // above the fold: keep native load animation
      el.classList.add('vh-reveal');
      pending.push(el);
    });
    if (!pending.length) return;

    var ticking = false;
    function sweep() {
      ticking = false;
      var vh = window.innerHeight || document.documentElement.clientHeight;
      var batch = [];
      for (var i = pending.length - 1; i >= 0; i--) {
        if (pending[i].getBoundingClientRect().top < vh * 0.92) { batch.push(pending[i]); pending.splice(i, 1); }
      }
      batch.sort(function (a, b) { return a.getBoundingClientRect().top - b.getBoundingClientRect().top; })
        .forEach(function (el, i) { el.style.transitionDelay = Math.min(i * 55, 300) + 'ms'; el.classList.add('vh-inview'); });
      if (!pending.length) { window.removeEventListener('scroll', onScroll); window.removeEventListener('resize', onScroll); }
    }
    function onScroll() { if (!ticking) { ticking = true; requestAnimationFrame(sweep); } }
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll, { passive: true });
    sweep();
  })();


  /* shared canvas helper */
  function canvasIn(host, draw, opts) {
    if (reduced) return;
    if (getComputedStyle(host).position === 'static') host.style.position = 'relative';
    var c = document.createElement('canvas'); c.className = 'vh-flow-canvas'; c.setAttribute('aria-hidden', 'true');
    if (opts && opts.opacity != null) c.style.opacity = opts.opacity;
    host.insertBefore(c, host.firstChild);
    var ctx = c.getContext('2d'), W = 1, H = 1, raf, visible = true;

    /* Browsers cap how large a canvas may be -- Firefox at 32767px a side,
       Chrome by total area -- and over the cap the canvas fails to allocate
       and paints as a broken image: an opaque grey box with a broken-image
       glyph in the corner. The products page is one card listing every
       product, which at 670 rows is ~53000px tall, so `inset: 0` made this
       backing store 107000px high at dpr 2 and greyed out the whole list.

       Clamp the backing store, and stop scaling the drawing by more than the
       clamp allows so the effect still lines up with the element. MAX is well
       under every browser's limit because a decorative wash on a card metres
       long is invisible anyway. */
    var MAX = 8192;

    function rs() {
      W = c.clientWidth || 1;
      H = c.clientHeight || 1;

      var scale = Math.min( dpr, MAX / Math.max( W, H, 1 ) );

      c.width  = Math.max( 1, Math.round( W * scale ) );
      c.height = Math.max( 1, Math.round( H * scale ) );
      c.dataset.scale = scale;
    }

    rs(); new ResizeObserver(rs).observe(c);
    if ('IntersectionObserver' in window) new IntersectionObserver(function (es) { visible = es[0].isIntersecting; }).observe(c);
    var t0 = performance.now(), state = {};
    (function loop(now) {
      raf = requestAnimationFrame(loop);
      if (!visible) return;
      // The transform follows the clamped scale, not dpr, or the drawing
      // would be laid out for a canvas larger than the one allocated.
      var k = parseFloat(c.dataset.scale) || dpr;
      ctx.setTransform(k, 0, 0, k, 0, 0);
      ctx.clearRect(0, 0, W, H);
      /* Math.max(0, ...): the first requestAnimationFrame timestamp is the
         frame's start time, which can be fractionally EARLIER than the
         performance.now() captured when this canvas was set up. That made
         elapsed time negative for one frame, and effects that wrap it with
         `% 1` inherited the sign -- JS keeps the dividend's -- so `ping`
         asked for a negative arc radius and threw. Invisible on a small
         card and very visible on a tall one, where the same tiny negative
         is multiplied by the element's height. */
      draw(ctx, W, H, Math.max(0, now - t0) * speed, state, (opts && opts.color) || accent);
    })(t0);
  }

  /* 3. widget-specific animations
     Keyed on data-vh-widget (the dashboard board) — every widget gets a motion that means
     something about its data. Unlisted widgets fall back to "lanes". Tiles/cards outside the
     board get "ping" (headline/KPI tiles) or "lanes" (everything else). */
  var SEV = { edge: '255,90,102', user: '255,154,60', inside: '94,163,255', critical: '255,90,102', high: '255,154,60', medium: '245,208,74', low: '94,163,255', good: '74,222,128' };
  var D = {
    /* horizontal particles on faint lanes — data arriving from connectors */
    lanes: function (n, lanes) { return function (ctx, W, H, t, st, col) {
      if (!st.ps) st.ps = Array.from({ length: n }, function (_, i) { return { l: i % lanes, x: Math.random(), v: 0.0006 + Math.random() * 0.0012, s: 0.6 + Math.random() }; });
      for (var l = 0; l < lanes; l++) { var y0 = H * (0.22 + 0.62 * l / Math.max(1, lanes - 1)); ctx.strokeStyle = 'rgba(' + col + ',0.07)'; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(0, y0); ctx.lineTo(W, y0); ctx.stroke(); }
      st.ps.forEach(function (p) { p.x += p.v * 1.6 * speed; if (p.x > 1.05) { p.x = -0.05; p.l = Math.floor(Math.random() * lanes); }
        var y = H * (0.22 + 0.62 * p.l / Math.max(1, lanes - 1)) + Math.sin(t * 0.002 + p.l) * 1.5, x = p.x * W;
        var g = ctx.createLinearGradient(x - 40 * p.s, y, x, y); g.addColorStop(0, 'rgba(' + col + ',0)'); g.addColorStop(1, 'rgba(' + col + ',0.35)');
        ctx.strokeStyle = g; ctx.lineWidth = 1.2; ctx.beginPath(); ctx.moveTo(x - 40 * p.s, y); ctx.lineTo(x, y); ctx.stroke();
        ctx.fillStyle = 'rgba(' + col + ',0.9)'; ctx.shadowColor = 'rgba(' + col + ',1)'; ctx.shadowBlur = 8; ctx.beginPath(); ctx.arc(x, y, 1.3 * p.s, 0, Math.PI * 2); ctx.fill(); ctx.shadowBlur = 0; }); }; },
    /* scanning band sweeping top→bottom — a table being re-read */
    scan: function (ctx, W, H, t, st, col) { var y = ((t * 0.00012) % 1) * (H + 60) - 30, g = ctx.createLinearGradient(0, y - 28, 0, y + 28); g.addColorStop(0, 'rgba(' + col + ',0)'); g.addColorStop(.5, 'rgba(' + col + ',0.10)'); g.addColorStop(1, 'rgba(' + col + ',0)'); ctx.fillStyle = g; ctx.fillRect(0, y - 28, W, 56); ctx.fillStyle = 'rgba(' + col + ',0.45)'; ctx.fillRect(0, y, W, 1); for (var x = 0; x < W; x += 24) { ctx.fillStyle = 'rgba(' + col + ',' + (0.25 + 0.25 * Math.sin(t * 0.004 + x)) + ')'; ctx.fillRect(x, y - 1, 6, 3); } },
    /* radar sweep with blips — what the scanner/sensor has seen */
    radar: function (ctx, W, H, t, st, col) { var cx = W * .78, cy = H * .55, R = Math.min(W, H) * .55, a = (t * .0009) % (Math.PI * 2); if (!st.b) st.b = Array.from({ length: 9 }, function () { return { r: .25 + Math.random() * .7, a: Math.random() * Math.PI * 2 }; }); for (var r = 1; r <= 3; r++) { ctx.strokeStyle = 'rgba(' + col + ',0.10)'; ctx.beginPath(); ctx.arc(cx, cy, R * r / 3, 0, Math.PI * 2); ctx.stroke(); } if (ctx.createConicGradient) { var g = ctx.createConicGradient(a, cx, cy); g.addColorStop(0, 'rgba(' + col + ',0.35)'); g.addColorStop(.18, 'rgba(' + col + ',0)'); g.addColorStop(1, 'rgba(' + col + ',0)'); ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.fill(); } ctx.strokeStyle = 'rgba(' + col + ',0.7)'; ctx.lineWidth = 1.2; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R); ctx.stroke(); st.b.forEach(function (b) { var d = (a - b.a + Math.PI * 2) % (Math.PI * 2), k = Math.max(0, 1 - d / 2.2); if (k > 0) { ctx.fillStyle = 'rgba(' + col + ',' + k + ')'; ctx.shadowColor = 'rgba(' + col + ',1)'; ctx.shadowBlur = 8 * k; ctx.beginPath(); ctx.arc(cx + Math.cos(b.a) * R * b.r, cy + Math.sin(b.a) * R * b.r, 2, 0, Math.PI * 2); ctx.fill(); ctx.shadowBlur = 0; } }); },
    /* slow falling streaks — time passing, rows streaming in */
    rain: function (ctx, W, H, t, st, col) { if (!st.p) st.p = Array.from({ length: 34 }, function () { return { x: Math.random(), y: Math.random(), v: .0003 + Math.random() * .0007, l: 10 + Math.random() * 26 }; }); st.p.forEach(function (p) { p.y += p.v * 8 * speed; if (p.y > 1.1) { p.y = -.1; p.x = Math.random(); } var x = p.x * W, y = p.y * H, g = ctx.createLinearGradient(x, y - p.l, x, y); g.addColorStop(0, 'rgba(' + col + ',0)'); g.addColorStop(1, 'rgba(' + col + ',0.5)'); ctx.strokeStyle = g; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(x, y - p.l); ctx.lineTo(x, y); ctx.stroke(); }); },
    /* breathing heat blooms in severity colours — where the risk concentrates */
    heat: function (ctx, W, H, t) { [[.72, .28, SEV.critical], [.55, .5, SEV.high], [.85, .7, SEV.low]].forEach(function (b, i) { var k = .6 + .4 * Math.sin(t * .0012 + i * 2), g = ctx.createRadialGradient(b[0] * W, b[1] * H, 0, b[0] * W, b[1] * H, 90 * k); g.addColorStop(0, 'rgba(' + b[2] + ',0.18)'); g.addColorStop(1, 'rgba(' + b[2] + ',0)'); ctx.fillStyle = g; ctx.fillRect(0, 0, W, H); }); },
    /* sonar rings from the right edge — waiting for a signal (tickets, exceptions, verification) */
    ping: function (ctx, W, H, t, st, col) { var cx = W * .92, cy = H * .5; for (var i = 0; i < 3; i++) { var k = ((t * .0004) + i / 3) % 1; ctx.strokeStyle = 'rgba(' + col + ',' + ((1 - k) * .5) + ')'; ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(cx, cy, 6 + k * Math.max(W, H) * .7, 0, Math.PI * 2); ctx.stroke(); } ctx.fillStyle = 'rgba(' + col + ',0.9)'; ctx.shadowColor = 'rgba(' + col + ',1)'; ctx.shadowBlur = 10; ctx.beginPath(); ctx.arc(cx, cy, 2.5, 0, Math.PI * 2); ctx.fill(); ctx.shadowBlur = 0; },
    /* live EKG trace that keeps scrolling — a number that is changing right now */
    ticker: function (ctx, W, H, t, st, col) { if (!st.pts) { st.pts = Array.from({ length: 60 }, Math.random); st.last = 0; } if (t - st.last > 140) { st.last = t; st.pts.push(Math.max(0, Math.min(1, st.pts[59] + (Math.random() - .5) * .5))); st.pts.shift(); } var sh = ((t - st.last) / 140) * (W / 59); ctx.beginPath(); st.pts.forEach(function (p, i) { var x = (i / 59) * W - sh + W / 59, y = H * .92 - p * H * .5; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }); ctx.strokeStyle = 'rgba(' + col + ',0.55)'; ctx.lineWidth = 1.4; ctx.shadowColor = 'rgba(' + col + ',1)'; ctx.shadowBlur = 6; ctx.stroke(); ctx.shadowBlur = 0; ctx.lineTo(W, H); ctx.lineTo(0, H); ctx.closePath(); var g = ctx.createLinearGradient(0, H * .4, 0, H); g.addColorStop(0, 'rgba(' + col + ',0.14)'); g.addColorStop(1, 'rgba(' + col + ',0)'); ctx.fillStyle = g; ctx.fill(); },
    /* slow rotating dashed ring behind donuts — the mix being re-sampled */
    orbitRing: function (ctx, W, H, t, st, col) { var cx = W * .22, cy = H * .6, R = Math.min(W, H) * .42; ctx.save(); ctx.translate(cx, cy); ctx.rotate(t * .0003); ctx.setLineDash([3, 9]); ctx.strokeStyle = 'rgba(' + col + ',0.25)'; ctx.beginPath(); ctx.arc(0, 0, R, 0, Math.PI * 2); ctx.stroke(); ctx.rotate(-t * .0007); ctx.setLineDash([1, 14]); ctx.strokeStyle = 'rgba(' + col + ',0.18)'; ctx.beginPath(); ctx.arc(0, 0, R * 1.18, 0, Math.PI * 2); ctx.stroke(); ctx.restore(); ctx.setLineDash([]); },
    /* sand trickling down through a funnel — findings narrowing to what matters */
    funnel: function (ctx, W, H, t, st, col) { if (!st.p) st.p = Array.from({ length: 40 }, function () { return { y: Math.random(), x: Math.random() * 2 - 1, v: .0004 + Math.random() * .0006 }; }); st.p.forEach(function (p) { p.y += p.v * 8 * speed; if (p.y > 1) { p.y = 0; p.x = Math.random() * 2 - 1; } var w = (1 - p.y * .8), x = W * .82 + p.x * w * W * .14, y = p.y * H; ctx.fillStyle = 'rgba(' + col + ',' + (.3 + .5 * p.y) + ')'; ctx.fillRect(x, y, 1.5, 4); }); },
    /* countdown ticks sweeping — things about to expire */
    countdown: function (ctx, W, H, t, st, col) { var cx = W * .86, cy = H * .5, R = Math.min(W, H) * .42, a = (t * .0006) % (Math.PI * 2); for (var i = 0; i < 24; i++) { var b = i / 24 * Math.PI * 2, on = ((b - a + Math.PI * 2) % (Math.PI * 2)) < Math.PI * .5; ctx.strokeStyle = 'rgba(' + col + ',' + (on ? .5 : .12) + ')'; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(cx + Math.cos(b) * R * .85, cy + Math.sin(b) * R * .85); ctx.lineTo(cx + Math.cos(b) * R, cy + Math.sin(b) * R); ctx.stroke(); } },
    /* flowing link from ticket to verdict — tickets moving through the pipeline */
    pipeline: function (ctx, W, H, t, st, col) { var y = H * .5; ctx.strokeStyle = 'rgba(' + col + ',0.10)'; ctx.setLineDash([6, 8]); ctx.lineDashOffset = -t * .03; ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); ctx.setLineDash([]); [0.15, 0.5, 0.85].forEach(function (x, i) { var k = .5 + .5 * Math.sin(t * .003 - i * 1.2); ctx.fillStyle = 'rgba(' + col + ',' + (.3 + .5 * k) + ')'; ctx.shadowColor = 'rgba(' + col + ',1)'; ctx.shadowBlur = 8 * k; ctx.beginPath(); ctx.arc(x * W, y, 3 + 2 * k, 0, Math.PI * 2); ctx.fill(); ctx.shadowBlur = 0; }); },
    /* constellation of assets, links pulsing between systems that know the same machine */
    mesh: function (ctx, W, H, t, st, col) { if (!st.n) st.n = Array.from({ length: 16 }, function () { return { x: .55 + Math.random() * .42, y: .1 + Math.random() * .8 }; }); ctx.lineWidth = 1; st.n.forEach(function (a, i) { st.n.forEach(function (b, j) { if (j <= i) return; var d = Math.hypot(a.x - b.x, a.y - b.y); if (d < .22) { ctx.strokeStyle = 'rgba(' + col + ',' + ((.22 - d) * 1.2 * (.5 + .5 * Math.sin(t * .002 + i))) + ')'; ctx.beginPath(); ctx.moveTo(a.x * W, a.y * H); ctx.lineTo(b.x * W, b.y * H); ctx.stroke(); } }); ctx.fillStyle = 'rgba(' + col + ',0.7)'; ctx.beginPath(); ctx.arc(a.x * W, a.y * H, 1.5, 0, Math.PI * 2); ctx.fill(); }); },
    /* fading horizon lines — support ending, dates receding */
    horizon: function (ctx, W, H, t, st, col) { for (var i = 0; i < 6; i++) { var k = ((t * .00008) + i / 6) % 1, y = H * (.2 + k * .75); ctx.strokeStyle = 'rgba(' + col + ',' + ((1 - k) * .18) + ')'; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(W * (.5 - k * .5), y); ctx.lineTo(W * (.5 + k * .5), y); ctx.stroke(); } }
  };
  /* widget id → [drawer, colour override, opacity] */
  var MAP = {
    headline: null,                        /* tiles inside get their own (see below) */
    attack_paths: null,                    /* handled by section 5 (particles on the routes) */
    severity_age: ['scan', null, 1], trend: ['ticker', null, .5], severity_mix: ['orbitRing', null, .8],
    patch_availability: null,              /* CSS shimmer on the bars (.vh-minibar) */
    age_buckets: ['rain', null, .5], exploit_funnel: ['funnel', null, .7],
    top_vulns: null,                       /* spotlight cycles rows, see below */
    top_assets: ['heat', null, 1], os_mix: ['mesh', null, .6], family_mix: ['mesh', null, .6], assets_by_type: ['mesh', null, .6],
    team_exposure: ['heat', null, 1], ownership_gaps: ['ping', SEV.high, .35],
    coverage_summary: ['radar', null, .5], coverage_by_type: ['radar', null, .35], coverage_by_site: ['radar', null, .35], coverage_by_source: ['radar', null, .35], coverage_cmdb: ['radar', null, .35], coverage_gaps: ['scan', SEV.critical, .8], coverage_gaps_cmdb: ['scan', SEV.critical, .8],
    defender_summary: ['radar', SEV.good, .5], defender_by_type: ['radar', SEV.good, .35], defender_by_source: ['radar', SEV.good, .35], defender_cmdb: ['radar', SEV.good, .35], defender_gaps: ['scan', SEV.critical, .8], defender_gaps_cmdb: ['scan', SEV.critical, .8],
    eol_platforms: ['horizon', SEV.high, 1], eol_software: ['horizon', SEV.high, 1], eol_hardware: ['horizon', SEV.high, 1],
    remediation_health: ['pipeline', SEV.good, .8], verification: ['ping', SEV.medium, .4], ticket_flow: ['pipeline', null, .8], exceptions_expiring: ['countdown', SEV.medium, .8]
  };
  function drawerFor(name) { return name === 'lanes' ? D.lanes(14, 4) : D[name]; }
  document.querySelectorAll('[data-vh-widget]').forEach(function (w) {
    var k = w.getAttribute('data-vh-widget'); if (!(k in MAP)) MAP[k] = ['lanes', null, .3];
    var m = MAP[k]; if (!m) return; canvasIn(w, drawerFor(m[0]), { color: m[1], opacity: m[2] });
  });
  /* headline / KPI tiles: colour from the tile's severity modifier, motion from what the number means */
  document.querySelectorAll('.vh-tile, .vh-card[class*="vh-card--"]').forEach(function (el, i) {
    var c = el.className, col = /critical|crit|bad/.test(c) ? SEV.critical : /serious|high/.test(c) ? SEV.high : /warning|warn|med/.test(c) ? SEV.medium : /good|ok/.test(c) ? SEV.good : accent;
    var label = (el.querySelector('.vh-tile__label, .vh-card__label') || {}).textContent || '';
    var d = /scan|coverage|not scanned/i.test(label) ? 'radar' : /still detected|disagree/i.test(label) ? 'heat' : /critical/i.test(label) ? 'ticker' : 'ping';
    canvasIn(el, drawerFor(d), { color: col, opacity: d === 'ticker' ? .5 : .35 });
  });
  /* remaining cards outside the board (admin screens): quiet lanes */
  document.querySelectorAll('.vh-card:not([class*="vh-card--"]), .vh-connector').forEach(function (el, i) { if (i % 2 === 0) canvasIn(el, D.lanes(8, 3), { opacity: .3 }); });
  /* top_vulns spotlight: highlight one row at a time */
  document.querySelectorAll('[data-vh-widget="top_vulns"] .vh-list__row, [data-vh-widget="top_vulns"] li').forEach(function (r) { r.style.transition = 'background .6s, box-shadow .6s'; });
  (function () { var rows = document.querySelectorAll('[data-vh-widget="top_vulns"] .vh-list__row, [data-vh-widget="top_vulns"] li'); if (!rows.length || reduced) return; var i = 0; setInterval(function () { rows.forEach(function (r, j) { var on = j === i; r.style.background = on ? 'rgba(' + accent + ',.08)' : ''; r.style.boxShadow = on ? 'inset 2px 0 0 rgb(' + accent + ')' : ''; }); i = (i + 1) % rows.length; }, 1400 / speed); })();
  /* patch availability bars shimmer; team exposure bars breathe (CSS classes from app.css) */
  document.querySelectorAll('[data-vh-widget="patch_availability"] .vh-minibar > *, [data-vh-widget="patch_availability"] .vh-bars__fill').forEach(function (b) { b.classList.add('vh-fx-shimmer'); });
  document.querySelectorAll('[data-vh-widget="team_exposure"] .vh-bars__fill, [data-vh-widget="team_exposure"] .vh-minibar > *').forEach(function (b, i) { b.classList.add('vh-fx-breathe'); b.style.animationDuration = (2.4 + i * .4) + 's'; });
  /* attack path route dots pulse */
  document.querySelectorAll('.vh-flow__dot, .vh-flow__card-n').forEach(function (d) { d.classList.add('vh-fx-pulse'); });

  /* 4. empty-state orbits */
  document.querySelectorAll('.vh-chart-empty, .vh-empty').forEach(function (el) {
    canvasIn(el, function (ctx, W, H, t) {
      var cx = W / 2, cy = H / 2;
      for (var r = 1; r <= 3; r++) { var rad = 40 + r * 34, a = t * 0.0004 * (r % 2 ? 1 : -1) + r; ctx.strokeStyle = 'rgba(' + accent + ',' + (0.12 - r * 0.02) + ')'; ctx.setLineDash([2, 6]); ctx.beginPath(); ctx.arc(cx, cy, rad, 0, Math.PI * 2); ctx.stroke(); ctx.setLineDash([]); ctx.fillStyle = 'rgba(' + accent + ',0.7)'; ctx.shadowColor = 'rgba(' + accent + ',1)'; ctx.shadowBlur = 8; ctx.beginPath(); ctx.arc(cx + Math.cos(a) * rad, cy + Math.sin(a) * rad, 1.8, 0, Math.PI * 2); ctx.fill(); ctx.shadowBlur = 0; }
    }, { opacity: 1 });
  });

  /* 5. attack-path particles: follow the existing SVG <path class="vh-flow__line ..."> geometry */
  document.querySelectorAll('.vh-flow__stage').forEach(function (stage) {
    var svg = stage.querySelector('svg'); if (!svg) return;
    var lines = Array.from(svg.querySelectorAll('.vh-flow__line')); if (!lines.length) return;
    var cols = { edge: '255,90,102', user: '255,154,60', inside: '94,163,255' };
    canvasIn(stage, function (ctx, W, H, t, st) {
      var sb = svg.getBoundingClientRect(), hb = stage.getBoundingClientRect(), vb = svg.viewBox.baseVal, sx = sb.width / (vb.width || sb.width), sy = sb.height / (vb.height || sb.height), ox = sb.left - hb.left, oy = sb.top - hb.top;
      if (!st.ps) st.ps = lines.flatMap(function (ln, i) { return Array.from({ length: 16 }, function () { return { i: i, t: Math.random(), v: 0.0015 + Math.random() * 0.002 }; }); });
      st.ps.forEach(function (p) {
        var ln = lines[p.i], L = ln.getTotalLength(); p.t += p.v * 1.6 * speed; if (p.t > 1) p.t = 0;
        var q = ln.getPointAtLength(p.t * L), k = ln.className.baseVal.match(/vh-flow__line--(\w+)/), col = cols[k ? k[1] : 'edge'] || accent;
        ctx.fillStyle = 'rgba(' + col + ',' + (0.5 + 0.5 * Math.sin(p.t * Math.PI)) + ')'; ctx.shadowColor = 'rgba(' + col + ',1)'; ctx.shadowBlur = 6; ctx.beginPath(); ctx.arc(ox + q.x * sx, oy + q.y * sy, 1.6, 0, Math.PI * 2); ctx.fill(); ctx.shadowBlur = 0;
      });
    }, { opacity: 1 });
    stage.querySelector('.vh-flow-canvas').style.zIndex = 1;
  });

  /* 7. OS badges — replaces the text inside .vh-os with an original glyph (no vendor logos); keeps the text as aria-label */
  var OS = { rhel: ['255,90,102', 'M5 15c2-1 3-5 7-5s5 4 7 5c-2 2-12 2-14 0z'], win: ['94,163,255', 'M5 6.5l6-1v6H5zM12 5.3l7-1.3v7.5h-7zM5 12.5h6v6l-6-1zM12 12.5h7V20l-7-1.3z'], ubuntu: ['255,154,60', 'M12 12m-5.5 0a5.5 5.5 0 1 0 11 0a5.5 5.5 0 1 0-11 0M12 4.6v2M5.6 15.7l1.7-1M18.4 15.7l-1.7-1'], linux: ['245,208,74', 'M6 7l4 5-4 5M12 17h6'], mac: ['200,210,230', 'M6 17V7l6 6 6-6v10'], esx: ['160,150,255', 'M4 7h16v10H4zM4 12h16M12 7v10'], other: ['125,138,163', 'M12 8v5m0 3v.5'] };
  function osKind(s) { s = s.toLowerCase(); return /red ?hat|rhel|^rh$/.test(s) ? 'rhel' : /win/.test(s) ? 'win' : /ubuntu/.test(s) ? 'ubuntu' : /mac|darwin|ios/.test(s) ? 'mac' : /esx|vmware/.test(s) ? 'esx' : /linux|rocky|alma|centos|debian|suse|lx/.test(s) ? 'linux' : 'other'; }
  document.querySelectorAll('.vh-os').forEach(function (el) {
    if (el.querySelector('.vh-os__logo, img, .vh-os__text')) { return; } // labelled badge (logo/name) from PHP — leave it readable
    var txt = el.textContent.trim(), full = el.getAttribute('title') || (el.nextSibling && el.nextSibling.textContent) || txt, k = OS[osKind(full + ' ' + txt)];
    el.setAttribute('aria-label', full); el.setAttribute('title', full); el.textContent = '';
    el.style.cssText += ';width:24px;height:24px;border-radius:7px;display:inline-grid;place-items:center;background:rgba(' + k[0] + ',.14);border:1px solid rgba(' + k[0] + ',.4);color:rgb(' + k[0] + ');box-shadow:0 0 10px rgba(' + k[0] + ',.18)';
    el.innerHTML = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="' + k[1] + '"/></svg>';
  });

  /* 6. hover spotlight */
  if (!reduced) document.querySelectorAll('.vh-card, .vh-tile, .vh-w, .vh-connector, .vh-panel').forEach(function (el) {
    var glow = document.createElement('span'); glow.setAttribute('aria-hidden', 'true');
    var paint = function () {
      glow.style.cssText = 'position:absolute;inset:0;pointer-events:none;opacity:' + (glow.style.opacity || '0') + ';transition:opacity .3s;z-index:0;background:radial-gradient(240px circle at var(--mx,50%) var(--my,50%),rgba(' + accent + ',.10),transparent 60%)';
    };
    paint();
    glows.push(paint);
    el.insertBefore(glow, el.firstChild);
    el.addEventListener('mousemove', function (e) { var b = el.getBoundingClientRect(); glow.style.setProperty('--mx', (e.clientX - b.left) + 'px'); glow.style.setProperty('--my', (e.clientY - b.top) + 'px'); glow.style.opacity = '1'; });
    el.addEventListener('mouseleave', function () { glow.style.opacity = '0'; });
  });
})();
