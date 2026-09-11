/* attack-surface-bg.js — vanilla JS, drop into WordPress via Elementor HTML widget or enqueue as a theme script.
   Usage: <canvas id="asm-bg"></canvas> positioned absolute/fixed behind the page, then:
   AttackSurfaceBG(document.getElementById('asm-bg'), { speed: 1, palette: 'cyan', threats: true }); */
function AttackSurfaceBG(c, opts) {
  opts = opts || {};
  const self = { props: { speed: opts.speed ?? 1, palette: opts.palette ?? 'cyan', threats: opts.threats ?? true }, raf: 0, ro: null };
  const palette = () => ({ cyan: '94,224,255', emerald: '96,255,190', violet: '176,150,255' }[self.props.palette] || '94,224,255');
  (function () {
    const ctx = c.getContext('2d');
    const N = 280, pts = [], golden = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < N; i++) { const y = 1 - (i / (N - 1)) * 2, r = Math.sqrt(1 - y * y), t = golden * i; pts.push([Math.cos(t) * r, y, Math.sin(t) * r]); }
    const edges = [];
    for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) { const d = Math.hypot(pts[i][0] - pts[j][0], pts[i][1] - pts[j][1], pts[i][2] - pts[j][2]); if (d < 0.27) edges.push([i, j]); }
    const dust = Array.from({ length: 70 }, () => ({ x: Math.random(), y: Math.random(), s: 0.2 + Math.random() * 0.8, v: 0.00002 + Math.random() * 0.00005 }));
    const threats = []; let lastThreat = 0;
    let W = 1, H = 1, dpr = 1;
    const resize = () => { dpr = Math.min(2, window.devicePixelRatio || 1); W = c.clientWidth || 1; H = c.clientHeight || 1; c.width = W * dpr; c.height = H * dpr; };
    resize(); self.ro = new ResizeObserver(resize); self.ro.observe(c);
    const proj = new Array(N);
    const rot = (p, ry, rx) => {
      const cy = Math.cos(ry), sy = Math.sin(ry), cx = Math.cos(rx), sx = Math.sin(rx);
      const x1 = p[0] * cy + p[2] * sy, z1 = -p[0] * sy + p[2] * cy;
      const y1 = p[1] * cx - z1 * sx, z2 = p[1] * sx + z1 * cx;
      return [x1, y1, z2];
    };
    const t0 = performance.now();
    const loop = (now) => {
      self.raf = requestAnimationFrame(loop);
      const speed = self.props.speed ?? 1, col = palette(), showThreats = self.props.threats ?? true;
      const t = (now - t0) * speed;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
      const cx = W * 0.5, cy = H * 0.5, R = Math.min(W, H) * 0.34;
      const ry = t * 0.00016, rx = 0.42 + Math.sin(t * 0.00007) * 0.08;
      // halo
      const g = ctx.createRadialGradient(cx, cy, R * 0.2, cx, cy, R * 1.6);
      g.addColorStop(0, `rgba(${col},0.10)`); g.addColorStop(0.6, `rgba(${col},0.03)`); g.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);
      // dust
      for (const d of dust) { d.y -= d.v * speed * 16; if (d.y < 0) { d.y = 1; d.x = Math.random(); } ctx.fillStyle = `rgba(${col},${0.12 * d.s})`; ctx.fillRect(d.x * W, d.y * H, d.s * 1.6, d.s * 1.6); }
      // project
      const f = (z) => 2.4 / (2.4 - z);
      for (let i = 0; i < N; i++) { const [x, y, z] = rot(pts[i], ry, rx); const k = f(z); proj[i] = [cx + x * R * k, cy - y * R * k, (z + 1) / 2, y]; }
      // scan latitude
      const scanY = Math.sin(t * 0.00045);
      // edges
      ctx.lineWidth = 0.8;
      for (const [i, j] of edges) { const a = proj[i], b = proj[j]; const dp = (a[2] + b[2]) / 2; const al = 0.04 + dp * dp * 0.3; ctx.strokeStyle = `rgba(${col},${al})`; ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.lineTo(b[0], b[1]); ctx.stroke(); }
      // scan ring
      ctx.beginPath(); let first = true;
      const sr = Math.sqrt(Math.max(0, 1 - scanY * scanY));
      for (let k = 0; k <= 96; k++) { const a = (k / 96) * Math.PI * 2; const [x, y, z] = rot([Math.cos(a) * sr, scanY, Math.sin(a) * sr], ry, rx); const kk = f(z); const px = cx + x * R * kk, py = cy - y * R * kk; if (first) { ctx.moveTo(px, py); first = false; } else ctx.lineTo(px, py); }
      ctx.strokeStyle = `rgba(${col},0.35)`; ctx.lineWidth = 1; ctx.stroke();
      // nodes
      for (let i = 0; i < N; i++) { const [px, py, dp, y] = proj[i]; const near = Math.max(0, 1 - Math.abs(y - scanY) / 0.08); const r = 0.9 + dp * 1.6 + near * 1.8; ctx.fillStyle = `rgba(${col},${0.18 + dp * 0.7 + near * 0.3})`; ctx.beginPath(); ctx.arc(px, py, r, 0, Math.PI * 2); ctx.fill(); if (near > 0.5) { ctx.fillStyle = `rgba(${col},${near * 0.15})`; ctx.beginPath(); ctx.arc(px, py, r * 3, 0, Math.PI * 2); ctx.fill(); } }
      // orbital ring
      ctx.beginPath(); first = true;
      for (let k = 0; k <= 128; k++) { const a = (k / 128) * Math.PI * 2; const [x, y, z] = rot([Math.cos(a) * 1.45, 0, Math.sin(a) * 1.45], t * 0.00005, rx + 0.9); const kk = f(z * 0.5); const px = cx + x * R * kk, py = cy - y * R * kk; if (first) { ctx.moveTo(px, py); first = false; } else ctx.lineTo(px, py); }
      ctx.setLineDash([2, 6]); ctx.strokeStyle = `rgba(${col},0.22)`; ctx.lineWidth = 1; ctx.stroke(); ctx.setLineDash([]);
      { const a = t * 0.0006; const [x, y, z] = rot([Math.cos(a) * 1.45, 0, Math.sin(a) * 1.45], t * 0.00005, rx + 0.9); const kk = f(z * 0.5); const px = cx + x * R * kk, py = cy - y * R * kk; ctx.fillStyle = `rgba(${col},0.9)`; ctx.shadowColor = `rgba(${col},1)`; ctx.shadowBlur = 12; ctx.beginPath(); ctx.arc(px, py, 2.2, 0, Math.PI * 2); ctx.fill(); ctx.shadowBlur = 0; }
      // threats
      if (showThreats) {
        if (now - lastThreat > 1900 / speed) { lastThreat = now; const labels = ['P1 · MAPPED', 'CVE LINKED', 'TICKET RAISED', 'EXCEPTION', 'HIGH IMPACT']; threats.push({ i: Math.floor(Math.random() * N), t0: now, label: labels[Math.floor(Math.random() * labels.length)] }); }
        for (let k = threats.length - 1; k >= 0; k--) { const th = threats[k]; const age = (now - th.t0) / 3200; if (age > 1) { threats.splice(k, 1); continue; } const [px, py, dp] = proj[th.i]; if (dp < 0.35) continue; const fade = 1 - age; ctx.strokeStyle = `rgba(255,90,102,${fade * 0.6})`; ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(px, py, 4 + age * 36, 0, Math.PI * 2); ctx.stroke(); ctx.strokeStyle = `rgba(255,90,102,${fade * 0.25})`; ctx.beginPath(); ctx.arc(px, py, 4 + age * 60, 0, Math.PI * 2); ctx.stroke(); ctx.fillStyle = `rgba(255,90,102,${0.5 + fade * 0.5})`; ctx.shadowColor = 'rgba(255,90,102,1)'; ctx.shadowBlur = 14; ctx.beginPath(); ctx.arc(px, py, 2.6, 0, Math.PI * 2); ctx.fill(); ctx.shadowBlur = 0; if (age < 0.7) { ctx.fillStyle = `rgba(255,140,150,${(0.7 - age) * 1.2})`; ctx.font = '10px "JetBrains Mono", monospace'; ctx.fillText(th.label, px + 10, py - 8); } }
      }
    };
    self.raf = requestAnimationFrame(loop);
  })();
  return { destroy() { cancelAnimationFrame(self.raf); if (self.ro) self.ro.disconnect(); }, set(p) { Object.assign(self.props, p); } };
}
