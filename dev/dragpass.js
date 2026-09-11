/*
 * Carrying a dashboard widget.
 *
 * Three things have to be true for a drag to feel like picking something up:
 * the widget travels with the pointer, a gap shows where it will land, and
 * the page comes to you when you carry it past an edge.
 *
 * Two of the bugs this covers were invisible in the inline style:
 *
 *  - `.vh-w` carries `animation: vhIn .5s both`, whose final keyframe is
 *    `transform: none`. A filled animation outranks an inline style, so the
 *    per-frame transform computed to the identity matrix and the widget sat
 *    at 0,0 while style.transform read translate3d(345px, 277px, 0).
 *  - The gap changes the height of content above the viewport, and Chrome's
 *    scroll anchoring answers that by moving scrollY -- which fought the edge
 *    auto-scroll and drifted the page 447px the wrong way.
 *
 * The scaffolding here is deliberate, not incidental. The dashboard opens on
 * a hero, so at scroll 0 no widget is on screen at all; the board repacks
 * after a scroll, so a rect measured too early puts the press on the wrong
 * element; and hovering the gap itself is a no-op by design. Every one of
 * those produced a confident failure against working code before it was
 * understood.
 */
const fs = require('fs');
const { chromium } = require('playwright');
const BASE = 'http://localhost:8093';
let pass = 0, fail = 0;
const ok = (n,d)=>{pass++;console.log(`ok    ${n}${d?'  — '+d:''}`);};
const bad = (n,d)=>{fail++;console.log(`FAIL  ${n}${d?'  — '+d:''}`);};

/* A widget whose midpoint is actually inside the viewport. elementFromPoint
 * answers null for anything below the fold, which silently turns every drop
 * test into a no-op -- the first version of this file did exactly that and
 * blamed the application. */
const onscreen = (page, skip) => page.evaluate((skip) => {
  const h = window.innerHeight;
  const ws = [...document.querySelectorAll('.vh-w:not(.is-dragging)')]
    .map(w => ({ w, r: w.getBoundingClientRect() }))
    // Only the sample points need to be on screen. Requiring the whole box
    // to fit excluded every widget on a board of tall cards.
    // The sample points must be on screen; the whole card need not be. Some
    // widgets here are 849px tall in a 900px window.
    .filter(({ r }) => {
      const a = r.top + Math.min(r.height * 0.25, 80);
      const bt = r.top + Math.min(r.height * 0.75, r.height - 20);
      return a > 110 && a < h - 160 && bt > 110 && bt < h - 160 && bt - a > 20;
    });
  const pick = ws[Math.min(skip, ws.length - 1)];
  if (!pick) return null;
  return { id: pick.w.getAttribute('data-vh-widget'),
           x: Math.round(pick.r.left + pick.r.width / 2),
           yTop: Math.round(pick.r.top + Math.min(pick.r.height * 0.25, 80)),
           yBot: Math.round(pick.r.top + Math.min(pick.r.height * 0.75, pick.r.height - 20)) };
}, skip);

const ghostSlot = page => page.evaluate(() => {
  const b = document.querySelector('[data-vh-board]');
  const g = document.querySelector('.vh-w-ghost');
  return g ? [].indexOf.call(b.children, g) : -1;
});

(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', e => errs.push(String(e).slice(0,160)));
  page.on('console', m => { if (m.type()==='error') errs.push(m.text().slice(0,160)); });

  const pw = fs.readFileSync('/srv/vulnhub/.admin_pass','utf8').trim();
  await page.goto(`${BASE}/sign-in/`, { waitUntil: 'domcontentloaded' });
  await page.fill('input[name="log"], #user_login, input[name="username"]', 'romy');
  await page.fill('input[type="password"]', pw);
  await page.click('button[type="submit"]', { noWaitAfter: true });
  await page.waitForURL(u => !String(u).includes('sign-in'), { timeout: 90000 });
  await page.goto(BASE + '/', { waitUntil: 'networkidle' });

  const before = await page.$$eval('[data-vh-widget]', els => els.map(e => e.getAttribute('data-vh-widget')));
  ok('board rendered', `${before.length} widgets`);

  /* Put a real widget in the middle of the window before touching anything.
   *
   * Two traps, both of which produced failures the application did not have:
   * the dashboard opens on a hero, so at scroll 0 the first widget starts at
   * y=915 in a 900px window and there is nothing on screen to drag or drop
   * onto; and a grip parked near the top edge sits inside the auto-scroll
   * zone, so the drag correctly scrolls the page to 0 the moment it arms. */
  const gripHandle = await page.evaluateHandle(() => {
    const grips = [...document.querySelectorAll('[data-vh-grip]')];
    const g = grips[2] || grips[0];
    const w = g.closest('.vh-w');
    const r = w.getBoundingClientRect();
    window.scrollTo(0, Math.round(r.top + window.scrollY - (window.innerHeight - r.height) / 2));
    return g;
  });
  const grip = gripHandle.asElement();

  /* Wait for the board to stop moving before measuring.
   *
   * pack() is debounced and re-runs on scroll, so the grip's rect right after
   * a scrollTo is not the rect it will have a frame later. Measuring too
   * early put the press on `.vh-w__head` instead of the grip, and the drag
   * simply never started -- which looks exactly like a broken feature. */
  let gb = null;
  for (let i = 0; i < 20; i++) {
    await page.waitForTimeout(120);
    const now = await grip.boundingBox();
    if (gb && now && Math.abs(now.y - gb.y) < 0.5 && Math.abs(now.x - gb.x) < 0.5) { gb = now; break; }
    gb = now;
  }
  if (!gb) { bad('grip is measurable'); await b.close(); process.exit(1); }
  await page.mouse.move(gb.x + gb.width/2, gb.y + gb.height/2);
  await page.mouse.down();
  await page.mouse.move(gb.x + 60, gb.y + 40, { steps: 8 });

  const lifted = await page.evaluate(() => {
    const w = document.querySelector('.vh-w.is-dragging');
    if (!w) return null;
    const cs = getComputedStyle(w);
    return { parent: w.parentElement.tagName, position: cs.position, pe: cs.pointerEvents,
             animation: cs.animationName,
             ghost: !!document.querySelector('.vh-w-ghost'),
             body: document.body.classList.contains('vh-is-dragging') };
  });
  lifted ? ok('widget lifts out of the grid') : bad('widget lifts');
  (lifted && lifted.position === 'fixed' && lifted.parent === 'BODY')
    ? ok('lifted to <body>, out of reach of .vh-main\'s transform') : bad('lifted to body', lifted && lifted.parent);
  (lifted && lifted.animation === 'none')
    ? ok('vhIn is suppressed, so the inline transform is not overruled') : bad('vhIn suppressed', lifted && lifted.animation);
  (lifted && lifted.ghost) ? ok('a ghost holds the space it came from') : bad('ghost exists');
  (lifted && lifted.pe === 'none') ? ok('the pointer reaches the board through it') : bad('pointer-events none');

  const samples = [];
  for (const [dx, dy] of [[200,120],[420,240],[300,360]]) {
    await page.mouse.move(gb.x + dx, gb.y + dy, { steps: 6 });
    samples.push(await page.evaluate(() => {
      const r = document.querySelector('.vh-w.is-dragging').getBoundingClientRect();
      return { l: Math.round(r.left), t: Math.round(r.top) };
    }));
  }
  const distinct = new Set(samples.map(s => s.l + ',' + s.t)).size;
  (distinct === samples.length) ? ok('it travels with the mouse', samples.map(s=>`${s.l},${s.t}`).join(' -> '))
                                : bad('it travels with the mouse', JSON.stringify(samples));

  const stuck = await page.evaluate(([gx, gy]) => {
    const r = document.querySelector('.vh-w.is-dragging').getBoundingClientRect();
    return gx >= r.left - 2 && gx <= r.right + 2 && gy >= r.top - 2 && gy <= r.bottom + 2;
  }, [gb.x + 300, gb.y + 360]);
  stuck ? ok('the cursor stays inside the carried widget') : bad('cursor stays inside the widget');

  /* --- the gap tracks the pointer ---
   *
   * Sampled at two heights in the window rather than two points inside one
   * card. Some widgets on this board are 849px tall in a 900px window, so
   * "a quarter and three quarters of the way down the card" is not a pair of
   * on-screen coordinates at all. */
  const t1 = { x: Math.round(1440 / 2) };
  const draggedId = await page.evaluate(() => document.querySelector('.vh-w.is-dragging').getAttribute('data-vh-widget'));

  /* Sweep down the window and note which widget is under the pointer at each
   * stop, then aim at a named one.
   *
   * Hovering the ghost itself is a no-op by design -- you are already over
   * the gap -- so a sweep can legitimately report "the gap did not move" if
   * it happens to pass down the column the gap occupies. Landing next to a
   * widget we can name is the assertion that means something. */
  let target = null;
  for (const y of [140, 300, 460, 620, 770]) {
    await page.mouse.move(t1.x, y, { steps: 8 });
    await page.waitForTimeout(200);
    const id = await page.evaluate(y => {
      const e = document.elementFromPoint(720, y);
      const w = e && e.closest ? e.closest('.vh-w') : null;
      return w ? w.getAttribute('data-vh-widget') : null;
    }, y);
    if (id && id !== draggedId) { target = { id, y }; }
  }

  if (!target) { bad('found a widget to drop next to'); }
  else {
    await page.mouse.move(t1.x, target.y, { steps: 8 });
    await page.waitForTimeout(280);
    const beside = await page.evaluate(id => {
      const board = document.querySelector('[data-vh-board]');
      const g = document.querySelector('.vh-w-ghost');
      const t = board.querySelector(`[data-vh-widget="${id}"]`);
      const kids = [...board.children];
      return { gap: kids.indexOf(g), target: kids.indexOf(t) };
    }, target.id);
    (Math.abs(beside.gap - beside.target) === 1)
      ? ok(`the gap opens next to ${target.id}`, `gap ${beside.gap}, target ${beside.target}`)
      : bad('gap opens beside the hovered widget', JSON.stringify(beside) + ' ' + target.id);
  }

  // --- auto-scroll, held still at each edge ---
  /* Both edges are measured from the moment the pointer *arrives*, not from
   * before the move. The pointer travels through the edge zone on its way
   * across, so a reading taken beforehand includes scrolling that the hold
   * being tested did not cause -- which is how an earlier run of this file
   * "proved" that dragging to the top edge scrolled the page downwards. */
  const scrollY = () => page.evaluate(() => window.scrollY);
  const X = t1 ? t1.x : 700;

  await page.mouse.move(X, 870, { steps: 4 });
  const atBottom = await scrollY();
  await page.waitForTimeout(800);
  const yDown = await scrollY();
  (yDown > atBottom + 40) ? ok('holding at the bottom edge scrolls down', `${atBottom} -> ${yDown}`)
                          : bad('auto-scroll down', `${atBottom} -> ${yDown}`);

  await page.mouse.move(X, 30, { steps: 4 });
  const atTop = await scrollY();
  await page.waitForTimeout(800);
  const yUp = await scrollY();
  (yUp < atTop - 40) ? ok('and at the top edge it scrolls back up', `${atTop} -> ${yUp}`)
                     : bad('auto-scroll up', `${atTop} -> ${yUp}`);

  // drop somewhere on-screen
  if (target) { await page.mouse.move(t1.x, target.y, { steps: 8 }); await page.waitForTimeout(300); }

  // Where the gap sat in the instant before release. This is the promise the
  // interface made, and the next assertion is whether it kept it.
  const promised = await page.evaluate(() => {
    const kids = [...document.querySelector('[data-vh-board]').children];
    return kids.indexOf(document.querySelector('.vh-w-ghost'));
  });
  await page.mouse.up();
  await page.waitForTimeout(700);

  const after = await page.evaluate(() => ({
    order: [...document.querySelectorAll('[data-vh-widget]')].map(e => e.getAttribute('data-vh-widget')),
    dragging: !!document.querySelector('.is-dragging'),
    ghost: !!document.querySelector('.vh-w-ghost'),
    body: document.body.classList.contains('vh-is-dragging'),
    inBoard: [...document.querySelectorAll('[data-vh-widget]')].every(e => e.closest('[data-vh-board]') !== null),
    stray: [...document.body.children].filter(e => e.classList && e.classList.contains('vh-w')).length
  }));
  (!after.dragging && !after.ghost && !after.body && !after.stray) ? ok('everything cleans up on release') : bad('cleanup', JSON.stringify(after));
  after.inBoard ? ok('every widget is back inside the board') : bad('widgets back in the board');
  (after.order.length === before.length && new Set(after.order).size === after.order.length)
    ? ok('no widget lost or duplicated', `${after.order.length}`) : bad('widget count', `${before.length} -> ${after.order.length}`);
  /* Not "the order changed" -- dropping a widget back where it started is a
   * legitimate outcome and an assertion that demands otherwise is testing the
   * arithmetic of the test, not the feature. What must hold is that the
   * widget lands exactly where the gap said it would. */
  const landed = await page.evaluate(id => {
    const kids = [...document.querySelector('[data-vh-board]').children];
    return kids.indexOf(document.querySelector(`[data-vh-widget="${id}"]`));
  }, draggedId);
  (landed === promised) ? ok('it lands exactly where the gap promised', `slot ${promised}`)
                        : bad('lands where the gap promised', `gap said ${promised}, landed at ${landed}`);

  if (target) {
    const gapI = after.order.indexOf(draggedId), tgtI = after.order.indexOf(target.id);
    (Math.abs(gapI - tgtI) === 1)
      ? ok(`${draggedId} landed next to ${target.id}`, `${gapI} vs ${tgtI}`)
      : bad('dropped where the gap was', `${draggedId}@${gapI}, ${target.id}@${tgtI}`);
  }

  // persistence: the route is POST-only, so reload and look
  await page.waitForTimeout(1400);
  await page.goto(BASE + '/', { waitUntil: 'networkidle' });
  const reloaded = await page.$$eval('[data-vh-widget]', els => els.map(e => e.getAttribute('data-vh-widget')));
  (reloaded.join() === after.order.join()) ? ok('the new order survives a reload', `${reloaded.length} widgets`)
                                           : bad('order persisted', `screen ${after.order.slice(0,3)} vs reload ${reloaded.slice(0,3)}`);

  errs.length ? bad('console clean', errs.slice(0,3).join(' | ')) : ok('console clean');
  console.log(`\n${pass}/${pass+fail} passed`);
  await b.close();
  process.exit(fail ? 1 : 0);
})();
