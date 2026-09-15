/*
 * Prove the patch-availability and end-of-life work end to end, in a browser.
 *
 * The point of this pass is not that the pages render — browserpass already
 * checks that. It is that the number on a chart and the length of the list
 * that number links to are the same number. Those are two different code
 * paths (an aggregate query and a filtered listing), and the whole value of
 * a clickable chart evaporates the moment they disagree.
 *
 *   node dev/lifecyclepass.js
 *
 * Screenshots land in dev/shots/. The admin password is read from
 * .admin_pass and handed to the login form; it is never printed.
 */
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const BASE = 'http://localhost:8093';
const ROOT = '/home/romy/vulnhub';
const OUT = path.join(ROOT, 'dev/shots');

const results = [];
const ok = (name, detail = '') => results.push({ pass: true, name, detail });
const bad = (name, detail = '') => results.push({ pass: false, name, detail });

(async () => {
  fs.mkdirSync(OUT, { recursive: true });

  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await ctx.newPage();

  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text().slice(0, 240)); });
  page.on('pageerror', (e) => errors.push('uncaught: ' + String(e).slice(0, 240)));

  const pass = fs.readFileSync(path.join(ROOT, '.admin_pass'), 'utf8').trim();
  await page.goto(`${BASE}/wp-login.php`, { waitUntil: 'domcontentloaded' });
  await page.fill('#user_login', (process.env.VH_ADMIN_USER || 'admin'));
  await page.fill('#user_pass', pass);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'domcontentloaded' }).catch(() => {}),
    page.click('#wp-submit'),
  ]);

  /* ================================================================= */
  /* 1. The dashboard draws both new widgets.                          */
  /* ================================================================= */

  await page.goto(`${BASE}/`, { waitUntil: 'networkidle', timeout: 90000 });

  const widgets = await page.evaluate(() => {
    const out = {};
    document.querySelectorAll('[data-vh-widget]').forEach((el) => {
      out[el.getAttribute('data-vh-widget')] = el.innerText.length;
    });
    return out;
  });

  for (const id of ['patch_availability', 'eol_platforms']) {
    if (widgets[id] > 100) ok(`widget ${id} rendered`, `${widgets[id]} chars`);
    else bad(`widget ${id} rendered`, `found ${widgets[id] || 'nothing'}`);
  }

  await page.screenshot({ path: path.join(OUT, 'lifecycle-dashboard.png'), fullPage: true });

  /* ================================================================= */
  /* 2. Every patch segment links to a list of the same length.        */
  /* ================================================================= */

  const segments = await page.evaluate(() => {
    const w = document.querySelector('[data-vh-widget="patch_availability"]');
    if (!w) return [];
    return [...w.querySelectorAll('a.vh-segbars__seg')].map((a) => ({
      href: a.getAttribute('href'),
      // The count is read off the aria-label, not the visible text: a
      // narrow segment hides its number by design, and the label is the
      // accessible name the segment actually claims.
      n: parseInt(((a.getAttribute('aria-label') || '').match(/[0-9][0-9,]*/) || ['0'])[0].replace(/,/g, ''), 10),
      label: a.getAttribute('aria-label'),
    }));
  });

  if (segments.length >= 6) ok('patch chart has clickable segments', `${segments.length}`);
  else bad('patch chart has clickable segments', `only ${segments.length}`);

  for (const seg of segments) {
    await page.goto(seg.href, { waitUntil: 'domcontentloaded', timeout: 90000 });

    const shown = await page.evaluate(() => {
      const m = (document.querySelector('.vh-page-head .vh-sub') || {}).innerText || '';
      const n = m.replace(/,/g, '').match(/([0-9]+)\s+finding/);
      return n ? parseInt(n[1], 10) : -1;
    });

    const which = (seg.label || '').slice(0, 46);

    if (shown === seg.n) ok(`segment matches its list: ${which}`, `${shown}`);
    else bad(`segment matches its list: ${which}`, `chart said ${seg.n}, list said ${shown}`);
  }

  /* ================================================================= */
  /* 3. The "no patch" list explains itself and can be cleared.        */
  /* ================================================================= */

  await page.goto(`${BASE}/vulnerabilities/?severity=critical&patch_available=0`, { waitUntil: 'domcontentloaded' });

  const banner = await page.evaluate(() => {
    const el = document.querySelector('.vh-notice--info');
    return el ? el.innerText.trim() : '';
  });

  if (/no known fix/i.test(banner)) ok('filtered list says why it is filtered');
  else bad('filtered list says why it is filtered', banner.slice(0, 80));

  await page.screenshot({ path: path.join(OUT, 'lifecycle-nopatch-list.png'), fullPage: true });

  /* ================================================================= */
  /* 4. Every EOL bar links to a list of the same length.              */
  /* ================================================================= */

  await page.goto(`${BASE}/`, { waitUntil: 'networkidle', timeout: 90000 });

  const bars = await page.evaluate(() => {
    const w = document.querySelector('[data-vh-widget="eol_platforms"]');
    if (!w) return [];
    return [...w.querySelectorAll('a.vh-segbars__seg')].slice(0, 6).map((a) => ({
      href: a.getAttribute('href'),
      n: parseInt(((a.getAttribute('aria-label') || '').match(/[0-9][0-9,]*/) || ['0'])[0].replace(/,/g, ''), 10),
      label: (a.getAttribute('aria-label') || '').slice(0, 44),
    }));
  });

  if (bars.length >= 4) ok('EOL chart has clickable bars', `${bars.length}`);
  else bad('EOL chart has clickable bars', `only ${bars.length}`);

  for (const bar of bars) {
    await page.goto(bar.href, { waitUntil: 'domcontentloaded', timeout: 90000 });

    const shown = await page.evaluate(() => {
      const m = (document.querySelector('.vh-page-head .vh-sub') || {}).innerText || '';
      const n = m.replace(/,/g, '').match(/([0-9]+)\s+asset/);
      return n ? parseInt(n[1], 10) : -1;
    });

    if (shown === bar.n) ok(`EOL bar matches its list: ${bar.label}`, `${shown}`);
    else bad(`EOL bar matches its list: ${bar.label}`, `chart said ${bar.n}, list said ${shown}`);
  }

  await page.screenshot({ path: path.join(OUT, 'lifecycle-eol-assets.png'), fullPage: true });

  /* ================================================================= */
  /* 5. The CSV buttons produce a CSV, and it holds the filtered rows. */
  /* ================================================================= */

  const downloads = [
    ['assets', `${BASE}/assets/`],
    ['findings-nopatch', `${BASE}/vulnerabilities/?severity=critical&patch_available=0`],
  ];

  for (const [name, url] of downloads) {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 90000 });

    const href = await page.evaluate(() => {
      // The export control is a <details> holding a GET form with a column
      // picker, not a bare link, so build the URL the browser would submit.
      const f = document.querySelector('form.vh-export__panel');
      if (!f) return '';
      const q = new URLSearchParams();
      for (const el of f.elements) {
        if (!el.name) continue;
        if ((el.type === 'checkbox' || el.type === 'radio') && !el.checked) continue;
        if (el.type === 'submit' || el.type === 'button') continue;
        q.append(el.name, el.value);
      }
      return f.getAttribute('action') + '?' + q.toString();
    });

    if (!href) { bad(`export button on ${name}`); continue; }
    ok(`export button on ${name}`);

    // Fetching it in the page keeps the session cookie without wiring up a
    // download listener, and lets us look at the bytes.
    const csv = await page.evaluate(async (u) => {
      const r = await fetch(u, { credentials: 'same-origin' });
      const t = await r.text();
      return { status: r.status, type: r.headers.get('content-type'), body: t.slice(0, 400), lines: t.split('\n').length };
    }, href);

    if (csv.status === 200 && /csv/.test(csv.type || '')) {
      ok(`${name} downloads as CSV`, `${csv.lines} lines`);
    } else {
      bad(`${name} downloads as CSV`, `status ${csv.status} type ${csv.type} — ${csv.body.slice(0, 160)}`);
    }

    if (/^﻿?"?Hostname|^﻿?"?Asset/.test(csv.body)) ok(`${name} CSV has a header row`);
    else bad(`${name} CSV has a header row`, csv.body.slice(0, 100));
  }

  /* The critical-no-patch export must hold exactly the two rows the chart
   * counted, plus its header. This is the whole promise of the feature. */
  await page.goto(`${BASE}/vulnerabilities/?severity=critical&patch_available=0`, { waitUntil: 'domcontentloaded' });

  const check = await page.evaluate(async () => {
    const f = document.querySelector('form.vh-export__panel');
    if (!f) return { rows: -1, listed: -2 };
    const q = new URLSearchParams();
    for (const el of f.elements) {
      if (!el.name) continue;
      if ((el.type === 'checkbox' || el.type === 'radio') && !el.checked) continue;
      if (el.type === 'submit' || el.type === 'button') continue;
      q.append(el.name, el.value);
    }
    const r = await fetch(f.getAttribute('action') + '?' + q.toString(), { credentials: 'same-origin' });
    const t = await r.text();
    const rows = t.trim().split('\n').length - 1;
    const shown = (document.querySelector('.vh-page-head .vh-sub') || {}).innerText || '';
    const n = shown.replace(/,/g, '').match(/([0-9]+)\s+finding/);
    return { rows, listed: n ? parseInt(n[1], 10) : -1 };
  });

  if (check.rows === check.listed) ok('CSV row count matches the filtered list', `${check.rows}`);
  else bad('CSV row count matches the filtered list', `csv ${check.rows}, list ${check.listed}`);

  /* ================================================================= */
  /* 6. The lifecycle table is editable from the portal.               */
  /* ================================================================= */

  await page.goto(`${BASE}/portal-admin/?section=screen-vulnhub-lifecycle`, { waitUntil: 'domcontentloaded', timeout: 90000 });
  let body = await page.evaluate(() => document.body.innerText);

  if (/lifecycle table/i.test(body)) ok('portal lifecycle screen renders');
  else bad('portal lifecycle screen renders', body.slice(0, 140));

  await page.goto(`${BASE}/wp-admin/admin.php?page=vulnhub-lifecycle`, { waitUntil: 'domcontentloaded', timeout: 90000 });
  body = await page.evaluate(() => document.body.innerText);

  if (/Windows Server 2012 R2/.test(body)) ok('wp-admin lifecycle screen lists the shipped table');
  else bad('wp-admin lifecycle screen lists the shipped table', body.slice(0, 200));

  await page.screenshot({ path: path.join(OUT, 'lifecycle-admin.png'), fullPage: true });

  /* ================================================================= */

  if (errors.length) bad('console clean', errors.slice(0, 4).join(' | '));
  else ok('console clean');

  await browser.close();

  let failed = 0;
  for (const r of results) {
    if (!r.pass) failed++;
    console.log(`${r.pass ? 'ok  ' : 'FAIL'}  ${r.name}${r.detail ? '  — ' + r.detail : ''}`);
  }
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed ? 1 : 0);
})();

